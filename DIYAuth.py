import logging
import os
import sys
import json
import base64
import secrets
import pyotp
import qrcode
import string
import time
from io import BytesIO
from typing import List, Dict, Any
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QListWidget, QLineEdit,
                             QInputDialog, QMessageBox, QFileDialog, QLabel, QDialog, QInputDialog, QMenuBar, QAction, QDialogButtonBox)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QPixmap, QImage
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

try:
    from google.protobuf.json_format import MessageToDict
    from migration_payload_pb2 import MigrationPayload, OtpParameters
    PROTOBUF_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Unable to import protobuf modules. Migration feature will be disabled. Error: {e}")
    PROTOBUF_AVAILABLE = False

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
ACCOUNTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts.json")
DEBUG_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug.log")
INTERNAL_STORAGE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "internal_storage.dat")

class PassphraseSetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Passphrase Setup")
        self.layout = QVBoxLayout(self)

        self.passphrase = self.generate_random_passphrase()

        self.info_label = QLabel(f"We've generated a secure passphrase for you:\n\n{self.passphrase}\n\nDo you want to use this passphrase?")
        self.layout.addWidget(self.info_label)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Yes | QDialogButtonBox.No)
        self.layout.addWidget(self.button_box)

        self.help_button = QPushButton("What's this?")
        self.button_box.addButton(self.help_button, QDialogButtonBox.HelpRole)

        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.help_button.clicked.connect(self.show_passphrase_help)

    def generate_random_passphrase(self, length=32):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def show_passphrase_help(self):
        help_text = ("Passphrase Information:\n\n"
                     "The passphrase is used to encrypt your TOTP account data, ensuring that "
                     "your sensitive information remains secure even if someone gains access to your device.\n\n"
                     "Guidelines for a strong passphrase:\n"
                     "- Use a mix of uppercase and lowercase letters, numbers, and symbols\n"
                     "- Make it at least 12 characters long\n"
                     "- Avoid using personal information or common words\n\n"
                     "Remember to store your passphrase securely, as you'll need it to access "
                     "your accounts if you reinstall the application or move to a new device.")

        QMessageBox.information(self, "Passphrase Help", help_text)

class DIYAuth(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DIYAuth")
        self.setGeometry(100, 100, 400, 500)

        self.accounts: List[Dict[str, str]] = []
        self.debug_mode = False
        self.setup_logging()

        self.salt = os.urandom(16)
        self.config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.encrypted")

        if not os.path.exists(self.config_file):
            self.initial_setup()
        else:
            self.load_config()

        self.setup_ui()
        self.load_accounts()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_totps)
        self.timer.start(30000)

    def setup_logging(self) -> None:
        self.logger = logging.getLogger('DIYAuth')
        self.logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler(DEBUG_LOG_FILE)
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def setup_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.setup_menu_bar()

        self.account_list = QListWidget()
        self.account_list.itemDoubleClicked.connect(self.show_totp_code)
        self.account_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.account_list.customContextMenuRequested.connect(self.show_context_menu)
        self.layout.addWidget(self.account_list)

        self.debug_label = QLabel()
        self.debug_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.debug_label)
        self.debug_label.hide()

    def setup_menu_bar(self):
        menubar = self.menuBar()

        # Account menu
        account_menu = menubar.addMenu('Account')
        add_action = QAction('Add Account', self)
        add_action.triggered.connect(self.add_account)
        account_menu.addAction(add_action)
        remove_action = QAction('Remove Account', self)
        remove_action.triggered.connect(self.remove_account)
        account_menu.addAction(remove_action)

        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        migrate_action = QAction('Migrate from Google Authenticator', self)
        migrate_action.triggered.connect(self.migrate_from_google_auth)
        tools_menu.addAction(migrate_action)
        if not PROTOBUF_AVAILABLE:
            migrate_action.setEnabled(False)
        export_action = QAction('Export Accounts', self)
        export_action.triggered.connect(self.export_accounts)
        tools_menu.addAction(export_action)
        import_action = QAction('Import Accounts', self)
        import_action.triggered.connect(self.import_accounts)
        tools_menu.addAction(import_action)

        # Debug menu
        debug_menu = menubar.addMenu('Debug')
        debug_action = QAction('Toggle Debug Mode', self)
        debug_action.triggered.connect(self.toggle_debug_mode)
        debug_menu.addAction(debug_action)
        generate_url_action = QAction('Generate OTPAuth URL', self)
        generate_url_action.triggered.connect(self.generate_otpauth_url)
        debug_menu.addAction(generate_url_action)

    def load_config(self):
        try:
            with open(self.config_file, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = self.decrypt_data(encrypted_data)
            config = json.loads(decrypted_data)
            self.passphrase = config["passphrase"]
            self.salt = base64.b64decode(config["salt"])
        except Exception as e:
            self.logger.error(f"Failed to load config: {str(e)}")
            self.passphrase = None
            self.salt = os.urandom(16)
            self.save_config()

        self.logger.debug(f"Config loaded. Passphrase: {self.passphrase}")

    def initial_setup(self):
        welcome_msg = ("Welcome to DIYAuth!\n\n"
                       "This application helps you manage your two-factor authentication (2FA) accounts securely. "
                       "To ensure the safety of your accounts, we use a passphrase to encrypt your data.\n\n"
                       "Let's set up your passphrase now.")

        QMessageBox.information(self, "Welcome", welcome_msg, QMessageBox.Ok, QMessageBox.Ok)

        dialog = PassphraseSetupDialog(self)
        result = dialog.exec_()

        if result == QDialog.Accepted:
            self.passphrase = dialog.passphrase
        else:
            custom_passphrase, ok = self.get_custom_passphrase()
            if not ok or not custom_passphrase:
                QMessageBox.warning(self, "Setup Failed", "A passphrase is required. Setup aborted.")
                sys.exit(1)
            self.passphrase = custom_passphrase

        self.salt = os.urandom(16)
        self.save_config()

        final_msg = ("Initial setup is complete. Your passphrase has been saved securely.\n\n"
                     "IMPORTANT: Please remember or securely store your passphrase. "
                     "You will need it to access your accounts if you reinstall the application "
                     "or move to a new device.")
        QMessageBox.information(self, "Setup Complete", final_msg)

    def get_custom_passphrase(self):
        dialog = QInputDialog(self)
        dialog.setInputMode(QInputDialog.TextInput)
        dialog.setWindowTitle("Passphrase Setup")
        dialog.setLabelText("Enter your own passphrase:")
        dialog.setTextEchoMode(QLineEdit.Password)

        help_button = dialog.findChild(QPushButton, "")
        if help_button:
            help_button.clicked.disconnect()
            help_button.clicked.connect(self.show_passphrase_help)

        ok = dialog.exec_()
        passphrase = dialog.textValue()
        return passphrase, ok

    def show_passphrase_help(self, parent_dialog):
        help_text = ("Passphrase Information:\n\n"
                     "The passphrase is used to encrypt your TOTP account data, ensuring that "
                     "your sensitive information remains secure even if someone gains access to your device.\n\n"
                     "Guidelines for a strong passphrase:\n"
                     "- Use a mix of uppercase and lowercase letters, numbers, and symbols\n"
                     "- Make it at least 12 characters long\n"
                     "- Avoid using personal information or common words\n\n"
                     "Remember to store your passphrase securely, as you'll need it to access "
                     "your accounts if you reinstall the application or move to a new device.")

        QMessageBox.information(parent_dialog, "Passphrase Help", help_text)

    def save_config(self):
        config = {
            "passphrase": self.passphrase,
            "salt": base64.b64encode(self.salt).decode('utf-8')
        }
        encrypted_data = self.encrypt_data(json.dumps(config))
        with open(self.config_file, 'wb') as f:
            f.write(encrypted_data)

    def encrypt_data(self, data: str) -> bytes:
        key = self.derive_key(self.passphrase)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return cipher.nonce + tag + ciphertext

    def decrypt_data(self, encrypted_data: bytes) -> str:
        key = self.derive_key(self.passphrase)
        nonce, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    def derive_key(self, passphrase: str) -> bytes:
        return PBKDF2(passphrase, self.salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

    def get_embedded_data(self, name: str) -> str:
        try:
            with open(INTERNAL_STORAGE_FILE, 'rb') as f:
                data = f.read()
            if data:
                decrypted_data = self.decrypt_data(data.decode('utf-8'))
                storage = json.loads(decrypted_data)
                return storage.get(name, '')
            return ''
        except FileNotFoundError:
            return ''
        except Exception as e:
            self.logger.error(f"Error reading internal storage: {str(e)}")
            return ''

    def set_embedded_data(self, name: str, data: str) -> None:
        try:
            storage = {}
            try:
                with open(INTERNAL_STORAGE_FILE, 'rb') as f:
                    existing_data = f.read()
                if existing_data:
                    decrypted_data = self.decrypt_data(existing_data.decode('utf-8'))
                    storage = json.loads(decrypted_data)
            except FileNotFoundError:
                pass

            storage[name] = data
            encrypted_data = self.encrypt_data(json.dumps(storage))

            with open(INTERNAL_STORAGE_FILE, 'wb') as f:
                f.write(encrypted_data.encode('utf-8'))

            self.logger.debug(f"Saved embedded data for {name}")
        except Exception as e:
            self.logger.error(f"Error writing to internal storage: {str(e)}")

    def load_accounts(self):
        try:
            with open(ACCOUNTS_FILE, 'r') as f:
                encrypted_data = f.read()

            if encrypted_data:
                decrypted_data = self.decrypt_data(encrypted_data)
                loaded_accounts = json.loads(decrypted_data)

                self.logger.debug(f"Loaded {len(loaded_accounts)} accounts from file.")

                if self.verify_account_data(loaded_accounts):
                    self.accounts = loaded_accounts
                    self.logger.info(f"Loaded {len(self.accounts)} accounts successfully.")
                else:
                    self.logger.error("Account data integrity check failed")
                    QMessageBox.warning(self, "Data Integrity Error", "Account data failed integrity check.")
                    return
            else:
                self.logger.info("No existing accounts found.")
                self.accounts = []

        except FileNotFoundError:
            self.logger.info("No existing accounts file found.")
            self.accounts = []
        except json.JSONDecodeError as json_error:
            self.logger.error(f"JSON parsing failed: {str(json_error)}")
            QMessageBox.warning(self, "Data Error", "Failed to parse account data. The file might be corrupted.")
            return
        except Exception as e:
            self.logger.error(f"An error occurred while loading accounts: {str(e)}")
            QMessageBox.warning(self, "Load Error", f"An error occurred while loading accounts: {str(e)}")
            self.accounts = []

        self.refresh_totps()
        self.logger.debug(f"TOTPs refreshed. Number of accounts displayed: {self.account_list.count()}")

    def verify_account_data(self, accounts: List[Dict[str, Any]]) -> bool:
        if not isinstance(accounts, list):
            self.logger.error("Account data is not a list")
            return False

        for account in accounts:
            if not isinstance(account, dict):
                self.logger.error(f"Account is not a dictionary: {account}")
                return False
            if 'name' not in account or 'secret' not in account:
                self.logger.error(f"Account is missing required fields: {account}")
                return False
            if not isinstance(account['name'], str) or not isinstance(account['secret'], str):
                self.logger.error(f"Account fields have incorrect types: {account}")
                return False
            if not account['name'] or not account['secret']:
                self.logger.error(f"Account has empty name or secret: {account}")
                return False

        return True

    def save_accounts(self):
        try:
            encrypted_data = self.encrypt_data(json.dumps(self.accounts))
            with open(ACCOUNTS_FILE, 'w') as f:
                f.write(encrypted_data)
            self.logger.debug(f"Saved {len(self.accounts)} accounts successfully.")
        except Exception as e:
            self.logger.error(f"Failed to save accounts: {str(e)}")
            QMessageBox.warning(self, "Save Error", f"Failed to save accounts: {str(e)}")

    def edit_account_name(self, index: int) -> None:
        account = self.accounts[index]
        new_name, ok = QInputDialog.getText(self, "Edit Account Name",
                                            "Enter new account name:",
                                            text=account['name'])
        if ok and new_name:
            old_name = account['name']
            account['name'] = new_name
            self.save_accounts()
            self.refresh_totps()
            self.logger.debug(f"Edited account name: {old_name} -> {new_name}")
            QMessageBox.information(self, "Success", f"Account name changed to {new_name}")

    def import_accounts(self) -> None:
        file_name, _ = QFileDialog.getOpenFileName(self, "Import Accounts", "", "JSON Files (*.json)")
        if file_name:
            try:
                with open(file_name, "r") as f:
                    imported_accounts = json.load(f)
                if self.verify_account_data(imported_accounts):
                    self.accounts.extend(imported_accounts)
                    self.save_accounts()
                    self.refresh_totps()
                    QMessageBox.information(self, "Import Successful", f"Imported {len(imported_accounts)} accounts.")
                    if self.debug_mode:
                        print(f"Imported {len(imported_accounts)} accounts from {file_name}")
                else:
                    raise ValueError("Imported data failed integrity check")
            except Exception as e:
                QMessageBox.warning(self, "Import Failed", f"Error during import: {str(e)}")
                if self.debug_mode:
                    print(f"Import failed: {str(e)}")

    def refresh_totps(self) -> None:
        self.logger.debug(f"Refreshing TOTPs. Number of accounts: {len(self.accounts)}")
        self.account_list.clear()
        for account in self.accounts:
            self.logger.debug(f"Adding account to list: {account['name']}")
            self.account_list.addItem(account['name'])
        self.logger.debug(f"TOTP refresh complete. Items in list: {self.account_list.count()}")

    def export_accounts(self) -> None:
        file_name, _ = QFileDialog.getSaveFileName(self, "Export Accounts", "", "JSON Files (*.json)")
        if file_name:
            try:
                with open(file_name, "w") as f:
                    json.dump(self.accounts, f, indent=2)
                QMessageBox.information(self, "Export Successful", f"Exported {len(self.accounts)} accounts to {file_name}")
                if self.debug_mode:
                    print(f"Exported {len(self.accounts)} accounts to {file_name}")
            except Exception as e:
                QMessageBox.warning(self, "Export Failed", f"Error during export: {str(e)}")
                if self.debug_mode:
                    print(f"Export failed: {str(e)}")

    def show_account_options(self, item) -> None:
        index = self.account_list.row(item)
        account = self.accounts[index]
        options = ["View TOTP Code", "Generate QR Code", "Edit Account Name"]
        choice, ok = QInputDialog.getItem(self, "Account Options",
                                          f"Choose an action for {account['name']}:",
                                          options, 0, False)

        if ok:
            if choice == "View TOTP Code":
                self.show_totp_code(account)
            elif choice == "Generate QR Code":
                self.generate_otpauth_url(account)
            elif choice == "Edit Account Name":
                self.edit_account_name(index)

    def show_context_menu(self, position):
            menu = QMenu()
            view_totp_action = menu.addAction("View TOTP Code")
            generate_qr_action = menu.addAction("Generate QR Code")
            edit_name_action = menu.addAction("Edit Account Name")

            action = menu.exec_(self.account_list.mapToGlobal(position))

            if action:
                item = self.account_list.itemAt(position)
                if item:
                    index = self.account_list.row(item)
                    account = self.accounts[index]

                    if action == view_totp_action:
                        self.show_totp_code(item)
                    elif action == generate_qr_action:
                        self.generate_otpauth_url(account)
                    elif action == edit_name_action:
                        self.edit_account_name(index)

    def show_totp_code(self, item):
        index = self.account_list.row(item)
        account = self.accounts[index]
        dialog = QDialog(self)
        dialog.setWindowTitle(f"TOTP for {account['name']}")
        dialog.setFixedSize(300, 200)
        layout = QVBoxLayout()
        code_label = QLabel(code)
        code_label.setAlignment(Qt.AlignCenter)
        code_label.setStyleSheet("font-size: 48px; font-weight: bold;")
        layout.addWidget(code_label)
        time_left_label = QLabel()
        layout.addWidget(time_left_label)

        copy_button = QPushButton("Copy to Clipboard")
        copy_button.clicked.connect(lambda: self.copy_to_clipboard(code))
        layout.addWidget(copy_button)

        dialog.setLayout(layout)

        def update_time_left():
            seconds_left = 30 - int(time.time()) % 30
            time_left_label.setText(f"Time left: {seconds_left} seconds")
            if seconds_left == 30:
                new_code = totp.now()
                code_label.setText(new_code)
                copy_button.clicked.disconnect()
                copy_button.clicked.connect(lambda: self.copy_to_clipboard(new_code))

        update_timer = QTimer(dialog)
        update_timer.timeout.connect(update_time_left)
        update_timer.start(1000)

        update_time_left()
        dialog.exec_()

    def copy_to_clipboard(self, text):
        pyperclip.copy(text)
        QMessageBox.information(self, "Copied", "TOTP code copied to clipboard!")

    def add_account(self) -> None:
        name, ok = QInputDialog.getText(self, "Add Account", "Enter account name:")
        if ok and name:
            secret, ok = QInputDialog.getText(self, "Add Account", "Enter TOTP secret:")
            if ok and secret:
                self.accounts.append({"name": name, "secret": secret})
                self.save_accounts()
                self.refresh_totps()
                self.logger.debug(f"Added new account: {name}")

    def remove_account(self) -> None:
        current_item = self.account_list.currentItem()
        if current_item:
            index = self.account_list.row(current_item)
            removed_account = self.accounts.pop(index)
            self.save_accounts()
            self.refresh_totps()
            self.logger.debug(f"Removed account: {removed_account['name']}")

    def toggle_debug_mode(self) -> None:
        self.debug_mode = not self.debug_mode
        if self.debug_mode:
            self.debug_label.setText("Debug Mode: ON")
            self.debug_label.show()
            self.logger.debug("Debug mode enabled")
        else:
            self.debug_label.hide()
            self.logger.debug("Debug mode disabled")

    def migrate_from_google_auth(self) -> None:
        if not PROTOBUF_AVAILABLE:
            QMessageBox.warning(self, "Feature Unavailable", "Migration feature is currently unavailable due to protobuf import issues.")
            return

        migration_data, ok = QInputDialog.getText(self, "Migrate from Google Authenticator", "Enter migration data:")
        if ok and migration_data:
            try:
                migration_data = migration_data.split("data=")[1]
                decoded_data = base64.b64decode(migration_data)
                payload = MigrationPayload()
                payload.ParseFromString(decoded_data)
                for otp_param in payload.otp_parameters:
                    secret = base64.b32encode(otp_param.raw_data).decode('utf-8').rstrip('=')
                    name = otp_param.name or f"Migrated Account {len(self.accounts) + 1}"
                    self.accounts.append({"name": name, "secret": secret})
                self.save_accounts()
                self.refresh_totps()
                QMessageBox.information(self, "Migration Successful", f"Imported {len(payload.otp_parameters)} accounts.")
                if self.debug_mode:
                    print(f"Migrated {len(payload.otp_parameters)} accounts from Google Authenticator.")
            except Exception as e:
                QMessageBox.warning(self, "Migration Failed", f"Error during migration: {str(e)}")
                if self.debug_mode:
                    print(f"Migration failed: {str(e)}")

    def generate_otpauth_url(self, account: Dict[str, str] = None) -> None:
        if not self.accounts:
            QMessageBox.warning(self, "Error", "No accounts available. Please add an account first.")
            return

        if account is None:
            current_item = self.account_list.currentItem()
            if current_item:
                index = self.account_list.row(current_item)
                account = self.accounts[index]
            else:
                QMessageBox.warning(self, "Error", "No account selected.")
                return

        url = f"otpauth://totp/{account['name']}?secret={account['secret']}"
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(url)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")
        img_buffer = BytesIO()
        qr_image.save(img_buffer)
        img_buffer.seek(0)
        qimage = QImage.fromData(img_buffer.getvalue(), "PNG")
        pixmap = QPixmap.fromImage(qimage)
        dialog = QMessageBox(self)
        dialog.setWindowTitle("OTPAuth URL")
        dialog.setText(url)
        dialog.setIconPixmap(pixmap)
        dialog.exec_()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DIYAuth()
    window.show()
    sys.exit(app.exec_())
