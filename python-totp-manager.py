import logging
import os
import sys
import json
import base64
import time
from io import BytesIO
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QListWidget, QLineEdit, QInputDialog, QMessageBox, QFileDialog, QLabel, QDialog, QTextEdit
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QPixmap, QImage
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pyotp
import qrcode
from google.protobuf.json_format import MessageToDict
from migration_payload_pb2 import MigrationPayload, OtpParameters

# Use absolute file paths when compiled
if getattr(sys, 'frozen', False):
    # Running as compiled
    base_path = sys._MEIPASS
else:
    # Running as script
    base_path = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(base_path, "config.json")
ACCOUNTS_FILE = os.path.join(base_path, "accounts.json")
DEBUG_LOG_FILE = os.path.join(base_path, "debug.log")

class TOTPManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TOTP Manager")
        self.setGeometry(100, 100, 400, 500)

        self.accounts = []
        self.debug_mode = False
        self.setup_logging()
        self.load_config()
        self.load_accounts()

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        self.account_list = QListWidget ()
        self.account_list.itemClicked.connect (self.show_account_options)
        self.layout.addWidget (self.account_list)

        self.refresh_button = QPushButton("Refresh TOTPs")
        self.refresh_button.clicked.connect(self.refresh_totps)
        self.layout.addWidget(self.refresh_button)

        button_layout = QHBoxLayout()
        self.add_button = QPushButton("Add Account")
        self.add_button.clicked.connect(self.add_account)
        button_layout.addWidget(self.add_button)

        self.remove_button = QPushButton("Remove Account")
        self.remove_button.clicked.connect(self.remove_account)
        button_layout.addWidget(self.remove_button)

        self.layout.addLayout(button_layout)

        advanced_layout = QHBoxLayout()
        self.migrate_button = QPushButton("Migrate from Google Authenticator")
        self.migrate_button.clicked.connect(self.migrate_from_google_auth)
        advanced_layout.addWidget(self.migrate_button)

        self.export_button = QPushButton("Export Accounts")
        self.export_button.clicked.connect(self.export_accounts)
        advanced_layout.addWidget(self.export_button)

        self.import_button = QPushButton("Import Accounts")
        self.import_button.clicked.connect(self.import_accounts)
        advanced_layout.addWidget(self.import_button)

        self.layout.addLayout(advanced_layout)

        debug_layout = QHBoxLayout()
        self.debug_button = QPushButton("Toggle Debug Mode")
        self.debug_button.clicked.connect(self.toggle_debug_mode)
        debug_layout.addWidget(self.debug_button)

        self.generate_url_button = QPushButton("Generate OTPAuth URL")
        self.generate_url_button.clicked.connect(self.generate_otpauth_url)
        debug_layout.addWidget(self.generate_url_button)

        self.layout.addLayout(debug_layout)

        self.debug_label = QLabel()
        self.debug_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.debug_label)
        self.debug_label.hide()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_totps)
        self.timer.start(30000)  # Refresh every 30 seconds

        self.refresh_totps()

    def setup_logging(self):
        self.logger = logging.getLogger('TOTPManager')
        self.logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler(DEBUG_LOG_FILE)
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def load_config(self):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            self.passphrase = config.get("passphrase", "please-use-you-strong-passphrase")
        except FileNotFoundError:
            self.passphrase = "please-use-you-strong-passphrase"
            self.save_config()
        
        self.logger.debug(f"Config loaded. Passphrase: {self.passphrase}")

    def save_config(self):
        config = {"passphrase": self.passphrase}
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
        
        self.logger.debug(f"Config saved. Passphrase: {self.passphrase}")

    def encrypt(self, data):
        key = self.passphrase.encode('utf-8')[:32].ljust(32, b'\0')
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data.encode('utf-8'), AES.block_size))
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt(self, encrypted_data):
        key = self.passphrase.encode('utf-8')[:32].ljust(32, b'\0')
        raw = base64.b64decode(encrypted_data.encode('utf-8'))
        nonce, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return unpad(decrypted, AES.block_size).decode('utf-8')

    def load_accounts(self):
        try:
            with open(ACCOUNTS_FILE, "r") as f:
                encrypted_data = f.read()
            decrypted_data = self.decrypt(encrypted_data)
            self.accounts = json.loads(decrypted_data)
            self.logger.debug(f"Loaded {len(self.accounts)} accounts successfully.")
        except FileNotFoundError:
            self.logger.debug("accounts.json file not found. Starting with an empty account list.")
            self.accounts = []
        except ValueError as e:
            self.logger.error(f"Decryption failed: {str(e)}")
            self.logger.debug("Starting with an empty account list due to decryption failure.")
            self.accounts = []
        except Exception as e:
            self.logger.error(f"An error occurred while loading accounts: {str(e)}")
            self.accounts = []

    def save_accounts(self):
        encrypted_data = self.encrypt(json.dumps(self.accounts))
        with open(ACCOUNTS_FILE, "w") as f:
            f.write(encrypted_data)
        
        self.logger.debug(f"Saved {len(self.accounts)} accounts successfully.")
    
    def edit_account_name(self, index):
        account = self.accounts[index]
        new_name, ok = QInputDialog.getText (self, "Edit Account Name",
                                             "Enter new account name:",
                                             text = account['name'])
        if ok and new_name:
            old_name = account['name']
            account['name'] = new_name
            self.save_accounts ()
            self.refresh_totps ()
            self.logger.debug (f"Edited account name: {old_name} -> {new_name}")
            QMessageBox.information (self, "Success", f"Account name changed to {new_name}")
    
    def refresh_totps(self):
        self.account_list.clear()
        for account in self.accounts:
            self.account_list.addItem(account['name'])
        
        self.logger.debug(f"Refreshed account list with {len(self.accounts)} accounts.")
    def show_selected_account(self, item):
        index = self.account_list.row(item)
        account = self.accounts[index]
        totp = pyotp.TOTP(account['secret'])
        code = totp.now()

        dialog = QDialog(self)
        dialog.setWindowTitle(f"TOTP for {account['name']}")
        dialog.setFixedSize(200, 200)

        layout = QVBoxLayout()

        code_label = QLabel(code)
        code_label.setAlignment(Qt.AlignCenter)
        code_label.setStyleSheet("font-size: 48px; font-weight: bold;")
        layout.addWidget(code_label)

        time_left_label = QLabel()
        layout.addWidget(time_left_label)

        dialog.setLayout(layout)
    
    def show_account_options(self, item):
        index = self.account_list.row (item)
        account = self.accounts[index]
        options = ["View TOTP Code", "Generate QR Code", "Edit Account Name"]
        choice, ok = QInputDialog.getItem (self, "Account Options",
                                           f"Choose an action for {account['name']}:",
                                           options, 0, False)
        
        if ok:
            if choice == "View TOTP Code":
                self.show_totp_code (account)
            elif choice == "Generate QR Code":
                self.generate_otpauth_url (account)
            elif choice == "Edit Account Name":
                self.edit_account_name (index)
                
    def show_totp_code(self, account):
        totp = pyotp.TOTP (account['secret'])
        code = totp.now ()
        
        dialog = QDialog (self)
        dialog.setWindowTitle (f"TOTP for {account['name']}")
        dialog.setFixedSize (300, 200)
        layout = QVBoxLayout ()
        code_label = QLabel (code)
        code_label.setAlignment (Qt.AlignCenter)
        code_label.setStyleSheet ("font-size: 48px; font-weight: bold;")
        layout.addWidget (code_label)
        time_left_label = QLabel ()
        layout.addWidget (time_left_label)
            
        dialog.setLayout (layout)

        def update_time_left():
            seconds_left = 30 - int(time.time()) % 30
            time_left_label.setText(f"Time left: {seconds_left} seconds")
            if seconds_left == 30:
                code_label.setText(totp.now())

        update_timer = QTimer(dialog)
        update_timer.timeout.connect(update_time_left)
        update_timer.start(1000)

        update_time_left()
        dialog.exec_()

    def add_account(self):
        name, ok = QInputDialog.getText(self, "Add Account", "Enter account name:")
        if ok and name:
            secret, ok = QInputDialog.getText(self, "Add Account", "Enter TOTP secret:")
            if ok and secret:
                self.accounts.append({"name": name, "secret": secret})
                self.save_accounts()
                self.refresh_totps()
                
                self.logger.debug(f"Added new account: {name}")

    def remove_account(self):
        current_item = self.account_list.currentItem()
        if current_item:
            index = self.account_list.row(current_item)
            removed_account = self.accounts.pop(index)
            self.save_accounts()
            self.refresh_totps()
            
            self.logger.debug(f"Removed account: {removed_account['name']}")

    def toggle_debug_mode(self):
        self.debug_mode = not self.debug_mode
        if self.debug_mode:
            self.debug_label.setText("Debug Mode: ON")
            self.debug_label.show()
            self.logger.debug("Debug mode enabled")
        else:
            self.debug_label.hide()
            self.logger.debug("Debug mode disabled")

    def migrate_from_google_auth(self):
        migration_data, ok = QInputDialog.getText(self, "Migrate from Google Authenticator", "Enter migration data:")
        if ok and migration_data:
            try:
                migration_data = migration_data.split("data=")[1]
                decoded_data = base64.b64decode(migration_data)
                payload = MigrationPayload()
                payload.ParseFromString(decoded_data)
                for otp_param in payload.otp_parameters:
                    secret = base64.b32encode(otp_param.raw_data).decode('utf-8').rstrip('=')
                    name = f"Migrated Account {len(self.accounts) + 1}"
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

    def export_accounts(self):
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

    def import_accounts(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Import Accounts", "", "JSON Files (*.json)")
        if file_name:
            try:
                with open(file_name, "r") as f:
                    imported_accounts = json.load(f)
                self.accounts.extend(imported_accounts)
                self.save_accounts()
                self.refresh_totps()
                QMessageBox.information(self, "Import Successful", f"Imported {len(imported_accounts)} accounts.")
                if self.debug_mode:
                    print(f"Imported {len(imported_accounts)} accounts from {file_name}")
            except Exception as e:
                QMessageBox.warning(self, "Import Failed", f"Error during import: {str(e)}")
                if self.debug_mode:
                    print(f"Import failed: {str(e)}")

    def generate_otpauth_url(self, account=None):
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
    window = TOTPManager()
    window.show()
    sys.exit(app.exec_())
