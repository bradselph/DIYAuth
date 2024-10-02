# DIYAuth

DIYAuth is a robust desktop application for managing Time-Based One-Time Password (TOTP) accounts used in two-factor authentication (2FA). It provides a secure and convenient way to store and generate TOTP codes for multiple accounts, enhancing your online security without the need for a mobile device.

## Features

### Account Management
- **Add Accounts**: Easily add new TOTP accounts with a user-friendly interface.
- **Edit Accounts**: Modify account details, including names and secrets.
- **Remove Accounts**: Securely delete accounts you no longer need.
- **View TOTP Codes**: Generate and display current TOTP codes with automatic refresh.

### Import and Export
- **Google Authenticator Import**: Seamlessly import accounts from Google Authenticator using their migration feature.
- **QR Code Generation**: Generate QR codes for easy setup on mobile devices, if needed.
- **Export Functionality**: Export your accounts for backup or transfer to another device.
- **Import Functionality**: Import previously exported accounts, facilitating easy recovery or device transitions.

### Security
- **Local Storage**: All data is stored locally, reducing the risk of online breaches.
- **Strong Encryption**: Uses AES-GCM for encrypting sensitive data.
- **Key Derivation**: Implements PBKDF2 with SHA256 for secure key derivation.
- **Salted Hashing**: Unique salt for each installation to prevent rainbow table attacks.
- **Encrypted Configuration**: Config file is encrypted to protect user settings.

### User Interface
- **Intuitive GUI**: Easy-to-use graphical interface built with PyQt5.
- **Account List**: Clear list of all your accounts for quick access.

## Installation

### Precompiled Binary (Windows)
1. Download the latest release from the [releases page](https://github.com/bradselph/DIYAuth/releases).
2. Extract the ZIP file to your desired location.
3. Run `DIYAuth.exe`.

### From Source
1. Ensure you have Python 3.7+ installed on your system.
2. Clone this repository:
   ```
   git clone https://github.com/bradselph/DIYAuth.git
   ```
3. Navigate to the project directory:
   ```
   cd DIYAuth
   ```
4. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage
1. Run the application:
   - If using the precompiled binary, double-click `DIYAuth.exe`.
   - If running from source, use `python DIYAuth.py`.
2. On first run, you'll be prompted to set a strong passphrase. This passphrase encrypts your TOTP secrets, so make sure it's secure and memorable.
3. Use the "Add Account" button to add new accounts. You'll need to provide:
   - Account Name: A memorable name for the account
   - TOTP Secret: The secret key provided by the service you're setting up 2FA for
4. To view a TOTP code, simply double click on the account in the list. The current code will be displayed and automatically refreshed.
5. Use the context menu (right-click on an account) to:
   - Edit the account name
   - Generate a QR code for the account
   - Remove the account
6. Use the "Import" and "Export" menu options to backup your accounts or transfer them to another device.

## Security Considerations
- **Encryption**: All sensitive data is encrypted using AES-GCM encryption. The encryption key is derived from your passphrase using PBKDF2 with SHA256.
- **Local Storage**: All data is stored locally on your device. No data is sent to any servers.
- **Passphrase Protection**: Your passphrase is never stored directly. Instead, a key derived from it is used for encryption.
- **Salted Hashing**: A unique salt is generated for each installation, adding an extra layer of security.
- **Encrypted Config**: The configuration file is also encrypted, protecting user settings.

## Advanced Usage
- **Changing Passphrase**: To change your passphrase, use the "Change Passphrase" option in the settings menu.
- **Debug Mode**: Enable debug mode for detailed logging (not recommended for regular use).

## Troubleshooting
- **Lost Passphrase**: If you lose your passphrase, you'll need to reset the configuration. Delete the `config.encrypted` file in the application directory. Note that this will make your existing stored accounts inaccessible.
- **Import Issues**: If you're having trouble importing from Google Authenticator, ensure you're copying the entire migration string, including the "otpauth-migration://offline?data=" part.

## Contributing

Contributions are welcome! Here's how you can contribute:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please ensure your code adheres to the existing style and all tests pass before submitting a PR.

## License
This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). This means:

- You are free to use, modify, and distribute this software.
- If you modify the software, you must distribute your modifications under the same license.
- If you run a modified version of this software as a network service, you must make the complete source code of your modified version available to the users of that service.

For more details, see the [LICENSE](LICENSE) file in the project repository or visit [https://www.gnu.org/licenses/agpl-3.0.en.html](https://www.gnu.org/licenses/agpl-3.0.en.html).

## Disclaimer

This software is provided "as is", without warranty of any kind. While we strive to make it as secure as possible, use it at your own risk. Always ensure you have backups of your TOTP secrets.

## Contact
If you have any questions, feedback, or run into any issues, please open an issue on the GitHub repository. We're here to help!

Remember, your online security is important. Always use strong, unique passwords and enable 2FA wherever possible. DIYAuth is here to make managing your 2FA accounts easier and more secure.
