package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"google.golang.org/protobuf/proto"
)

type Account struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

type Storage struct {
	Accounts []Account `json:"accounts"`
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func loadStorage(filename, passphrase string) (*Storage, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return &Storage{}, nil
		}
		return nil, err
	}

	decryptedData, err := decrypt(data, passphrase)
	if err != nil {
		return nil, err
	}

	var storage Storage
	err = json.Unmarshal(decryptedData, &storage)
	if err != nil {
		return nil, err
	}
	return &storage, nil
}

func saveStorage(filename, passphrase string, storage *Storage) error {
	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return err
	}

	encryptedData, err := encrypt(data, passphrase)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, encryptedData, 0644)
}

func (s *Storage) addAccount(name, secret string) {
	s.Accounts = append(s.Accounts, Account{Name: name, Secret: secret})
}

func (s *Storage) removeAccount(index int) {
	if index >= 0 && index < len(s.Accounts) {
		s.Accounts = append(s.Accounts[:index], s.Accounts[index+1:]...)
	}
}

func (s *Storage) editAccount(index int, newName, newSecret string) {
	if index >= 0 && index < len(s.Accounts) {
		s.Accounts[index].Name = newName
		s.Accounts[index].Secret = newSecret
	}
}

func generateTOTP(secret string) (string, error) {
	passcode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", err
	}
	return passcode, nil
}

func decodeMigrationData(data string, debug bool, reader *bufio.Reader) ([]Account, error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %v", err)
	}

	if debug {
		fmt.Printf("Decoded data length: %d bytes\n", len(decoded))
		fmt.Printf("Decoded data (hex): %x\n", decoded)
	}

	var payload MigrationPayload
	err = proto.Unmarshal(decoded, &payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal protobuf: %v", err)
	}

	if debug {
		fmt.Printf("Number of OTP parameters: %d\n", len(payload.OtpParameters))
	}

	var accounts []Account
	for i, otp := range payload.OtpParameters {
		if debug {
			fmt.Printf("OTP parameter %d raw data: %x\n", i, otp.RawData)
		}

		secret := base32.StdEncoding.EncodeToString(otp.RawData)

		fmt.Printf("Enter name for account %d: ", i)
		name, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("error reading account name: %v", err)
		}
		name = strings.TrimSpace(name)

		accounts = append(accounts, Account{
			Name:   name,
			Secret: secret,
		})
	}
	return accounts, nil
}
func showTOTP(account Account, done chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
			passcode, err := generateTOTP(account.Secret)
			if err != nil {
				log.Printf("Error generating TOTP for account %s: %v", account.Name, err)
				return
			}
			fmt.Printf("Account: %s, TOTP: %s\n", account.Name, passcode)
			time.Sleep(30 * time.Second)
		}
	}
}

func showAllTOTPs(accounts []Account, done chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
			for _, account := range accounts {
				passcode, err := generateTOTP(account.Secret)
				if err != nil {
					log.Printf("Error generating TOTP for account %s: %v", account.Name, err)
					continue
				}
				fmt.Printf("Account: %s, TOTP: %s\n", account.Name, passcode)
			}
			time.Sleep(30 * time.Second)
		}
	}
}

func generateOTPAuthURL(account Account) string {
	return fmt.Sprintf("otpauth://totp/%s?secret=%s", account.Name, account.Secret)
}

func main() {
	const storageFile = "accounts.json"
	const passphrase = "your-strong-passphrase"

	storage, err := loadStorage(storageFile, passphrase)
	if err != nil {
		log.Fatalf("Error loading storage: %v", err)
	}

	reader := bufio.NewReader(os.Stdin)
	debugMode := false

	mainOptions := map[int]string{
		1: "Show specific TOTP",
		2: "Show all TOTPs",
		3: "More options",
		4: "Exit",
	}

	moreOptions := map[int]string{
		1:  "Add Account",
		2:  "Remove Account",
		3:  "Edit Account",
		4:  "Export Accounts",
		5:  "Import Accounts",
		6:  "Backup Accounts",
		7:  "Restore Accounts",
		8:  "Generate OTPAuth URL",
		9:  "Toggle Debug Mode",
		10: "Back to main menu",
	}

	for {
		for i := 1; i <= len(mainOptions); i++ {
			fmt.Printf("%d. %s\n", i, mainOptions[i])
		}
		fmt.Print("Choose an option: ")

		optionStr, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading input: %v", err)
			continue
		}
		optionStr = strings.TrimSpace(optionStr)
		option, err := strconv.Atoi(optionStr)
		if err != nil {
			fmt.Println("Invalid option")
			continue
		}

		switch option {
		case 1:
			fmt.Println("Accounts:")
			for i, account := range storage.Accounts {
				fmt.Printf("%d. %s\n", i+1, account.Name)
			}
			fmt.Print("Enter the number of the account to show: ")
			accountNumberStr, err := reader.ReadString('\n')
			if err != nil {
				log.Printf("Error reading input: %v", err)
				continue
			}
			accountNumberStr = strings.TrimSpace(accountNumberStr)
			accountNumber, err := strconv.Atoi(accountNumberStr)
			if err != nil || accountNumber < 1 || accountNumber > len(storage.Accounts) {
				fmt.Println("Invalid account number")
				continue
			}

			done := make(chan struct{})
			go showTOTP(storage.Accounts[accountNumber-1], done)
			fmt.Println("Press Enter to stop...")
			reader.ReadString('\n')
			close(done)

		case 2:
			done := make(chan struct{})
			go showAllTOTPs(storage.Accounts, done)
			fmt.Println("Press Enter to stop...")
			reader.ReadString('\n')
			close(done)

		case 3:
			for i := 1; i <= len(moreOptions); i++ {
				fmt.Printf("%d. %s\n", i, moreOptions[i])
			}
			fmt.Print("Choose an option: ")

			moreOptionStr, err := reader.ReadString('\n')
			if err != nil {
				log.Printf("Error reading input: %v", err)
				continue
			}
			moreOptionStr = strings.TrimSpace(moreOptionStr)
			moreOption, err := strconv.Atoi(moreOptionStr)
			if err != nil {
				fmt.Println("Invalid option")
				continue
			}

			switch moreOption {
			case 1:
				fmt.Print("Enter account name: ")
				name, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				name = strings.TrimSpace(name)

				fmt.Print("Enter secret: ")
				secret, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				secret = strings.TrimSpace(secret)

				storage.addAccount(name, secret)
				if err := saveStorage(storageFile, passphrase, storage); err != nil {
					log.Printf("Error saving storage: %v", err)
				}

			case 2:
				fmt.Println("Accounts:")
				for i, account := range storage.Accounts {
					fmt.Printf("%d. %s\n", i+1, account.Name)
				}
				fmt.Print("Enter the number of the account to remove: ")
				accountNumberStr, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				accountNumberStr = strings.TrimSpace(accountNumberStr)
				accountNumber, err := strconv.Atoi(accountNumberStr)
				if err != nil || accountNumber < 1 || accountNumber > len(storage.Accounts) {
					fmt.Println("Invalid account number")
					continue
				}

				storage.removeAccount(accountNumber - 1)
				if err := saveStorage(storageFile, passphrase, storage); err != nil {
					log.Printf("Error saving storage: %v", err)
				} else {
					fmt.Println("Account removed successfully")
				}

			case 3:
				fmt.Println("Accounts:")
				for i, account := range storage.Accounts {
					fmt.Printf("%d. %s\n", i+1, account.Name)
				}
				fmt.Print("Enter the number of the account to edit: ")
				accountNumberStr, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				accountNumberStr = strings.TrimSpace(accountNumberStr)
				accountNumber, err := strconv.Atoi(accountNumberStr)
				if err != nil || accountNumber < 1 || accountNumber > len(storage.Accounts) {
					fmt.Println("Invalid account number")
					continue
				}

				fmt.Print("Enter new name (leave empty to keep current): ")
				newName, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				newName = strings.TrimSpace(newName)

				fmt.Print("Enter new secret (leave empty to keep current): ")
				newSecret, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				newSecret = strings.TrimSpace(newSecret)

				account := storage.Accounts[accountNumber-1]
				if newName != "" {
					account.Name = newName
				}
				if newSecret != "" {
					account.Secret = newSecret
				}

				storage.editAccount(accountNumber-1, account.Name, account.Secret)
				if err := saveStorage(storageFile, passphrase, storage); err != nil {
					log.Printf("Error saving storage: %v", err)
				} else {
					fmt.Println("Account edited successfully")
				}

			case 4:
				fmt.Print("Enter export filename: ")
				exportFilename, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				exportFilename = strings.TrimSpace(exportFilename)

				data, err := json.MarshalIndent(storage, "", "  ")
				if err != nil {
					log.Printf("Error exporting accounts: %v", err)
					continue
				}

				err = os.WriteFile(exportFilename, data, 0644)
				if err != nil {
					log.Printf("Error saving export file: %v", err)
				} else {
					fmt.Println("Accounts exported successfully")
				}

			case 5:
				fmt.Print("Enter import filename: ")
				importFilename, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				importFilename = strings.TrimSpace(importFilename)

				data, err := os.ReadFile(importFilename)
				if err != nil {
					log.Printf("Error reading import file: %v", err)
					continue
				}

				var importedStorage Storage
				err = json.Unmarshal(data, &importedStorage)
				if err != nil {
					log.Printf("Error importing accounts: %v", err)
					continue
				}

				storage.Accounts = append(storage.Accounts, importedStorage.Accounts...)
				if err := saveStorage(storageFile, passphrase, storage); err != nil {
					log.Printf("Error saving storage: %v", err)
				} else {
					fmt.Println("Accounts imported successfully")
				}

			case 6:
				fmt.Print("Enter backup filename: ")
				backupFilename, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				backupFilename = strings.TrimSpace(backupFilename)

				data, err := json.MarshalIndent(storage, "", "  ")
				if err != nil {
					log.Printf("Error creating backup: %v", err)
					continue
				}

				err = os.WriteFile(backupFilename, data, 0644)
				if err != nil {
					log.Printf("Error saving backup file: %v", err)
				} else {
					fmt.Println("Backup created successfully")
				}

			case 7:
				fmt.Print("Enter backup filename: ")
				backupFilename, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				backupFilename = strings.TrimSpace(backupFilename)

				data, err := os.ReadFile(backupFilename)
				if err != nil {
					log.Printf("Error reading backup file: %v", err)
					continue
				}

				var restoredStorage Storage
				err = json.Unmarshal(data, &restoredStorage)
				if err != nil {
					log.Printf("Error restoring accounts: %v", err)
					continue
				}

				storage = &restoredStorage
				if err := saveStorage(storageFile, passphrase, storage); err != nil {
					log.Printf("Error saving storage: %v", err)
				} else {
					fmt.Println("Accounts restored successfully")
				}

			case 8:
				fmt.Println("Accounts:")
				for i, account := range storage.Accounts {
					fmt.Printf("%d. %s\n", i+1, account.Name)
				}
				fmt.Print("Enter the number of the account to generate URL for: ")
				accountNumberStr, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				accountNumberStr = strings.TrimSpace(accountNumberStr)
				accountNumber, err := strconv.Atoi(accountNumberStr)
				if err != nil || accountNumber < 1 || accountNumber > len(storage.Accounts) {
					fmt.Println("Invalid account number")
					continue
				}

				url := generateOTPAuthURL(storage.Accounts[accountNumber-1])
				fmt.Printf("OTPAuth URL: %s\n", url)

			case 9:
				debugMode = !debugMode
				if debugMode {
					fmt.Println("Debug mode enabled")
				} else {
					fmt.Println("Debug mode disabled")
				}

			case 10:
				break

			default:
				fmt.Println("Invalid option")
			}

		case 4:
			return

		default:
			fmt.Println("Invalid option")
		}
	}
}
