package main

import (
	"bufio"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
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

func loadStorage(filename string) (*Storage, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return &Storage{}, nil
		}
		return nil, err
	}

	var storage Storage
	err = json.Unmarshal(data, &storage)
	if err != nil {
		return nil, err
	}
	return &storage, nil
}

func saveStorage(filename string, storage *Storage) error {
	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func (s *Storage) addAccount(name, secret string) {
	s.Accounts = append(s.Accounts, Account{Name: name, Secret: secret})
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

func tryManualDecode(data []byte) {
	if len(data) < 2 {
		fmt.Println("Data too short")
		return
	}

	tag := data[0]
	fieldNumber := tag >> 3
	wireType := tag & 0x7

	fmt.Printf("First byte: %02x\n", tag)
	fmt.Printf("Field number: %d\n", fieldNumber)
	fmt.Printf("Wire type: %d\n", wireType)

	if wireType == 2 {
		length := int(data[1])
		fmt.Printf("Length: %d\n", length)
		if len(data) >= length+2 {
			fmt.Printf("Field data: %x\n", data[2:length+2])
		}
	}
}

const storageFile = "accounts.json"

func main() {
	storage, err := loadStorage(storageFile)
	if err != nil {
		log.Fatalf("Error loading storage: %v", err)
	}

	reader := bufio.NewReader(os.Stdin)
	debugMode := false

	for {
		fmt.Println("\n1. Add Account")
		fmt.Println("2. Show TOTPs")
		fmt.Println("3. Migrate from Google Authenticator")
		fmt.Println("4. Toggle Debug Mode")
		fmt.Println("5. Exit")
		fmt.Print("Choose an option: ")

		option, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading input: %v", err)
			continue
		}
		option = strings.TrimSpace(option)

		switch option {
		case "1":
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
			if err := saveStorage(storageFile, storage); err != nil {
				log.Printf("Error saving storage: %v", err)
			}

		case "2":
			for _, account := range storage.Accounts {
				passcode, err := generateTOTP(account.Secret)
				if err != nil {
					log.Printf("Error generating TOTP for account %s: %v", account.Name, err)
					continue
				}
				fmt.Printf("Account: %s, TOTP: %s\n", account.Name, passcode)
			}

		case "3":
			fmt.Print("Enter migration data: ")
			migrationData, err := reader.ReadString('\n')
			if err != nil {
				log.Printf("Error reading input: %v", err)
				continue
			}
			migrationData = strings.TrimSpace(migrationData)

			if strings.HasPrefix(migrationData, "otpauth-migration://offline?data=") {
				migrationData = strings.TrimPrefix(migrationData, "otpauth-migration://offline?data=")
			}

			accounts, err := decodeMigrationData(migrationData, debugMode, reader)
			if err != nil {
				log.Printf("Error decoding migration data: %v", err)
				continue
			}

			fmt.Printf("Decoded %d accounts\n", len(accounts))
			for i, account := range accounts {
				fmt.Printf("Account %d: Name=%s, Secret length=%d\n", i, account.Name, len(account.Secret))
			}

			for _, account := range accounts {
				storage.addAccount(account.Name, account.Secret)
			}

			if err := saveStorage(storageFile, storage); err != nil {
				log.Printf("Error saving storage: %v", err)
				continue
			}

			fmt.Println("Accounts migrated successfully")

		case "4":
			debugMode = !debugMode
			if debugMode {
				fmt.Println("Debug mode enabled")
			} else {
				fmt.Println("Debug mode disabled")
			}

		case "5":
			fmt.Println("Exiting...")
			return

		default:
			fmt.Println("Invalid option")
		}
	}
}
