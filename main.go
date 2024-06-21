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

// Account struct for storing account information
type Account struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

// Storage struct for storing multiple accounts
type Storage struct {
	Accounts []Account `json:"accounts"`
}

// Function to load storage from a JSON file
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

// Function to save storage to a JSON file
func saveStorage(filename string, storage *Storage) error {
	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// Method to add an account to storage
func (s *Storage) addAccount(name, secret string) {
	s.Accounts = append(s.Accounts, Account{Name: name, Secret: secret})
}

func generateTOTP(secret string) (string, error) {
	// Decode the base32 secret if necessary
	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		// If decoding fails, assume the secret is already in the correct format
		secretBytes = []byte(secret)
	}

	passcode, err := totp.GenerateCode(string(secretBytes), time.Now())
	if err != nil {
		return "", err
	}
	return passcode, nil
}

func decodeMigrationData(data string) ([]Account, error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %v", err)
	}

	var payload MigrationPayload
	err = proto.Unmarshal(decoded, &payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal protobuf: %v", err)
	}

	var accounts []Account
	for i, otp := range payload.OtpParameters {
		secret := base32.StdEncoding.EncodeToString(otp.RawData)
		accounts = append(accounts, Account{
			Name:   fmt.Sprintf("Imported Account %d", i+1),
			Secret: secret,
		})
	}
	return accounts, nil
}

func parseOtpParameter(data []byte) (name, issuer, secret string, err error) {
	for len(data) > 0 {
		tag := data[0]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		data = data[1:]

		switch fieldNum {
		case 1: // name
			if wireType != 2 {
				return "", "", "", fmt.Errorf("invalid wire type for name")
			}
			length := int(data[0])
			name = string(data[1 : length+1])
			data = data[length+1:]
		case 2: // issuer
			if wireType != 2 {
				return "", "", "", fmt.Errorf("invalid wire type for issuer")
			}
			length := int(data[0])
			issuer = string(data[1 : length+1])
			data = data[length+1:]
		case 3: // secret
			if wireType != 2 {
				return "", "", "", fmt.Errorf("invalid wire type for secret")
			}
			length := int(data[0])
			secret = base32.StdEncoding.EncodeToString(data[1 : length+1])
			data = data[length+1:]
		default:
			// Skip unknown fields
			switch wireType {
			case 0: // varint
				for data[0]&0x80 != 0 {
					data = data[1:]
				}
				data = data[1:]
			case 2: // length-delimited
				length := int(data[0])
				data = data[length+1:]
			default:
				return "", "", "", fmt.Errorf("unsupported wire type: %d", wireType)
			}
		}
	}
	return
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

	if wireType == 2 { // Length-delimited field
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
	for {
		fmt.Println("\n1. Add Account")
		fmt.Println("2. Show TOTPs")
		fmt.Println("3. Migrate from Google Authenticator")
		fmt.Println("4. Exit")
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

			accounts, err := decodeMigrationData(migrationData)
			if err != nil {
				log.Printf("Error decoding migration data: %v", err)
				continue
			}

			fmt.Printf("Decoded %d accounts\n", len(accounts))
			for i, account := range accounts {
				fmt.Printf("Account %d\n", i+1)
				fmt.Print("Enter a name for this account: ")
				name, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading input: %v", err)
					continue
				}
				name = strings.TrimSpace(name)
				if name == "" {
					name = account.Name
				}
				storage.addAccount(name, account.Secret)
			}

			if err := saveStorage(storageFile, storage); err != nil {
				log.Printf("Error saving storage: %v", err)
				continue
			}

			fmt.Println("Accounts migrated successfully")

		case "4":
			fmt.Println("Exiting...")
			return

		default:
			fmt.Println("Invalid option")
		}
	}
}
