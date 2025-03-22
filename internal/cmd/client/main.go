package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"securechat/internal/chat"

	"golang.org/x/term"
)

// readPassword reads a password from stdin without echoing it
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	// Get the file descriptor of stdin
	fd := int(syscall.Stdin)

	// Read password without echoing
	passwordBytes, err := term.ReadPassword(fd)

	// Print a newline after reading the password
	fmt.Println()

	if err != nil {
		return "", err
	}

	return string(passwordBytes), nil
}

func main() {
	serverAddr := "localhost:8080"
	if len(os.Args) > 1 {
		serverAddr = os.Args[1]
	}

	fmt.Println("Connecting to secure chat server at", serverAddr)
	client, err := chat.NewClient(serverAddr)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		os.Exit(1)
	}

	defer client.Close()

	// Interactive client menu
	fmt.Println("===== Secure Chat Client =====")
	fmt.Println("1. Request registration validation code")
	fmt.Println("2. Register new account")
	fmt.Println("3. Login")
	fmt.Print("Choose an option: ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	option := strings.TrimSpace(input)

	switch option {
	case "1":
		fmt.Println("Requesting registration validation code...")
		_, validationCode, err := client.RequestRegistrationToken()
		if err != nil {
			fmt.Println("Error requesting validation code:", err)
			os.Exit(1)
		}

		fmt.Println("Your validation code is:", validationCode)
		fmt.Println("IMPORTANT: Contact your administrator to get your registration token.")
		fmt.Println("You will need both the token and this validation code to register.")

	case "2":
		fmt.Println("Please enter the registration token provided by your administrator:")
		fmt.Print("Registration token: ")
		token, _ := reader.ReadString('\n')
		token = strings.TrimSpace(token)

		fmt.Print("Enter validation code: ")
		validationCode, _ := reader.ReadString('\n')
		validationCode = strings.TrimSpace(validationCode)

		// Read password without echoing
		password, err := readPassword("Create password: ")
		if err != nil {
			fmt.Println("Error reading password:", err)
			os.Exit(1)
		}

		username, err := client.Register(token, validationCode, password)
		if err != nil {
			fmt.Println("Registration error:", err)
			os.Exit(1)
		}

		fmt.Println("Registration successful!")
		fmt.Println("Your username is:", username)
		fmt.Println("Please login with your new credentials.")

	case "3":
		fmt.Print("Username: ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)

		// Read password without echoing
		password, err := readPassword("Password: ")
		if err != nil {
			fmt.Println("Error reading password:", err)
			os.Exit(1)
		}

		err = client.Login(username, password)
		if err != nil {
			fmt.Println("Login error:", err)
			os.Exit(1)
		}

		fmt.Println("Login successful!")
		fmt.Println("Establishing secure connection...")

		err = client.Connect()
		if err != nil {
			fmt.Println("Connection error:", err)
			os.Exit(1)
		}

		fmt.Println("Secure connection established!")
		fmt.Println("Type messages and press Enter to send.")

		// Start receiving messages in a goroutine
		go client.ReceiveMessages()

		// Read messages from stdin
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			message := scanner.Text()

			if message != "" {
				err = client.SendMessage(message)
				if err != nil {
					fmt.Println("Error sending message:", err)
				}
			}
		}

	default:
		fmt.Println("Invalid option")
		os.Exit(1)
	}
}
