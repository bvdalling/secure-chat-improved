package chat

import (
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"securechat/internal/crypto"
	"securechat/internal/protocol"
)

// ChatClient handles DH key exchange and encrypted communication with server
type ChatClient struct {
	dhKey           *crypto.DHKey
	conn            net.Conn
	sharedSecret    []byte
	username        string
	token           string
	sequenceCounter int64
}

// NewClient creates a new chat client with DH capabilities
func NewClient(serverAddr string) (*ChatClient, error) {
	// Generate client's DH keys
	dhKey, err := crypto.GenerateDHKeys()
	if err != nil {
		return nil, err
	}

	// Create TLS configuration
	tlsConfig := crypto.CreateClientTLSConfig(true) // Skip verification for self-signed certs

	// Connect to server with TLS
	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		return nil, err
	}

	return &ChatClient{
		dhKey: dhKey,
		conn:  conn,
	}, nil
}

// RequestRegistrationToken requests a validation code from the server
// The token will only be visible to the server admin
func (c *ChatClient) RequestRegistrationToken() (string, string, error) {
	// Send request
	_, err := c.conn.Write([]byte(protocol.FormatRequestTokenRequest()))
	if err != nil {
		return "", "", err
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := c.conn.Read(buffer)
	if err != nil {
		return "", "", err
	}

	response := string(buffer[:n])
	parts := strings.Split(response, ":")

	if parts[0] != protocol.RespValidationCode || len(parts) != 2 {
		return "", "", fmt.Errorf("invalid server response: %s", response)
	}

	validationCode := parts[1]

	// Return only validation code and a placeholder for token
	// Token must be provided by admin out-of-band
	return "CONTACT_ADMIN_FOR_TOKEN", validationCode, nil
}

// Register registers a new user with the server
func (c *ChatClient) Register(token, validationCode, password string) (string, error) {
	// Send registration request
	request := protocol.FormatRegisterRequest(token, validationCode, password)
	_, err := c.conn.Write([]byte(request))
	if err != nil {
		return "", err
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := c.conn.Read(buffer)
	if err != nil {
		return "", err
	}

	response := string(buffer[:n])
	parts := strings.Split(response, ":")

	if parts[0] != protocol.RespRegistered || len(parts) != 2 {
		return "", fmt.Errorf("registration failed: %s", response)
	}

	c.username = parts[1]
	return c.username, nil
}

// Login logs in an existing user
func (c *ChatClient) Login(username, password string) error {
	// Send login request
	request := protocol.FormatLoginRequest(username, password)
	_, err := c.conn.Write([]byte(request))
	if err != nil {
		return err
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := c.conn.Read(buffer)
	if err != nil {
		return err
	}

	response := string(buffer[:n])
	if response != protocol.RespAuthenticated {
		return fmt.Errorf("authentication failed: %s", response)
	}

	c.username = username
	return nil
}

// Connect performs DH key exchange with the server
func (c *ChatClient) Connect() error {
	// Send our public key
	_, err := c.conn.Write([]byte(c.dhKey.Public.Text(16)))
	if err != nil {
		return err
	}

	// Receive server's public key
	buffer := make([]byte, 1024)
	n, err := c.conn.Read(buffer)
	if err != nil {
		return err
	}

	// Parse server's public key
	serverPubKey, ok := new(big.Int).SetString(string(buffer[:n]), 16)
	if !ok {
		return fmt.Errorf("invalid public key received")
	}

	// Compute shared secret
	c.sharedSecret = crypto.ComputeSharedSecret(c.dhKey.Private, serverPubKey)

	fmt.Println("Connected to server with DH key exchange completed")
	return nil
}

// getNextSequenceID atomically increments and returns the sequence counter
func (c *ChatClient) getNextSequenceID() int64 {
	return atomic.AddInt64(&c.sequenceCounter, 1)
}

// SendMessage encrypts and sends a message to the server
func (c *ChatClient) SendMessage(message string) error {
	// Encrypt the message
	encryptedMsg, err := crypto.EncryptMessage(c.sharedSecret, message)
	if err != nil {
		return err
	}

	// Create authenticated message
	sequenceID := c.getNextSequenceID()
	authMsg, err := crypto.NewAuthenticatedMessage(encryptedMsg, c.username, sequenceID, c.sharedSecret)
	if err != nil {
		return fmt.Errorf("failed to create authenticated message: %v", err)
	}

	// Serialize and send
	serialized, err := authMsg.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize message: %v", err)
	}

	_, err = c.conn.Write([]byte(serialized))
	return err
}

// ReceiveMessages continuously receives and decrypts messages from the server
func (c *ChatClient) ReceiveMessages() {
	buffer := make([]byte, 8192) // Increased buffer size for authenticated messages
	for {
		n, err := c.conn.Read(buffer)
		if err != nil {
			fmt.Println("Disconnected from server")
			os.Exit(1)
		}

		// Parse authenticated message
		authMsgStr := string(buffer[:n])
		authMsg, err := crypto.DeserializeAuthenticatedMessage(authMsgStr)
		if err != nil {
			fmt.Println("Message parsing error:", err)
			continue
		}

		// Verify message authenticity
		isValid, err := authMsg.Verify(c.sharedSecret)
		if err != nil || !isValid {
			fmt.Println("Message authentication failed, potential tampering detected")
			continue
		}

		// Check for replay attack
		if authMsg.IsExpired(60) { // 60 seconds expiry
			fmt.Println("Expired message received, potential replay attack")
			continue
		}

		// Decrypt the payload
		plaintext, err := crypto.DecryptMessage(c.sharedSecret, authMsg.Payload)
		if err != nil {
			fmt.Println("Decryption error:", err)
			continue
		}

		// Format message with sender (if not from ourselves)
		if authMsg.Sender != c.username {
			fmt.Printf("[%s]: %s\n", authMsg.Sender, plaintext)
		} else {
			fmt.Println(plaintext)
		}
	}
}

// Close closes the connection to the server
func (c *ChatClient) Close() error {
	// Zero out sensitive data
	if c.sharedSecret != nil {
		for i := range c.sharedSecret {
			c.sharedSecret[i] = 0
		}
	}

	return c.conn.Close()
}
