package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

// DH parameters - in production use larger, well-known safe primes
var (
	// 2048-bit MODP Group from RFC 3526
	Prime, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	Generator = big.NewInt(2)
)

// Argon2 parameters
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

// DHKey represents a Diffie-Hellman key pair
type DHKey struct {
	Private *big.Int
	Public  *big.Int
}

// User represents a registered user
type User struct {
	Username       string
	PasswordHash   []byte
	Salt           []byte
	RegistrationID string
}

// RegistrationToken represents a one-time token for registration
type RegistrationToken struct {
	Token          string    // The token itself
	ValidationCode string    // 8-digit alphanumeric code for validation
	Created        time.Time // When the token was created
	Used           bool      // Whether the token has been used
}

// Database handles all database operations
type Database struct {
	db            *sql.DB
	encryptionKey []byte
}

// ChatServer manages DH key exchange and encrypted communication
type ChatServer struct {
	dhKey         *DHKey
	connections   map[net.Conn]string // map connection to username
	sharedSecrets map[net.Conn][]byte
	database      *Database
	listener      net.Listener
	mutex         sync.Mutex
}

// ChatClient handles DH key exchange and encrypted communication with server
type ChatClient struct {
	dhKey        *DHKey
	conn         net.Conn
	sharedSecret []byte
	username     string
	token        string
}

// Wordlists for username generation
var (
	colors   = []string{"Red", "Blue", "Green", "Yellow", "Purple", "Orange", "Pink", "Black", "White", "Silver", "Gold", "Brown", "Turquoise", "Magenta", "Cyan", "Indigo", "Violet", "Crimson", "Azure", "Emerald"}
	animals  = []string{"Wolf", "Fox", "Lion", "Tiger", "Eagle", "Bear", "Dolphin", "Shark", "Hawk", "Owl", "Panther", "Dragon", "Phoenix", "Unicorn", "Griffin", "Raven", "Cobra", "Falcon", "Jaguar", "Lynx"}
	elements = []string{"Fire", "Water", "Earth", "Air", "Steel", "Light", "Shadow", "Thunder", "Ice", "Crystal", "Plasma", "Stone", "Wind", "Flame", "Ocean", "Mountain", "Storm", "Forest", "Desert", "Void"}
)

// Database functions

// NewDatabase creates a new in-memory SQLite database with encryption
func NewDatabase() (*Database, error) {
	// Generate a random encryption key that will be discarded when the program exits
	encryptionKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, encryptionKey); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	// Register SQLite encryption extension (in a real implementation this would use SQLite encryption extension)
	// For this example, we'll simulate encryption with our own wrapper
	sql.Register("sqlite3_encrypted", &sqlite3.SQLiteDriver{})

	// Connect to in-memory database
	db, err := sql.Open("sqlite3_encrypted", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	database := &Database{
		db:            db,
		encryptionKey: encryptionKey,
	}

	// Create tables
	if err := database.createTables(); err != nil {
		db.Close()
		return nil, err
	}

	return database, nil
}

// createTables creates the necessary tables in the database
func (d *Database) createTables() error {
	// Create users table
	_, err := d.db.Exec(`
		CREATE TABLE users (
			username TEXT PRIMARY KEY,
			password_hash BLOB NOT NULL,
			salt BLOB NOT NULL,
			registration_id TEXT UNIQUE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create users table: %v", err)
	}

	// Create registration tokens table
	_, err = d.db.Exec(`
		CREATE TABLE registration_tokens (
			token TEXT PRIMARY KEY,
			validation_code TEXT NOT NULL,
			created TIMESTAMP NOT NULL,
			used BOOLEAN NOT NULL DEFAULT 0
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create registration_tokens table: %v", err)
	}

	return nil
}

// AddUser adds a new user to the database
func (d *Database) AddUser(user User) error {
	// Encrypt sensitive data before storing
	encryptedHash := encryptData(user.PasswordHash, d.encryptionKey)
	encryptedSalt := encryptData(user.Salt, d.encryptionKey)

	_, err := d.db.Exec(
		"INSERT INTO users (username, password_hash, salt, registration_id) VALUES (?, ?, ?, ?)",
		user.Username, encryptedHash, encryptedSalt, user.RegistrationID,
	)
	if err != nil {
		return fmt.Errorf("failed to add user: %v", err)
	}
	return nil
}

// GetUser retrieves a user from the database by username
func (d *Database) GetUser(username string) (*User, error) {
	var user User
	var encryptedHash, encryptedSalt []byte

	err := d.db.QueryRow(
		"SELECT username, password_hash, salt, registration_id FROM users WHERE username = ?",
		username,
	).Scan(&user.Username, &encryptedHash, &encryptedSalt, &user.RegistrationID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, fmt.Errorf("failed to get user: %v", err)
	}

	// Decrypt sensitive data
	user.PasswordHash = decryptData(encryptedHash, d.encryptionKey)
	user.Salt = decryptData(encryptedSalt, d.encryptionKey)

	return &user, nil
}

// GenerateRegistrationToken creates a new registration token
func (d *Database) GenerateRegistrationToken() (*RegistrationToken, error) {
	// Generate a random token
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %v", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Generate an 8-digit alphanumeric validation code
	validationCode, err := generateAlphanumericCode(8)
	if err != nil {
		return nil, fmt.Errorf("failed to generate validation code: %v", err)
	}

	// Store the token in the database
	_, err = d.db.Exec(
		"INSERT INTO registration_tokens (token, validation_code, created, used) VALUES (?, ?, ?, 0)",
		token, validationCode, time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to store token: %v", err)
	}

	return &RegistrationToken{
		Token:          token,
		ValidationCode: validationCode,
		Created:        time.Now(),
		Used:           false,
	}, nil
}

// ValidateRegistrationToken checks if a token is valid and marks it as used
func (d *Database) ValidateRegistrationToken(token, validationCode string) (bool, error) {
	var used bool
	var storedValidationCode string
	var created time.Time

	err := d.db.QueryRow(
		"SELECT validation_code, created, used FROM registration_tokens WHERE token = ?",
		token,
	).Scan(&storedValidationCode, &created, &used)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // Token not found
		}
		return false, fmt.Errorf("failed to get token: %v", err)
	}

	// Check if token is valid
	if used {
		return false, nil // Token already used
	}

	// Check if token is expired (24 hour validity)
	if time.Since(created) > 24*time.Hour {
		return false, nil // Token expired
	}

	// Check validation code
	if storedValidationCode != validationCode {
		return false, nil // Invalid validation code
	}

	// Mark token as used
	_, err = d.db.Exec("UPDATE registration_tokens SET used = 1 WHERE token = ?", token)
	if err != nil {
		return false, fmt.Errorf("failed to mark token as used: %v", err)
	}

	return true, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	// Zero out the encryption key
	for i := range d.encryptionKey {
		d.encryptionKey[i] = 0
	}
	return d.db.Close()
}

// Auth utilities

// HashPassword hashes a password using Argon2id
func HashPassword(password string) (hash []byte, salt []byte, err error) {
	// Generate a random salt
	salt = make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}

	// Hash the password
	hash = argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return hash, salt, nil
}

// VerifyPassword checks if a password matches a hash
func VerifyPassword(password string, hash []byte, salt []byte) bool {
	// Hash the password with the provided salt
	newHash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	// Compare the hashes
	return bytes.Equal(hash, newHash)
}

// GenerateUsername generates a random username in the format color-animal-element
func GenerateUsername() string {
	// Select random words from each category
	color := colors[secureRandomInt(len(colors))]
	animal := animals[secureRandomInt(len(animals))]
	element := elements[secureRandomInt(len(elements))]

	return fmt.Sprintf("%s-%s-%s", color, animal, element)
}

// Encryption utilities

// encryptData encrypts data with AES-GCM
func encryptData(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Never use the same nonce more than once with the same key
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// Encrypt and append nonce
	ciphertext := aesGCM.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...)
}

// decryptData decrypts data with AES-GCM
func decryptData(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// Extract nonce and ciphertext
	if len(data) < 12 {
		panic("ciphertext too short")
	}
	nonce, ciphertext := data[:12], data[12:]

	// Decrypt
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	return plaintext
}

// DH Key utilities

// GenerateDHKeys generates a new DH key pair
func GenerateDHKeys() (*DHKey, error) {
	// Generate a random private key
	privateKey, err := rand.Int(rand.Reader, Prime)
	if err != nil {
		return nil, err
	}

	// Calculate public key: g^private mod p
	publicKey := new(big.Int).Exp(Generator, privateKey, Prime)

	return &DHKey{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}

// ComputeSharedSecret calculates the shared secret from our private key and their public key
func ComputeSharedSecret(privateKey, peerPublicKey *big.Int) []byte {
	// Calculate shared secret: (peer_public)^private mod p
	sharedSecret := new(big.Int).Exp(peerPublicKey, privateKey, Prime)

	// Convert to bytes and hash it to get a suitable encryption key
	sharedBytes := sharedSecret.Bytes()
	hash := sha256.Sum256(sharedBytes)

	return hash[:]
}

// Message encryption/decryption functions

func encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Never use the same nonce more than once with the same key
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt and append nonce
	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)
	result := append(nonce, ciphertext...)

	// Base64 encode for transmission
	return base64.StdEncoding.EncodeToString(result), nil
}

func decrypt(key []byte, ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Split nonce and ciphertext
	if len(data) < 12 {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, encryptedMsg := data[:12], data[12:]

	// Decrypt
	plaintext, err := aesGCM.Open(nil, nonce, encryptedMsg, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Utility functions

// generateAlphanumericCode generates a random alphanumeric code of the specified length
func generateAlphanumericCode(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, err := secureRandomBytes(1)
		if err != nil {
			return "", err
		}
		result[i] = charset[int(n[0])%len(charset)]
	}
	return string(result), nil
}

// secureRandomInt returns a secure random integer in the range [0, max)
func secureRandomInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return int(n.Int64())
}

// secureRandomBytes returns secure random bytes of the specified length
func secureRandomBytes(length int) ([]byte, error) {
	result := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, result)
	return result, err
}

// Server implementation

// NewChatServer creates a new chat server with DH capabilities
func NewChatServer(port string) (*ChatServer, error) {
	// Generate server's DH keys
	dhKey, err := GenerateDHKeys()
	if err != nil {
		return nil, err
	}

	// Initialize database
	database, err := NewDatabase()
	if err != nil {
		return nil, err
	}

	// Start listening
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		database.Close()
		return nil, err
	}

	return &ChatServer{
		dhKey:         dhKey,
		connections:   make(map[net.Conn]string),
		sharedSecrets: make(map[net.Conn][]byte),
		database:      database,
		listener:      listener,
	}, nil
}

// Run starts the chat server
func (s *ChatServer) Run() {
	fmt.Println("Chat server started on", s.listener.Addr())
	fmt.Println("Server public DH key:", hex.EncodeToString(s.dhKey.Public.Bytes()))

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			fmt.Println("Connection error:", err)
			continue
		}

		// Handle each client in a goroutine
		go s.handleClient(conn)
	}
}

// handleClient manages authentication, DH key exchange, and communication with a client
func (s *ChatServer) handleClient(conn net.Conn) {
	defer conn.Close()

	// First, handle authentication
	buffer := make([]byte, 4096)

	// Read auth request
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Read error:", err)
		return
	}

	authRequest := string(buffer[:n])
	parts := strings.Split(authRequest, ":")

	if len(parts) < 2 {
		conn.Write([]byte("ERROR:INVALID_REQUEST"))
		return
	}

	switch parts[0] {
	case "REGISTER":
		// Registration request: REGISTER:token:validation_code:password
		if len(parts) != 4 {
			conn.Write([]byte("ERROR:INVALID_REGISTER"))
			return
		}

		token, validationCode, password := parts[1], parts[2], parts[3]

		// Validate the token
		valid, err := s.database.ValidateRegistrationToken(token, validationCode)
		if err != nil {
			fmt.Println("Token validation error:", err)
			conn.Write([]byte("ERROR:SERVER_ERROR"))
			return
		}

		if !valid {
			conn.Write([]byte("ERROR:INVALID_TOKEN"))
			return
		}

		// Generate a unique username
		username := GenerateUsername()

		// Make sure username is unique
		for {
			user, err := s.database.GetUser(username)
			if err != nil {
				fmt.Println("Database error:", err)
				conn.Write([]byte("ERROR:SERVER_ERROR"))
				return
			}

			if user == nil {
				break // Username is unique
			}

			// Try another username
			username = GenerateUsername()
		}

		// Hash the password
		hash, salt, err := HashPassword(password)
		if err != nil {
			fmt.Println("Password hashing error:", err)
			conn.Write([]byte("ERROR:SERVER_ERROR"))
			return
		}

		// Create the user
		user := User{
			Username:       username,
			PasswordHash:   hash,
			Salt:           salt,
			RegistrationID: token,
		}

		err = s.database.AddUser(user)
		if err != nil {
			fmt.Println("User creation error:", err)
			conn.Write([]byte("ERROR:SERVER_ERROR"))
			return
		}

		// Send success response with username
		conn.Write([]byte("REGISTERED:" + username))

	case "LOGIN":
		// Login request: LOGIN:username:password
		if len(parts) != 3 {
			conn.Write([]byte("ERROR:INVALID_LOGIN"))
			return
		}

		username, password := parts[1], parts[2]

		// Get the user
		user, err := s.database.GetUser(username)
		if err != nil {
			fmt.Println("Database error:", err)
			conn.Write([]byte("ERROR:SERVER_ERROR"))
			return
		}

		if user == nil {
			conn.Write([]byte("ERROR:INVALID_CREDENTIALS"))
			return
		}

		// Verify the password
		if !VerifyPassword(password, user.PasswordHash, user.Salt) {
			conn.Write([]byte("ERROR:INVALID_CREDENTIALS"))
			return
		}

		// Send success response
		conn.Write([]byte("AUTHENTICATED"))

		// Proceed with DH key exchange
		n, err = conn.Read(buffer)
		if err != nil {
			fmt.Println("Read error:", err)
			return
		}

		// Parse client's public key
		clientPubKey, ok := new(big.Int).SetString(string(buffer[:n]), 16)
		if !ok {
			fmt.Println("Invalid public key received")
			return
		}

		// Send our public key
		_, err = conn.Write([]byte(s.dhKey.Public.Text(16)))
		if err != nil {
			fmt.Println("Write error:", err)
			return
		}

		// Compute shared secret
		sharedSecret := ComputeSharedSecret(s.dhKey.Private, clientPubKey)

		// Store client information
		s.mutex.Lock()
		s.connections[conn] = username
		s.sharedSecrets[conn] = sharedSecret
		s.mutex.Unlock()

		fmt.Printf("User %s connected with DH key exchange completed\n", username)

		// Broadcast user connected message
		s.broadcastServerMessage(username + " has joined the chat")

		// Handle messages
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				s.mutex.Lock()
				username := s.connections[conn]
				delete(s.connections, conn)
				delete(s.sharedSecrets, conn)
				s.mutex.Unlock()

				fmt.Printf("User %s disconnected\n", username)
				s.broadcastServerMessage(username + " has left the chat")
				return
			}

			// Decrypt the message
			encryptedMsg := string(buffer[:n])
			plaintext, err := decrypt(sharedSecret, encryptedMsg)
			if err != nil {
				fmt.Println("Decryption error:", err)
				continue
			}

			fmt.Printf("[%s]: %s\n", username, plaintext)

			// Broadcast to other clients
			s.broadcastMessage(conn, username, plaintext)
		}

	case "REQUEST_TOKEN":
		// Generate a new registration token
		token, err := s.database.GenerateRegistrationToken()
		if err != nil {
			fmt.Println("Token generation error:", err)
			conn.Write([]byte("ERROR:SERVER_ERROR"))
			return
		}

		// Send the token and validation code
		response := fmt.Sprintf("TOKEN:%s:%s", token.Token, token.ValidationCode)
		conn.Write([]byte(response))

		fmt.Printf("Generated registration token: %s with validation code: %s\n", token.Token, token.ValidationCode)

	default:
		conn.Write([]byte("ERROR:UNKNOWN_COMMAND"))
	}
}

// broadcastMessage sends an encrypted message to all clients except the sender
func (s *ChatServer) broadcastMessage(sender net.Conn, username string, message string) {
	formatted := fmt.Sprintf("[%s]: %s", username, message)
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for conn, secret := range s.sharedSecrets {
		if conn != sender {
			encryptedMsg, err := encrypt(secret, formatted)
			if err != nil {
				fmt.Println("Encryption error:", err)
				continue
			}
			conn.Write([]byte(encryptedMsg))
		}
	}
}

// broadcastServerMessage sends a server message to all connected clients
func (s *ChatServer) broadcastServerMessage(message string) {
	formatted := fmt.Sprintf("[SERVER]: %s", message)
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for conn, secret := range s.sharedSecrets {
		encryptedMsg, err := encrypt(secret, formatted)
		if err != nil {
			fmt.Println("Encryption error:", err)
			continue
		}
		conn.Write([]byte(encryptedMsg))
	}
}

// Client implementation

// NewChatClient creates a new chat client with DH capabilities
func NewChatClient(serverAddr string) (*ChatClient, error) {
	// Generate client's DH keys
	dhKey, err := GenerateDHKeys()
	if err != nil {
		return nil, err
	}

	// Connect to server
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	return &ChatClient{
		dhKey: dhKey,
		conn:  conn,
	}, nil
}

// RequestRegistrationToken requests a registration token from the server
func (c *ChatClient) RequestRegistrationToken() (string, string, error) {
	// Send request
	_, err := c.conn.Write([]byte("REQUEST_TOKEN"))
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

	if parts[0] != "TOKEN" || len(parts) != 3 {
		return "", "", fmt.Errorf("invalid server response: %s", response)
	}

	return parts[1], parts[2], nil
}

// Register registers a new user with the server
func (c *ChatClient) Register(token, validationCode, password string) (string, error) {
	// Send registration request
	request := fmt.Sprintf("REGISTER:%s:%s:%s", token, validationCode, password)
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

	if parts[0] != "REGISTERED" || len(parts) != 2 {
		return "", fmt.Errorf("registration failed: %s", response)
	}

	c.username = parts[1]
	return c.username, nil
}

// Login logs in an existing user
func (c *ChatClient) Login(username, password string) error {
	// Send login request
	request := fmt.Sprintf("LOGIN:%s:%s", username, password)
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
	if response != "AUTHENTICATED" {
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
	c.sharedSecret = ComputeSharedSecret(c.dhKey.Private, serverPubKey)

	fmt.Println("Connected to server with DH key exchange completed")
	return nil
}

// SendMessage encrypts and sends a message to the server
func (c *ChatClient) SendMessage(message string) error {
	encryptedMsg, err := encrypt(c.sharedSecret, message)
	if err != nil {
		return err
	}

	_, err = c.conn.Write([]byte(encryptedMsg))
	return err
}

// ReceiveMessages continuously receives and decrypts messages from the server
func (c *ChatClient) ReceiveMessages() {
	buffer := make([]byte, 4096)
	for {
		n, err := c.conn.Read(buffer)
		if err != nil {
			fmt.Println("Disconnected from server")
			os.Exit(1)
		}

		encryptedMsg := string(buffer[:n])
		plaintext, err := decrypt(c.sharedSecret, encryptedMsg)
		if err != nil {
			fmt.Println("Decryption error:", err)
			continue
		}

		fmt.Println(plaintext)
	}
}

// Main function with interactive CLI

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: program [server|client] [options]")
		os.Exit(1)
	}

	mode := os.Args[1]

	if mode == "server" {
		port := "8080"
		if len(os.Args) > 2 {
			port = os.Args[2]
		}

		server, err := NewChatServer(port)
		if err != nil {
			fmt.Println("Error starting server:", err)
			os.Exit(1)
		}

		fmt.Println("Server started on port", port)
		fmt.Println("Use the client to request registration tokens")
		server.Run()
	} else if mode == "client" {
		serverAddr := "localhost:8080"
		if len(os.Args) > 2 {
			serverAddr = os.Args[2]
		}

		client, err := NewChatClient(serverAddr)
		if err != nil {
			fmt.Println("Error creating client:", err)
			os.Exit(1)
		}

		// Interactive client menu
		fmt.Println("===== Secure Chat Client =====")
		fmt.Println("1. Request registration token")
		fmt.Println("2. Register new account")
		fmt.Println("3. Login")
		fmt.Print("Choose an option: ")

		var option int
		fmt.Scanln(&option)

		switch option {
		case 1:
			fmt.Println("Requesting registration token...")
			token, validationCode, err := client.RequestRegistrationToken()
			if err != nil {
				fmt.Println("Error requesting token:", err)
				os.Exit(1)
			}

			fmt.Println("Registration token:", token)
			fmt.Println("Validation code:", validationCode)
			fmt.Println("Keep these values to register an account.")

		case 2:
			var token, validationCode, password string

			fmt.Print("Enter registration token: ")
			fmt.Scanln(&token)

			fmt.Print("Enter validation code: ")
			fmt.Scanln(&validationCode)

			fmt.Print("Create password: ")
			fmt.Scanln(&password)

			username, err := client.Register(token, validationCode, password)
			if err != nil {
				fmt.Println("Registration error:", err)
				os.Exit(1)
			}

			fmt.Println("Registration successful!")
			fmt.Println("Your username is:", username)
			fmt.Println("Please login with your new credentials.")

		case 3:
			var username, password string

			fmt.Print("Username: ")
			fmt.Scanln(&username)

			fmt.Print("Password: ")
			fmt.Scanln(&password)

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
	} else {
		fmt.Println("Invalid mode. Use 'server' or 'client'")
		os.Exit(1)
	}
}
