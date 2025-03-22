package chat

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"securechat/internal/auth"
	"securechat/internal/crypto"
	"securechat/internal/database"
	"securechat/internal/protocol"
)

// ChatServer manages DH key exchange and encrypted communication
type ChatServer struct {
	dhKey            *crypto.DHKey
	connections      map[net.Conn]string // map connection to username
	sharedSecrets    map[net.Conn][]byte
	database         *database.Database
	listener         net.Listener
	mutex            sync.Mutex
	sequenceCounters map[string]*int64 // Track message sequence IDs by username
}

// NewServer creates a new chat server with DH capabilities
func NewServer(port string) (*ChatServer, error) {
	// Generate server's DH keys
	dhKey, err := crypto.GenerateDHKeys()
	if err != nil {
		return nil, err
	}

	// Initialize database
	db, err := database.NewDatabase()
	if err != nil {
		return nil, err
	}

	// Create TLS configuration
	tlsConfig, err := crypto.CreateTLSConfig()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create TLS config: %v", err)
	}

	// Start listening with TLS
	listener, err := tls.Listen("tcp", "0.0.0.0:8080", tlsConfig)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &ChatServer{
		dhKey:            dhKey,
		connections:      make(map[net.Conn]string),
		sharedSecrets:    make(map[net.Conn][]byte),
		database:         db,
		listener:         listener,
		sequenceCounters: make(map[string]*int64),
	}, nil
}

// getNextSequenceID gets the next sequence ID for a given username
func (s *ChatServer) getNextSequenceID(username string) int64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	counter, exists := s.sequenceCounters[username]
	if !exists {
		counter = new(int64)
		s.sequenceCounters[username] = counter
	}

	return atomic.AddInt64(counter, 1)
}

// Run starts the chat server
func (s *ChatServer) Run() {
	fmt.Println("Secure chat server started on", s.listener.Addr())
	fmt.Println("TLS enabled with certificate:", crypto.GetCertificatePath())
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

	print("")

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

	if len(parts) < 1 {
		conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrInvalidRequest)))
		return
	}

	switch parts[0] {
	case protocol.CmdRegister:
		// Registration request: REGISTER:token:validation_code:password
		if len(parts) != 4 {
			conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrInvalidRegister)))
			return
		}

		token, validationCode, password := parts[1], parts[2], parts[3]

		// Validate the token
		valid, err := s.database.ValidateRegistrationToken(token, validationCode)
		if err != nil {
			fmt.Println("Token validation error:", err)
			conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrServerError)))
			return
		}

		if !valid {
			conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrInvalidToken)))
			return
		}

		// Generate a unique username
		username := auth.GenerateUsername()

		// Make sure username is unique
		for {
			user, err := s.database.GetUser(username)
			if err != nil {
				fmt.Println("Database error:", err)
				conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrServerError)))
				return
			}

			if user == nil {
				break // Username is unique
			}

			// Try another username
			username = auth.GenerateUsername()
		}

		// Hash the password
		hash, salt, err := auth.HashPassword(password)
		if err != nil {
			fmt.Println("Password hashing error:", err)
			conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrServerError)))
			return
		}

		// Create the user
		user := auth.User{
			Username:       username,
			PasswordHash:   hash,
			Salt:           salt,
			RegistrationID: token,
		}

		err = s.database.AddUser(user)
		if err != nil {
			fmt.Println("User creation error:", err)
			conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrServerError)))
			return
		}

		// Send success response with username
		conn.Write([]byte(protocol.FormatRegisteredResponse(username)))

	case protocol.CmdLogin:
		// Login request: LOGIN:username:password
		if len(parts) != 3 {
			conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrInvalidLogin)))
			return
		}

		username, password := parts[1], parts[2]

		// Get the user
		user, err := s.database.GetUser(username)
		if err != nil {
			fmt.Println("Database error:", err)
			conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrServerError)))
			return
		}

		if user == nil {
			conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrInvalidCredentials)))
			return
		}

		// Verify the password
		if !auth.VerifyPassword(password, user.PasswordHash, user.Salt) {
			conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrInvalidCredentials)))
			return
		}

		// Send success response
		conn.Write([]byte(protocol.RespAuthenticated))

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
		sharedSecret := crypto.ComputeSharedSecret(s.dhKey.Private, clientPubKey)

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

			// Parse authenticated message
			authMsgStr := string(buffer[:n])
			authMsg, err := crypto.DeserializeAuthenticatedMessage(authMsgStr)
			if err != nil {
				fmt.Println("Message parsing error:", err)
				continue
			}

			// Verify message integrity
			isValid, err := authMsg.Verify(sharedSecret)
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
			plaintext, err := crypto.DecryptMessage(sharedSecret, authMsg.Payload)
			if err != nil {
				fmt.Println("Decryption error:", err)
				continue
			}

			fmt.Printf("[%s]: %s\n", username, plaintext)

			// Broadcast to other clients
			s.broadcastMessage(conn, username, plaintext)
		}

	case protocol.CmdRequestToken:
		// Generate a new registration token
		token, err := s.database.GenerateRegistrationToken()
		if err != nil {
			fmt.Println("Token generation error:", err)
			conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrServerError)))
			return
		}

		// Print ONLY the token to the server admin console (for out-of-band distribution)
		fmt.Printf("ADMIN: Generated registration token: %s\n", token.Token)

		// Send ONLY the validation code to the user
		response := protocol.FormatValidationCodeResponse(token.ValidationCode)
		conn.Write([]byte(response))

		fmt.Println("User has been sent the validation code only")

	default:
		conn.Write([]byte(protocol.FormatErrorResponse(protocol.ErrUnknownCommand)))
	}
}

// broadcastMessage sends an encrypted message to all clients except the sender
func (s *ChatServer) broadcastMessage(sender net.Conn, username string, message string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for conn, receiverName := range s.connections {
		if conn != sender {
			secret := s.sharedSecrets[conn]

			// Encrypt the message
			encryptedMsg, err := crypto.EncryptMessage(secret, message)
			if err != nil {
				fmt.Println("Encryption error:", err)
				continue
			}

			// Create authenticated message
			sequenceID := s.getNextSequenceID(receiverName)
			authMsg, err := crypto.NewAuthenticatedMessage(encryptedMsg, username, sequenceID, secret)
			if err != nil {
				fmt.Println("Failed to create authenticated message:", err)
				continue
			}

			// Serialize and send
			serialized, err := authMsg.Serialize()
			if err != nil {
				fmt.Println("Failed to serialize message:", err)
				continue
			}

			conn.Write([]byte(serialized))
		}
	}
}

// broadcastServerMessage sends a server message to all connected clients
func (s *ChatServer) broadcastServerMessage(message string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for conn, username := range s.connections {
		secret := s.sharedSecrets[conn]

		// Encrypt the message
		encryptedMsg, err := crypto.EncryptMessage(secret, message)
		if err != nil {
			fmt.Println("Encryption error:", err)
			continue
		}

		// Create authenticated message
		sequenceID := s.getNextSequenceID(username)
		authMsg, err := crypto.NewAuthenticatedMessage(encryptedMsg, "SERVER", sequenceID, secret)
		if err != nil {
			fmt.Println("Failed to create authenticated message:", err)
			continue
		}

		// Serialize and send
		serialized, err := authMsg.Serialize()
		if err != nil {
			fmt.Println("Failed to serialize message:", err)
			continue
		}

		conn.Write([]byte(serialized))
	}
}

// Close closes the server and all resources
func (s *ChatServer) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Close all client connections
	for conn := range s.connections {
		conn.Close()
	}

	// Clear maps
	s.connections = make(map[net.Conn]string)
	s.sharedSecrets = make(map[net.Conn][]byte)
	s.sequenceCounters = make(map[string]*int64)

	// Close database
	if err := s.database.Close(); err != nil {
		return err
	}

	// Close listener
	return s.listener.Close()
}
