package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// AuthenticatedMessage represents a message with authentication and integrity protection
type AuthenticatedMessage struct {
	Payload    string `json:"payload"`    // Encrypted message content
	Nonce      string `json:"nonce"`      // Unique value for this message
	Timestamp  int64  `json:"timestamp"`  // When the message was created
	Sender     string `json:"sender"`     // Username of sender (if available)
	MAC        string `json:"mac"`        // Message Authentication Code
	SequenceID int64  `json:"sequenceId"` // Sequence ID to prevent replay attacks
}

// NewAuthenticatedMessage creates a new authenticated message
func NewAuthenticatedMessage(payload string, sender string, sequenceID int64, key []byte) (*AuthenticatedMessage, error) {
	// Generate a random nonce
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, err
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	// Create the message without MAC first
	msg := &AuthenticatedMessage{
		Payload:    payload,
		Nonce:      nonce,
		Timestamp:  time.Now().Unix(),
		Sender:     sender,
		SequenceID: sequenceID,
	}

	// Calculate MAC
	mac, err := calculateMAC(msg, key)
	if err != nil {
		return nil, err
	}
	msg.MAC = mac

	return msg, nil
}

// Verify checks if a message's MAC is valid
func (m *AuthenticatedMessage) Verify(key []byte) (bool, error) {
	// Save the received MAC
	receivedMAC := m.MAC

	// Clear the MAC field for recalculation
	m.MAC = ""

	// Calculate the expected MAC
	expectedMAC, err := calculateMAC(m, key)
	if err != nil {
		return false, err
	}

	// Restore the received MAC
	m.MAC = receivedMAC

	// Compare MACs in constant time to prevent timing attacks
	return hmac.Equal([]byte(receivedMAC), []byte(expectedMAC)), nil
}

// Serialize converts the message to JSON format
func (m *AuthenticatedMessage) Serialize() (string, error) {
	bytes, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// DeserializeAuthenticatedMessage converts a JSON string back to an AuthenticatedMessage
func DeserializeAuthenticatedMessage(data string) (*AuthenticatedMessage, error) {
	bytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	var msg AuthenticatedMessage
	if err := json.Unmarshal(bytes, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// IsExpired checks if a message has expired (useful for preventing replay attacks)
func (m *AuthenticatedMessage) IsExpired(maxAgeSeconds int64) bool {
	return time.Now().Unix()-m.Timestamp > maxAgeSeconds
}

// calculateMAC generates a message authentication code for the message
func calculateMAC(msg *AuthenticatedMessage, key []byte) (string, error) {
	// Prepare data for MAC calculation (JSON without the MAC field)
	data, err := json.Marshal(struct {
		Payload    string `json:"payload"`
		Nonce      string `json:"nonce"`
		Timestamp  int64  `json:"timestamp"`
		Sender     string `json:"sender"`
		SequenceID int64  `json:"sequenceId"`
	}{
		Payload:    msg.Payload,
		Nonce:      msg.Nonce,
		Timestamp:  msg.Timestamp,
		Sender:     msg.Sender,
		SequenceID: msg.SequenceID,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal message for MAC: %v", err)
	}

	// Create HMAC
	h := hmac.New(sha256.New, key)
	h.Write(data)
	macBytes := h.Sum(nil)

	return base64.StdEncoding.EncodeToString(macBytes), nil
}