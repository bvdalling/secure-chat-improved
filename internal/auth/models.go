package auth

import (
	"time"
)

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
