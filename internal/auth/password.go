package auth

import (
	"bytes"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2 parameters
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

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
