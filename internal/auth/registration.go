package auth

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
)

// GenerateAlphanumericCode generates a random alphanumeric code of the specified length
func GenerateAlphanumericCode(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, err := SecureRandomBytes(1)
		if err != nil {
			return "", err
		}
		result[i] = charset[int(n[0])%len(charset)]
	}
	return string(result), nil
}

// GenerateToken generates a secure random token
func GenerateToken() (string, error) {
	// Generate a random token
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(tokenBytes), nil
}

// SecureRandomInt returns a secure random integer in the range [0, max)
func SecureRandomInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return int(n.Int64())
}

// SecureRandomBytes returns secure random bytes of the specified length
func SecureRandomBytes(length int) ([]byte, error) {
	result := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, result)
	return result, err
}
