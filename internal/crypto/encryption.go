package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// EncryptMessage encrypts a message with AES-GCM
func EncryptMessage(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt the plaintext
	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)

	// Combine nonce and ciphertext
	result := append(nonce, ciphertext...)

	// Base64 encode for transmission
	return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptMessage decrypts a message with AES-GCM
func DecryptMessage(key []byte, ciphertext string) (string, error) {
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
		return "", fmt.Errorf("ciphertext too short or tampered")
	}
	nonce, encryptedMsg := data[:12], data[12:]

	// Decrypt the message
	plaintext, err := aesGCM.Open(nil, nonce, encryptedMsg, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// EncryptData encrypts data with AES-GCM (for database use)
func EncryptData(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Generate a random nonce
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

// DecryptData decrypts data with AES-GCM (for database use)
func DecryptData(data []byte, key []byte) []byte {
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
