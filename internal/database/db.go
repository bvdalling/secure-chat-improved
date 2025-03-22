package database

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"time"

	"securechat/internal/auth"
	"securechat/internal/crypto"

	"github.com/mattn/go-sqlite3"
)

// Database handles all database operations
type Database struct {
	db            *sql.DB
	encryptionKey []byte
}

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
func (d *Database) AddUser(user auth.User) error {
	// Encrypt sensitive data before storing
	encryptedHash := crypto.EncryptData(user.PasswordHash, d.encryptionKey)
	encryptedSalt := crypto.EncryptData(user.Salt, d.encryptionKey)

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
func (d *Database) GetUser(username string) (*auth.User, error) {
	var user auth.User
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
	user.PasswordHash = crypto.DecryptData(encryptedHash, d.encryptionKey)
	user.Salt = crypto.DecryptData(encryptedSalt, d.encryptionKey)

	return &user, nil
}

// GenerateRegistrationToken creates a new registration token
func (d *Database) GenerateRegistrationToken() (*auth.RegistrationToken, error) {
	// Generate a random token
	token, err := auth.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %v", err)
	}

	// Generate an 8-digit alphanumeric validation code
	validationCode, err := auth.GenerateAlphanumericCode(8)
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

	return &auth.RegistrationToken{
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
