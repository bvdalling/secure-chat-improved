# SecureChat Security Features Guide

## Overview

SecureChat is a secure terminal-based chat application built with Go, featuring multiple layers of cryptographic protection. This document explains the key security features, how they work, and how to use them effectively.

The main use-case is to have a private and secure messaging room. However, keep in mind that anything you do online is logged, monitored, and can be used against you. This is `good-enough` privacy and security for transmitting one-time-secrets and other information. But never use this if your safety and security depend on it.

It's easier to use something like signal as a daily driver. This was built as a proof-of-concept for the Cache Tech Community relating to a series of talks regarding data and information security in GO-based applications. This application is not perfect. It is not safe. There is no warranty or gauruntee of privacy and security. Use of this tool is at your own descretion and you are responsible for what you do with it.

## Core Security Features

### 1. End-to-End Encryption

**What it is**: Messages are encrypted on the sender's device and can only be decrypted by the intended recipient.

**How it works**:

- Uses Diffie-Hellman key exchange to establish a shared secret
- AES-GCM for authenticated encryption of messages
- Fresh keys for each session

**Usage**:

```go
// Automatically handled during connection setup
client.Connect()

// To send an encrypted message
client.SendMessage("Your secure message")
```

**Security benefit**: Even if someone intercepts network traffic, they cannot read message contents.

### 2. TLS Transport Security

**What it is**: An encrypted tunnel for all client-server communications.

**How it works**:

- Self-signed certificates generated on first run
- TLS 1.2+ with strong cipher suites
- Server authentication via certificate

**Usage**:

```bash
# Start server (certificates automatically generated)
./server 8080

# Connect client (skips certificate verification for self-signed certs)
./client localhost:8080
```

**Security benefit**: Provides an additional encryption layer and helps prevent man-in-the-middle attacks.

### 3. Message Authentication

**What it is**: Cryptographic proof that messages haven't been tampered with.

**How it works**:

- HMAC-SHA256 for message authentication codes
- Unique nonce values for each message
- Includes timestamp and sequence numbers to prevent replay attacks

**Usage**:

```go
// Automatic in NewAuthenticatedMessage
authMsg, err := crypto.NewAuthenticatedMessage(encryptedMsg, username, sequenceID, secret)

// Verification happens automatically
isValid, err := authMsg.Verify(sharedSecret)
```

**Security benefit**: Ensures message integrity and detects any tampering during transmission.

### 4. Two-Factor Registration

**What it is**: Registration requires two separate pieces of information delivered through different channels.

**How it works**:

- Server generates a registration token and validation code
- Token shown only to admin (for out-of-band delivery)
- Validation code sent to user
- Both must be combined to register

**Usage**:

```bash
# User requests registration
./client localhost:8080
# Select option 1 to get validation code

# Admin sees token in server console and provides it to user
# User combines both for registration (option 2)
```

**Security benefit**: Prevents unauthorized account creation and requires admin approval.

### 5. Password Security

**What it is**: Secure storage of authentication credentials.

**How it works**:

- Argon2id password hashing (winner of Password Hashing Competition)
- Unique salt for each user
- Configurable work factors

**Usage**:

```go
// Automatically handled during registration
hash, salt, err := auth.HashPassword(password)

// Verification during login
auth.VerifyPassword(password, user.PasswordHash, user.Salt)
```

**Security benefit**: Protects passwords against brute force attacks and rainbow tables.

## Advanced Security Features

### 6. In-Memory Database Encryption

**What it is**: Additional protection for sensitive data in the database.

**How it works**:

- In-memory SQLite database prevents disk exposure
- Sensitive fields encrypted with AES-GCM
- Encryption key discarded on server shutdown

**Usage**: Automatic during database operations.

**Security benefit**: Protects against memory dumps and prevents persistent data exposure.

### 7. Secure Channel Separation

**What it is**: Critical security information is split across different communication channels.

**How it works**:

- Token and validation code never transmitted together
- Admin sees only tokens, users see only validation codes

**Usage**: Built into the registration protocol.

**Security benefit**: Prevents complete credential theft through a single compromised channel.

## Operating Recommendations

1. **Server Security**:

   - Run in a secure environment with limited access
   - Use a proper certificate in production (not self-signed)
   - Regularly rotate cryptographic keys

2. **Client Security**:

   - Verify the first connection manually
   - Keep registration tokens secure
   - Use strong passwords

3. **Network Security**:
   - Consider running the server behind a reverse proxy
   - Implement IP filtering if appropriate
   - Monitor for unusual connection patterns

## Threat Mitigations

| Threat                    | Mitigation                      |
| ------------------------- | ------------------------------- |
| Network eavesdropping     | End-to-end encryption + TLS     |
| Message tampering         | Message authentication codes    |
| Replay attacks            | Timestamps + sequence numbers   |
| Password theft            | Argon2id hashing + unique salts |
| Unauthorized registration | Two-factor token/code system    |
| Data exposure             | In-memory DB + encryption       |

## Suggested Security Enhancements

### 1. Panic Mode

**What it is**: Emergency shutdown mechanism that securely erases sensitive data.

**How it would work**:

- Special administrator command to trigger
- Could be activated by specific key combinations or chat commands
- Immediately zeroes all sensitive memory
- Terminates all connections
- Logs the emergency event (without sensitive data)

**Implementation suggestion**:

```go
func (s *ChatServer) ActivatePanicMode(reason string) {
    // Log panic reason securely
    log.Printf("PANIC MODE ACTIVATED: %s", reason)

    // Zero out all sensitive data
    for _, secret := range s.sharedSecrets {
        crypto.SecureZeroMemory(secret)
    }

    // Notify all clients to also zero their memory
    s.broadcastServerMessage("PANIC:SHUTDOWN")

    // Close all connections
    s.Close()

    // Exit immediately
    os.Exit(1)
}
```

**Security benefit**: Provides rapid response to security breaches and minimizes data exposure.

### 2. Login Two-Factor Authentication

**What it is**: Additional verification step after password authentication.

**How it would work**:

- TOTP (Time-based One-Time Password) like Google Authenticator
- FIDO2/WebAuthn support for hardware security keys
- SMS or email verification codes

**Implementation suggestion**:

```go
// During registration
func (c *ChatClient) SetupTOTP() (string, error) {
    // Generate a secret key
    secret := generateTOTPSecret()

    // Display QR code for user to scan with authenticator app
    qrCode := generateQRCode(secret)
    fmt.Println(qrCode)

    return secret, nil
}

// During login
func (s *ChatServer) verifyTOTP(username string, password string, code string) bool {
    // First verify password
    if !verifyPassword(username, password) {
        return false
    }

    // Then verify TOTP code
    user, _ := s.database.GetUser(username)
    return validateTOTPCode(user.TOTPSecret, code)
}
```

**Security benefit**: Prevents account takeover even if passwords are compromised.

### 3. Perfect Forward Secrecy with Key Rotation

**What it is**: Automatic key regeneration at regular intervals.

**How it would work**:

- Periodically regenerate Diffie-Hellman keys
- Setup protocol for renegotiating keys during an active session
- Old keys securely discarded

**Implementation suggestion**:

```go
func (c *ChatClient) RotateKeys() error {
    // Generate new DH keys
    newDHKey, err := crypto.GenerateDHKeys()
    if err != nil {
        return err
    }

    // Signal server for key rotation
    c.SendControlMessage("KEY_ROTATION_REQUEST")

    // Exchange new public key
    // ... protocol for exchange ...

    // Zero out old keys when done
    crypto.SecureZeroMemory(c.sharedSecret)

    return nil
}
```

**Security benefit**: Limits the amount of data exposed system memory is dumped.

### 4. Tamper-Evident Logging

**What it is**: Securely log security events in a way that cannot be modified.

**How it would work**:

- Cryptographically linked log entries
- Forward-secure signing
- Distributed verification

**Security benefit**: Creates reliable audit trail for security incidents.

By implementing these additional security features, SecureChat would provide comprehensive protection against advanced threats while maintaining usability for secure communications.
