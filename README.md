# SecureChat Security Features Guide

## Overview

SecureChat is a secure terminal-based chat application built with Go, featuring multiple layers of cryptographic protection. This document explains the key security features, how they work, and how to use them effectively.

The main use-case is to have a private and secure messaging room. However, keep in mind that anything you do online is logged, monitored, and can be used against you. This is `good-enough` privacy and security for transmitting one-time-secrets and other information. But never use this if your safety and security depend on it.

It's easier to use something like signal as a daily driver. This was built as a proof-of-concept for the Cache Tech Community relating to a series of talks regarding data and information security in GO-based applications. This application is not perfect. It is not safe. There is no warranty or guarantee of privacy and security. Use of this tool is at your own discretion and you are responsible for what you do with it.

## Core Security Features

### 1. End-to-End Encryption

**What it is**: Messages are encrypted on the sender's device and can only be decrypted by the intended recipient.

**How it works**:

- Uses Diffie-Hellman key exchange to establish a shared secret
- AES-GCM for encryption of messages
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

### 3. Two-Factor Registration

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

### 4. Password Security

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

### 5. In-Memory Database Encryption

**What it is**: Additional protection for sensitive data in the database.

**How it works**:

- In-memory SQLite database prevents disk exposure
- Sensitive fields encrypted with AES-GCM
- Encryption key discarded on server shutdown

**Usage**: Automatic during database operations.

**Security benefit**: Protects against memory dumps and prevents persistent data exposure.

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
