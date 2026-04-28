# JWKS Server - Enhanced Security and User Management

## Student Information
Name: Abdul Abubakar  
EUID: aoa0169

## Overview
This project extends the JWKS server by adding stronger security and user-management features. The server stores RSA private keys in SQLite, encrypts private keys before saving them, exposes a JWKS endpoint, issues signed JWTs from `/auth`, supports user registration through `/register`, and logs successful authentication requests.

## Implemented Requirements
- AES encryption for private keys stored in the database
- Encryption key loaded from the `NOT_MY_KEY` environment variable
- `users` table with username, email, Argon2 password hash, registration date, and last login
- `POST /register` endpoint that generates a UUIDv4 password and returns it to the user
- Argon2id password hashing for registered users
- `auth_logs` table for successful authentication requests
- Successful `/auth` requests log request IP, timestamp, and user ID when available
- Optional time-window rate limiter on `/auth` set to 10 requests per second
- Existing JWKS behavior preserved for Gradebot compatibility

## Environment Setup
Create a `.env` file or set the environment variable manually before running the server.

Example:

```bash
export NOT_MY_KEY="replace-this-with-a-strong-secret-key"
```

A sample file is included as `.env.example`. Do not commit your real `.env` file.

## How to Run

```bash
go mod tidy
go run main.go
```

The server listens on:

```text
http://localhost:8080
```

## Endpoints

### GET `/.well-known/jwks.json`
Returns the public JWKS for valid, non-expired signing keys.

### POST `/register`
Registers a new user.

Request body:

```json
{
  "username": "MyCoolUsername",
  "email": "MyCoolEmail@example.com"
}
```

Successful response:

```json
{
  "password": "generated-uuid-v4-password"
}
```

### POST `/auth`
Authenticates a request and returns a JWT signed with an RSA private key. Registered users can authenticate with JSON credentials.

Example:

```json
{
  "username": "MyCoolUsername",
  "password": "generated-uuid-v4-password"
}
```

The endpoint also supports the original Basic Auth behavior for compatibility with the previous Gradebot tests.

### POST `/auth?expired=true`
Returns a JWT signed with an expired key for testing expired-token behavior.

## Database Schema

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    iv BLOB NOT NULL,
    exp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
```

## Testing

Run tests with:

```bash
export NOT_MY_KEY="test-secret-key-for-aes-encryption"
go test ./...
```

Run coverage with:

```bash
export NOT_MY_KEY="test-secret-key-for-aes-encryption"
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

## Screenshots
Screenshots are stored in the `screenshots/` folder:

- `screenshots/test-client.png`
- `screenshots/test coverage.png`

## Security Notes
- The real encryption key must be supplied through `NOT_MY_KEY`.
- Never commit `.env` or real secrets.
- Private keys are encrypted before they are inserted into SQLite.
- Passwords are not stored directly; only Argon2id hashes are saved.



