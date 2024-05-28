package config

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// createUser creates a new user in the database, with an argon2id-derived password.
func (c *Config) createUser(username, password, email string) error {
	// Generate the hashed password
	hashedPassword, err := generateHashedPassword(password)
	if err != nil {
		return fmt.Errorf("unable to generate hashed password: %v", err)
	}

	// Create the user in the database
	sqlInsert := "INSERT INTO users (username, password, email) VALUES ($1, $2, $3);"
	_, err = c.dbConnPool.Exec(context.Background(), sqlInsert, username, hashedPassword, email)
	if err != nil {
		return fmt.Errorf("unable to create user: %v", err)
	}

	return nil
}

// createAdminUser creates a new admin user in the database, with an argon2id-derived password.
func (c *Config) createAdminUser(username, password, email string) error {
	// Generate the hashed password
	hashedPassword, err := generateHashedPassword(password)
	if err != nil {
		return fmt.Errorf("unable to generate hashed password: %v", err)
	}

	// Create the user in the database
	sqlInsert := "INSERT INTO users (username, password, admin, email) VALUES ($1, $2, true, $3);"
	_, err = c.dbConnPool.Exec(context.Background(), sqlInsert, username, hashedPassword, email)
	if err != nil {
		return fmt.Errorf("unable to create user: %v", err)
	}

	return nil
}

// updateUserPassword updates the password of an existing user in the database.
func (c *Config) updateUserPassword(username, password string) error {
	// Hash the password
	hashedPassword, err := generateHashedPassword(password)
	if err != nil {
		return fmt.Errorf("unable to generate hashed password: %v", err)
	}

	// Update the user in the database
	sqlUpdate := "UPDATE users SET password = $1 WHERE username = $2;"
	_, err = c.dbConnPool.Exec(context.Background(), sqlUpdate, hashedPassword, username)
	if err != nil {
		return fmt.Errorf("unable to update user: %v", err)
	}

	return nil
}

// updateUserEmail updates the email of an existing user in the database.
func (c *Config) updateUserEmail(username, email string) error {
	// Update the user in the database
	sqlUpdate := "UPDATE users SET email = $1 WHERE username = $2;"
	_, err := c.dbConnPool.Exec(context.Background(), sqlUpdate, email, username)
	if err != nil {
		return fmt.Errorf("unable to update user: %v", err)
	}

	return nil
}

// deleteUser deletes an existing user from the database, only if there is at least one admin user left other than
// the one being deleted.
func (c *Config) deleteUser(username string) error {
	// Check if there are any other admin users
	sqlSelect := "SELECT COUNT(*) FROM users WHERE admin = true AND username != $1;"
	var count int
	err := c.dbConnPool.QueryRow(context.Background(), sqlSelect, username).Scan(&count)
	if err != nil {
		return fmt.Errorf("unable to check if there are any other admin users: %v", err)
	}

	if count == 0 {
		return fmt.Errorf("unable to delete user: there must be at least one admin user")
	}

	// Delete the user from the database
	sqlDelete := "DELETE FROM users WHERE username = $1;"
	_, err = c.dbConnPool.Exec(context.Background(), sqlDelete, username)
	if err != nil {
		return fmt.Errorf("unable to delete user: %v", err)
	}

	return nil
}

// generateSalt generates a random salt of the specified length.
func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// hashPassword hashes the password with the specified salt.
func hashPassword(password string, salt []byte) string {
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return base64.RawStdEncoding.EncodeToString(key)
}

// generateHashedPassword generates a hashed password with a random salt.
func generateHashedPassword(password string) (string, error) {
	salt, err := generateSalt(16)
	if err != nil {
		return "", err
	}

	hashedPassword := hashPassword(password, salt)
	return fmt.Sprintf("%s.%s", base64.RawStdEncoding.EncodeToString(salt), hashedPassword), nil
}

// verifyPassword verifies that the password matches the hashed password.
func verifyPassword(password, hashedPassword string) (bool, error) {
	parts := strings.Split(hashedPassword, ".")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid hashed password format")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false, err
	}

	expectedHashedPassword := hashPassword(password, salt)
	return expectedHashedPassword == parts[1], nil
}
