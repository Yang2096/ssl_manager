package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/registration"
)

// User implements the lego User interface
type User struct {
	Email        string
	Registration *registration.Resource
	key          *ecdsa.PrivateKey
}

// NewUser creates a new ACME user
func NewUser(email string) *User {
	return &User{
		Email: email,
	}
}

// GetEmail returns the user's email
func (u *User) GetEmail() string {
	return u.Email
}

// GetRegistration returns the user's registration resource
func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

// SetRegistration sets the user's registration resource
func (u *User) SetRegistration(reg *registration.Resource) {
	u.Registration = reg
}

// GetPrivateKey returns the user's private key
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// LoadOrCreateKey loads an existing key or creates a new one
func (u *User) LoadOrCreateKey(keyPath string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Try to load existing key
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("failed to decode PEM key")
		}

		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse EC private key: %w", err)
		}

		u.key = key
		return nil
	}

	// Create new key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	u.key = key

	// Save key to disk
	if err := u.SaveKey(keyPath); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	return nil
}

// SaveKey saves the private key to disk
func (u *User) SaveKey(keyPath string) error {
	if u.key == nil {
		return fmt.Errorf("no key to save")
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return err
	}

	// Marshal key to ASN.1 DER format
	keyBytes, err := x509.MarshalECPrivateKey(u.key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Encode to PEM
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	file, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, block)
}

// LoadKey loads a private key from disk
func (u *User) LoadKey(keyPath string) error {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to decode PEM key")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse EC private key: %w", err)
	}

	u.key = key
	return nil
}

// LoadAccountJSON loads account registration from JSON file
func (u *User) LoadAccountJSON(accountPath string) error {
	if _, err := os.Stat(accountPath); os.IsNotExist(err) {
		// File doesn't exist, not an error
		return nil
	}

	data, err := os.ReadFile(accountPath)
	if err != nil {
		return fmt.Errorf("failed to read account file: %w", err)
	}

	// For now, we'll just note that we have an account
	// In a full implementation, we'd deserialize the registration
	_ = data
	return nil
}

// SaveAccountJSON saves account registration to JSON file
func (u *User) SaveAccountJSON(accountPath string) error {
	if u.Registration == nil {
		return fmt.Errorf("no registration to save")
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(accountPath), 0700); err != nil {
		return err
	}

	// In a full implementation, we'd serialize the registration
	// For now, just create an empty file as a marker
	file, err := os.Create(accountPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return nil
}
