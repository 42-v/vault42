// Package crypto provides cryptographic primitives for the Vault auth service,
// including AES-256-GCM encryption, Argon2id password hashing, HMAC-SHA256,
// RS256 JWT signing and validation, TOTP, DPoP proof verification, device
// fingerprinting, and secure random generation.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Key must be exactly 32 bytes. Returns nonce || ciphertext.
// Optional aad (Additional Authenticated Data) binds the ciphertext to a context
// (e.g., user ID or record ID) so it cannot be swapped between owners.
func Encrypt(plaintext, key []byte, aad ...[]byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("aes: key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes: new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("aes: generate nonce: %w", err)
	}

	var ad []byte
	if len(aad) > 0 {
		ad = aad[0]
	}

	return gcm.Seal(nonce, nonce, plaintext, ad), nil
}

// Decrypt decrypts AES-256-GCM ciphertext (nonce || ciphertext).
// Key must be exactly 32 bytes.
// Optional aad must match the value used during encryption.
func Decrypt(ciphertext, key []byte, aad ...[]byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("aes: key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes: new gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) <= nonceSize {
		return nil, errors.New("aes: ciphertext too short")
	}

	var ad []byte
	if len(aad) > 0 {
		ad = aad[0]
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, ad)
	if err != nil {
		return nil, fmt.Errorf("aes: decrypt: %w", err)
	}

	return plaintext, nil
}
