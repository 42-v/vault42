package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// RandomBytes returns n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}
	return b, nil
}

// RandomHex returns a hex-encoded string of n random bytes (2n hex chars).
func RandomHex(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandomUUID generates a v4 UUID from crypto/rand.
func RandomUUID() (string, error) {
	b, err := RandomBytes(16)
	if err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// RandomToken generates a URL-safe token of n random bytes, hex-encoded.
func RandomToken(n int) (string, error) {
	return RandomHex(n)
}
