package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// SignRS256Bytes signs a signing string with RS256 (PKCS1v15 + SHA-256).
// Returns the raw signature bytes.
func SignRS256Bytes(signingString string, key *rsa.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil private key", ErrInvalidKeyType)
	}
	hash := sha256.Sum256([]byte(signingString))
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
}

// VerifyRS256 verifies an RS256 signature. Returns nil on success.
func VerifyRS256(signingString string, sig []byte, key *rsa.PublicKey) error {
	if key == nil {
		return fmt.Errorf("%w: nil public key", ErrInvalidKeyType)
	}
	hash := sha256.Sum256([]byte(signingString))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig)
}
