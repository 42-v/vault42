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
//
// PKCS#1 v1.5 is not a fallback for RSASSA-PSS here: RFC 7518 §3.3 defines the
// RS256 JWS algorithm as RSASSA-PKCS1-v1_5 with SHA-256, so a token labeled
// RS256 must use it or no standard verifier will accept it. PSS has its own
// JWS identifiers (PS256 and up), which this package does not implement.
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
