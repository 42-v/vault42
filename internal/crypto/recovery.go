package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
)

// Recovery escrow uses hybrid asymmetric encryption so the server can WRITE
// recovery records (with a public key) but cannot READ them back: only the
// holder of the offline private key can decrypt. This protects deleted users'
// emails from a compromised server or database while still allowing an operator
// to restore them from backup.
//
// Scheme:
//  1. A fresh random AES-256 key encrypts the plaintext with AES-256-GCM
//     (reusing Encrypt, which prepends a random nonce).
//  2. The AES key is wrapped with RSA-OAEP(SHA-256) under the recovery public key.
//
// Serialization (self-describing): uint32 big-endian length of the wrapped key,
// then the wrapped key, then the AES-GCM blob (nonce || ciphertext).
//
//   [ len(wrappedKey) : 4 bytes ][ wrappedKey ][ nonce || ciphertext ]

const recoveryAESKeySize = 32

// EncryptRecovery encrypts plaintext for recovery escrow under the given RSA
// public key. The returned blob can only be decrypted with the matching private
// key via DecryptRecovery.
func EncryptRecovery(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("recovery: nil public key")
	}

	aesKey := make([]byte, recoveryAESKeySize)
	// crypto/rand.Read has no error path to handle: since Go 1.24 a Reader
	// failure calls the runtime fatal handler and terminates the process
	// instead of returning ($GOROOT/src/crypto/rand/rand.go). The recoverable
	// entropy failure for this function is the GCM nonce draw inside Encrypt,
	// which goes through io.ReadFull(rand.Reader, ...) and is handled below.
	_, _ = rand.Read(aesKey)

	aesBlob, err := Encrypt(plaintext, aesKey)
	if err != nil {
		return nil, fmt.Errorf("recovery: aes encrypt: %w", err)
	}

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("recovery: wrap aes key: %w", err)
	}

	// wrappedKey is an RSA-OAEP ciphertext, bounded by the key size in bytes; the
	// guard makes the uint32 length-prefix conversion provably safe.
	if len(wrappedKey) > math.MaxUint32 {
		return nil, errors.New("recovery: wrapped key too large")
	}
	out := make([]byte, 4+len(wrappedKey)+len(aesBlob))
	binary.BigEndian.PutUint32(out[:4], uint32(len(wrappedKey))) // #nosec G115 -- bounded by the check above
	copy(out[4:], wrappedKey)
	copy(out[4+len(wrappedKey):], aesBlob)
	return out, nil
}

// DecryptRecovery is the inverse of EncryptRecovery. It is used by the offline
// recovery tool (cmd/recover), never by the running server, which holds no
// private key.
func DecryptRecovery(priv *rsa.PrivateKey, blob []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("recovery: nil private key")
	}
	if len(blob) < 4 {
		return nil, errors.New("recovery: blob too short")
	}

	wrappedLen := binary.BigEndian.Uint32(blob[:4])
	if int(wrappedLen) > len(blob)-4 {
		return nil, errors.New("recovery: corrupt blob (wrapped key length)")
	}
	wrappedKey := blob[4 : 4+wrappedLen]
	aesBlob := blob[4+wrappedLen:]

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("recovery: unwrap aes key: %w", err)
	}

	plaintext, err := Decrypt(aesBlob, aesKey)
	if err != nil {
		return nil, fmt.Errorf("recovery: aes decrypt: %w", err)
	}
	return plaintext, nil
}

// LoadRSAPublicKeyPEM parses an RSA public key from PEM data. It accepts both
// PKIX ("BEGIN PUBLIC KEY") and PKCS#1 ("BEGIN RSA PUBLIC KEY") encodings.
func LoadRSAPublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("recovery: no PEM block found in public key")
	}

	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("recovery: public key is not RSA")
		}
		return key, nil
	}

	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("recovery: parse public key: %w", err)
	}
	return key, nil
}

// LoadRSAPrivateKeyPEM parses an RSA private key from PEM data. It accepts both
// PKCS#8 ("BEGIN PRIVATE KEY") and PKCS#1 ("BEGIN RSA PRIVATE KEY") encodings.
// Used by the offline recovery tool.
func LoadRSAPrivateKeyPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("recovery: no PEM block found in private key")
	}

	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("recovery: private key is not RSA")
		}
		return key, nil
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("recovery: parse private key: %w", err)
	}
	return key, nil
}
