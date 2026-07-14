package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"testing"
)

// The recovery blob is the only copy of an erased account's details, and it is
// decrypted offline by cmd/recover against operator-supplied input. Every reject
// path therefore has to fail cleanly rather than panic or index out of range —
// these inputs are exactly what a corrupted or truncated escrow file looks like.

func TestEncryptRecovery_NilPublicKey(t *testing.T) {
	if _, err := EncryptRecovery(nil, []byte("payload")); err == nil {
		t.Error("expected an error for a nil public key")
	}
}

func TestDecryptRecovery_NilPrivateKey(t *testing.T) {
	if _, err := DecryptRecovery(nil, []byte("blob")); err == nil {
		t.Error("expected an error for a nil private key")
	}
}

// Shorter than the 4-byte length prefix: reading the prefix at all would slice
// out of bounds.
func TestDecryptRecovery_BlobTooShort(t *testing.T) {
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, err := DecryptRecovery(priv, []byte{0x00, 0x01}); err == nil {
		t.Error("expected an error for a blob shorter than the length prefix")
	}
}

// A length prefix larger than the blob itself is the classic corrupt-header case:
// trusting it would slice past the end of the buffer.
func TestDecryptRecovery_CorruptWrappedKeyLength(t *testing.T) {
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	blob := make([]byte, 8)
	binary.BigEndian.PutUint32(blob[:4], 0xFFFFFFFF) // claims a huge wrapped key
	if _, err := DecryptRecovery(priv, blob); err == nil {
		t.Error("expected an error for a wrapped-key length past the end of the blob")
	}
}

// Header and wrapped key are intact, but the AES payload has been tampered with:
// GCM must reject it rather than return garbage plaintext.
func TestDecryptRecovery_TamperedAESPayload(t *testing.T) {
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	blob, err := EncryptRecovery(&priv.PublicKey, []byte("erased account payload"))
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}

	// Flip a byte in the trailing AES ciphertext, leaving the RSA-wrapped key and
	// the length prefix untouched.
	tampered := make([]byte, len(blob))
	copy(tampered, blob)
	tampered[len(tampered)-1] ^= 0xFF

	if _, err := DecryptRecovery(priv, tampered); err == nil {
		t.Error("expected GCM to reject a tampered recovery payload")
	}
}

// A structurally valid PKCS#8 key that is not RSA must be rejected by name, not
// panic on the type assertion.
func TestLoadRSAPrivateKeyPEM_NotRSA(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if _, err := LoadRSAPrivateKeyPEM(pemBytes); err == nil {
		t.Error("expected a non-RSA PKCS#8 key to be rejected")
	}
}
