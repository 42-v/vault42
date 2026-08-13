package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

// The recovery blob is the only copy of an erased account's details, and it is
// decrypted offline by cmd/recover against operator-supplied input. Every reject
// path therefore has to fail cleanly rather than panic or index out of range —
// these inputs are exactly what a corrupted or truncated escrow file looks like.

// errorsBinding is the row context these fixtures are sealed to. Its value does
// not matter to any assertion below; what matters is that it is the same on both
// sides, so every failure these tests observe is the one they name and not a
// binding mismatch.
var errorsBinding = RecoveryBinding("11111111-2222-4333-8444-555555555555", "pseudonym-a")

func TestEncryptRecovery_NilPublicKey(t *testing.T) {
	if _, err := EncryptRecovery(nil, []byte("payload"), errorsBinding); err == nil {
		t.Error("expected an error for a nil public key")
	}
}

func TestDecryptRecovery_NilPrivateKey(t *testing.T) {
	if _, err := DecryptRecovery(nil, []byte("blob"), errorsBinding); err == nil {
		t.Error("expected an error for a nil private key")
	}
	if _, err := DecryptRecoveryLegacy(nil, []byte("blob")); err == nil {
		t.Error("expected an error for a nil private key on the legacy path")
	}
}

// Shorter than the 4-byte length prefix: reading the prefix at all would slice
// out of bounds.
func TestDecryptRecovery_BlobTooShort(t *testing.T) {
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, err := DecryptRecovery(priv, []byte{0x00, 0x01}, errorsBinding); err == nil {
		t.Error("expected an error for a blob shorter than the length prefix")
	}
	if _, err := DecryptRecoveryLegacy(priv, []byte{0x00, 0x01}); err == nil {
		t.Error("expected an error for a legacy blob shorter than the length prefix")
	}
}

// A length prefix larger than the blob itself is the classic corrupt-header case:
// trusting it would slice past the end of the buffer.
func TestDecryptRecovery_CorruptWrappedKeyLength(t *testing.T) {
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// Built in the bound framing, so the guard under test is reached rather than
	// the format check in front of it.
	blob := append([]byte(recoveryMagic), recoveryVersionBound, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(blob[recoveryHeaderLen:], 0xFFFFFFFF) // claims a huge wrapped key
	if _, err := DecryptRecovery(priv, blob, errorsBinding); err == nil {
		t.Error("expected an error for a wrapped-key length past the end of the blob")
	}

	legacy := make([]byte, 8)
	binary.BigEndian.PutUint32(legacy[:4], 0xFFFFFFFF)
	if _, err := DecryptRecoveryLegacy(priv, legacy); err == nil {
		t.Error("expected the same guard on the legacy path")
	}
}

// Header and wrapped key are intact, but the AES payload has been tampered with:
// GCM must reject it rather than return garbage plaintext.
func TestDecryptRecovery_TamperedAESPayload(t *testing.T) {
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	blob, err := EncryptRecovery(&priv.PublicKey, []byte("erased account payload"), errorsBinding)
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}

	// Flip a byte in the trailing AES ciphertext, leaving the RSA-wrapped key and
	// the length prefix untouched.
	tampered := make([]byte, len(blob))
	copy(tampered, blob)
	tampered[len(tampered)-1] ^= 0xFF

	if _, err := DecryptRecovery(priv, tampered, errorsBinding); err == nil {
		t.Error("expected GCM to reject a tampered recovery payload")
	}
}

// An undersized recovery public key must fail at the RSA-OAEP wrap: Go rejects
// sub-1024-bit moduli outright, and even a permissive build could not fit the
// wrapped AES key into 64 bytes. Either way, no escrow blob may be produced.
func TestEncryptRecovery_UndersizedPublicKey(t *testing.T) {
	n := new(big.Int).Lsh(big.NewInt(1), 512)
	n.Sub(n, big.NewInt(1)) // 2^512 - 1: an odd 512-bit modulus
	pub := &rsa.PublicKey{N: n, E: 65537}

	if _, err := EncryptRecovery(pub, []byte("payload"), errorsBinding); err == nil {
		t.Error("expected an error for a 512-bit recovery key")
	} else if !strings.Contains(err.Error(), "wrap aes key") {
		t.Errorf("error = %v, want wrap aes key", err)
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
