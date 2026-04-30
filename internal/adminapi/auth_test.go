package adminapi

import (
	"encoding/hex"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

func TestHashSessionToken_Deterministic(t *testing.T) {
	token := "test-session-token-abc123"
	h1 := hashSessionToken(token)
	h2 := hashSessionToken(token)
	if h1 != h2 {
		t.Errorf("hash should be deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("hash length = %d, want 64", len(h1))
	}
}

func TestHashSessionToken_DifferentTokensDifferentHashes(t *testing.T) {
	h1 := hashSessionToken("token-a")
	h2 := hashSessionToken("token-b")
	if h1 == h2 {
		t.Error("different tokens should produce different hashes")
	}
}

func TestEncryptDecryptTOTPSecret(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	secret := "JBSWY3DPEHPK3PXP"
	const adminID = "00000000-0000-0000-0000-000000000001"
	enc, err := encryptTOTPSecret(secret, key, adminID)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	dec, err := decryptTOTPSecret(enc, key, adminID)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if dec != secret {
		t.Errorf("decrypted = %q, want %q", dec, secret)
	}
}

func TestEncryptDecryptTOTPSecret_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 0xFF

	secret := "JBSWY3DPEHPK3PXP"
	const adminID = "00000000-0000-0000-0000-000000000002"
	enc, err := encryptTOTPSecret(secret, key1, adminID)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = decryptTOTPSecret(enc, key2, adminID)
	if err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

// A-4: a TOTP ciphertext encrypted under one admin's ID must NOT decrypt
// under a different admin's ID — the AAD binding prevents the row-swap
// attack documented in the audit.
func TestEncryptDecryptTOTPSecret_AADBoundToAdminID(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	const adminA = "00000000-0000-0000-0000-00000000000A"
	const adminB = "00000000-0000-0000-0000-00000000000B"

	enc, err := encryptTOTPSecret(secret, key, adminA)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Same admin ID — must succeed.
	if dec, err := decryptTOTPSecret(enc, key, adminA); err != nil || dec != secret {
		t.Fatalf("same-admin decrypt: dec=%q err=%v", dec, err)
	}

	// Cross-admin decrypt with a non-empty differing ID — must fail.
	// (Empty adminID would invoke the legacy fallback by design; that's
	// covered by the AcceptsLegacyCiphertext test below.)
	if _, err := decryptTOTPSecret(enc, key, adminB); err == nil {
		t.Fatal("cross-admin decrypt must fail — AAD binding broken")
	}
}

// A-4: pre-A-4 ciphertexts (encrypted without AAD) must NOT decrypt under
// the new code. Pre-1.0 release; we accept the breaking change rather than
// carrying a fallback path that could mask attacks.
func TestDecryptTOTPSecret_RejectsLegacyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	const secret = "JBSWY3DPEHPK3PXP"

	rawEnc, err := vaultcrypto.Encrypt([]byte(secret), key)
	if err != nil {
		t.Fatalf("legacy encrypt: %v", err)
	}
	encHex := hex.EncodeToString(rawEnc)

	const adminID = "00000000-0000-0000-0000-000000000099"
	if _, err := decryptTOTPSecret(encHex, key, adminID); err == nil {
		t.Fatal("legacy non-AAD ciphertext must NOT decrypt under A-4 code")
	}
}
