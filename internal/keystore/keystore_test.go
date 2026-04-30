package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Generate a test key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Marshal to PEM
	privPEM, err := vaultcrypto.MarshalSigningKeyPEM(key)
	if err != nil {
		t.Fatalf("marshal PEM: %v", err)
	}

	// Encrypt with a test master key and kid as AAD
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("generate master key: %v", err)
	}

	kid := vaultcrypto.KIDFromPublicKey(&key.PublicKey)

	encrypted, err := vaultcrypto.Encrypt(privPEM, masterKey, []byte(kid))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Decrypt
	decrypted, err := vaultcrypto.Decrypt(encrypted, masterKey, []byte(kid))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	// Verify round-trip
	loadedKey, loadedKID, err := vaultcrypto.LoadSigningKeyPEM(decrypted)
	if err != nil {
		t.Fatalf("load PEM: %v", err)
	}

	if loadedKID != kid {
		t.Errorf("kid mismatch: got %s, want %s", loadedKID, kid)
	}

	if !key.Equal(loadedKey) {
		t.Error("private key mismatch after round-trip")
	}
}

func TestEncryptDecryptAADMismatch(t *testing.T) {
	privPEM := []byte("test data")
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("generate master key: %v", err)
	}

	// Encrypt with kid1 as AAD
	encrypted, err := vaultcrypto.Encrypt(privPEM, masterKey, []byte("kid-1"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Decrypt with different AAD — must fail
	_, err = vaultcrypto.Decrypt(encrypted, masterKey, []byte("kid-2"))
	if err == nil {
		t.Error("expected decrypt to fail with mismatched AAD")
	}
}

func TestKIDDeterminism(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	kid1 := vaultcrypto.KIDFromPublicKey(&key.PublicKey)
	kid2 := vaultcrypto.KIDFromPublicKey(&key.PublicKey)

	if kid1 != kid2 {
		t.Errorf("KID is not deterministic: %s != %s", kid1, kid2)
	}

	// Different key must have different KID
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key2: %v", err)
	}
	kid3 := vaultcrypto.KIDFromPublicKey(&key2.PublicKey)
	if kid1 == kid3 {
		t.Error("different keys produced same KID")
	}
}

func TestPublicKeyMarshalRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Marshal public key to DER (same format as stored in DB)
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	// Parse it back
	parsed, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatal("parsed key is not RSA")
	}

	if !key.PublicKey.Equal(rsaPub) {
		t.Error("public key mismatch after round-trip")
	}
}

func TestKeyInfoFields(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Hour)
	ki := KeyInfo{
		KID:       "test-kid",
		Algorithm: "RS256",
		Status:    "active",
		CreatedAt: now,
		RetiredAt: nil,
		ExpiresAt: &later,
	}

	if ki.KID != "test-kid" {
		t.Errorf("unexpected KID: %s", ki.KID)
	}
	if ki.Status != "active" {
		t.Errorf("unexpected status: %s", ki.Status)
	}
	if ki.ExpiresAt == nil || !ki.ExpiresAt.Equal(later) {
		t.Errorf("unexpected expires_at")
	}
}
