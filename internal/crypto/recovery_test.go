package crypto

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestEncryptRecoveryRoundTrip(t *testing.T) {
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	plaintext := []byte(`{"email":"user@example.com","roles":["user"]}`)

	blob, err := EncryptRecovery(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(blob, plaintext) {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := DecryptRecovery(priv, blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestDecryptRecoveryWrongKeyFails(t *testing.T) {
	priv1, _ := GenerateRSAKeyPair()
	priv2, _ := GenerateRSAKeyPair()

	blob, err := EncryptRecovery(&priv1.PublicKey, []byte("user@example.com"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := DecryptRecovery(priv2, blob); err == nil {
		t.Fatal("expected decryption with a different key to fail")
	}
}

func TestLoadRSAPublicAndPrivateKeyPEM(t *testing.T) {
	priv, _ := GenerateRSAKeyPair()

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustPKCS8(t, priv),
	})
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: mustPKIX(t, &priv.PublicKey),
	})

	loadedPub, err := LoadRSAPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("load public: %v", err)
	}
	loadedPriv, err := LoadRSAPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("load private: %v", err)
	}

	// End-to-end through the parsed keys.
	blob, err := EncryptRecovery(loadedPub, []byte("user@example.com"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := DecryptRecovery(loadedPriv, blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != "user@example.com" {
		t.Fatalf("got %q", got)
	}
}

func mustPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return b
}

func mustPKIX(t *testing.T, k *rsa.PublicKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return b
}
