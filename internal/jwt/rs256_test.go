package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func mustGenKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestRS256_SignVerify(t *testing.T) {
	key := mustGenKey(t)
	msg := "header.payload"

	sig, err := SignRS256Bytes(msg, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := VerifyRS256(msg, sig, &key.PublicKey); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestRS256_WrongKey(t *testing.T) {
	key1 := mustGenKey(t)
	key2 := mustGenKey(t)
	msg := "header.payload"

	sig, err := SignRS256Bytes(msg, key1)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := VerifyRS256(msg, sig, &key2.PublicKey); err == nil {
		t.Fatal("expected error with wrong key, got nil")
	}
}

func TestRS256_TamperedData(t *testing.T) {
	key := mustGenKey(t)
	msg := "header.payload"

	sig, err := SignRS256Bytes(msg, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := VerifyRS256("header.TAMPERED", sig, &key.PublicKey); err == nil {
		t.Fatal("expected error with tampered data, got nil")
	}
}

func TestRS256_TamperedSignature(t *testing.T) {
	key := mustGenKey(t)
	msg := "header.payload"

	sig, err := SignRS256Bytes(msg, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Flip a bit
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xff

	if err := VerifyRS256(msg, tampered, &key.PublicKey); err == nil {
		t.Fatal("expected error with tampered signature, got nil")
	}
}

func TestRS256_NilPrivateKey(t *testing.T) {
	_, err := SignRS256Bytes("test", nil)
	if err == nil {
		t.Fatal("expected error for nil private key")
	}
}

func TestRS256_NilPublicKey(t *testing.T) {
	err := VerifyRS256("test", []byte("sig"), nil)
	if err == nil {
		t.Fatal("expected error for nil public key")
	}
}

func TestRS256_EmptyMessage(t *testing.T) {
	key := mustGenKey(t)

	sig, err := SignRS256Bytes("", key)
	if err != nil {
		t.Fatalf("sign empty: %v", err)
	}

	if err := VerifyRS256("", sig, &key.PublicKey); err != nil {
		t.Fatalf("verify empty: %v", err)
	}
}
