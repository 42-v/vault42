package crypto

import (
	"bytes"
	"testing"
)

func TestAESRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("top secret data that must be protected")

	ct, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	// Ciphertext should be different from plaintext
	if bytes.Equal(ct, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	pt, err := Decrypt(ct, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Errorf("decrypted = %q, want %q", pt, plaintext)
	}
}

func TestAESWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 0xFF

	ct, err := Encrypt([]byte("secret"), key1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(ct, key2)
	if err == nil {
		t.Error("decryption with wrong key should fail")
	}
}

func TestAESInvalidKeyLength(t *testing.T) {
	_, err := Encrypt([]byte("data"), make([]byte, 16))
	if err == nil {
		t.Error("16-byte key should be rejected (need 32)")
	}

	_, err = Decrypt([]byte("data"), make([]byte, 16))
	if err == nil {
		t.Error("16-byte key should be rejected for decrypt")
	}
}

func TestAESTruncatedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_, err := Decrypt([]byte("short"), key)
	if err == nil {
		t.Error("truncated ciphertext should fail")
	}
}

func TestAESDifferentNonces(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("same input")

	ct1, _ := Encrypt(plaintext, key)
	ct2, _ := Encrypt(plaintext, key)

	if bytes.Equal(ct1, ct2) {
		t.Error("same plaintext should produce different ciphertext (random nonce)")
	}
}

func TestAESEmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	ct, err := Encrypt([]byte{}, key)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(ct, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Error("empty plaintext should round-trip")
	}
}
