package crypto

import (
	"bytes"
	"testing"
)

// AES-256-GCM takes a 32-byte key and nothing else. A key of the wrong length must be
// refused at the door rather than silently truncated or padded into something that
// "works": the master key protects the JWT signing keys, the TOTP secrets and the
// identity blobs, and a mis-sized key that encrypted anyway would produce ciphertext
// nobody could ever decrypt again — or, far worse, ciphertext under a key the operator
// did not choose.
func TestEncryptDecrypt_RejectKeysThatAreNotAES256(t *testing.T) {
	plaintext := []byte("the quick brown fox")

	for _, n := range []int{0, 1, 15, 16, 24, 31, 33, 64} {
		key := bytes.Repeat([]byte{0x42}, n)

		if _, err := Encrypt(plaintext, key); err == nil {
			t.Errorf("Encrypt accepted a %d-byte key", n)
		}
		if _, err := Decrypt([]byte("irrelevant-ciphertext"), key); err == nil {
			t.Errorf("Decrypt accepted a %d-byte key", n)
		}
	}
}

// A 32-byte key round-trips, and the AAD is bound: ciphertext encrypted with one AAD must
// not decrypt under another. That binding is what stops a TOTP secret being lifted out of
// one admin's row and dropped into another's.
func TestEncryptDecrypt_AADIsBound(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("totp-secret")

	enc, err := Encrypt(plaintext, key, []byte("admin-1"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(enc, key, []byte("admin-1"))
	if err != nil {
		t.Fatalf("Decrypt with the right AAD failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: %q", got)
	}

	if _, err := Decrypt(enc, key, []byte("admin-2")); err == nil {
		t.Error("ciphertext bound to admin-1 decrypted under admin-2 — a row swap would go undetected")
	}
}
