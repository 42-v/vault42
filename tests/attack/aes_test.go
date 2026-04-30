package attack

import (
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestAESWrongKey verifies that decryption with wrong key fails.
func TestAESWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key1[0] = 0x01
	key2[0] = 0x02

	plaintext := []byte("secret-totp-key-base32")
	encrypted, err := vaultcrypto.Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = vaultcrypto.Decrypt(encrypted, key2)
	if err == nil {
		t.Fatal("Decryption with wrong key should fail")
	}
}

// TestAESTruncatedCiphertext verifies that truncated ciphertext is rejected.
func TestAESTruncatedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("test-data")
	encrypted, _ := vaultcrypto.Encrypt(plaintext, key)

	truncations := []int{0, 1, 5, 12} // nonce is 12 bytes
	for _, n := range truncations {
		if n > len(encrypted) {
			continue
		}
		_, err := vaultcrypto.Decrypt(encrypted[:n], key)
		if err == nil {
			t.Fatalf("Truncated ciphertext (len=%d) should fail", n)
		}
	}
}

// TestAESTamperedCiphertext verifies that tampered ciphertext is rejected.
func TestAESTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("test-data")
	encrypted, _ := vaultcrypto.Encrypt(plaintext, key)

	// Flip a bit in the middle
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)/2] ^= 0xFF

	_, err := vaultcrypto.Decrypt(tampered, key)
	if err == nil {
		t.Fatal("Tampered ciphertext should fail authentication")
	}
}
