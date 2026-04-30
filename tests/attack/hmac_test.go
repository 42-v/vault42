package attack

import (
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestHMACTamper verifies that tampered messages fail HMAC verification.
func TestHMACTamper(t *testing.T) {
	key := []byte("test-hmac-secret-key-for-attack-tests")
	msg := []byte("original-message")

	sig := vaultcrypto.HMACSign(msg, key)

	// Valid message should verify
	if !vaultcrypto.HMACVerify(msg, key, sig) {
		t.Fatal("Valid HMAC signature failed verification")
	}

	// Tampered message
	tampered := []byte("tampered-message")
	if vaultcrypto.HMACVerify(tampered, key, sig) {
		t.Fatal("Tampered message passed HMAC verification")
	}

	// Tampered signature
	if vaultcrypto.HMACVerify(msg, key, "0000"+sig[4:]) {
		t.Fatal("Tampered signature passed HMAC verification")
	}

	// Wrong key
	wrongKey := []byte("different-key")
	if vaultcrypto.HMACVerify(msg, wrongKey, sig) {
		t.Fatal("Wrong key passed HMAC verification")
	}

	// Empty signature
	if vaultcrypto.HMACVerify(msg, key, "") {
		t.Fatal("Empty signature passed HMAC verification")
	}
}
