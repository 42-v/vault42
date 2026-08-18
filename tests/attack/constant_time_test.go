package attack

import (
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestSecureCompare verifies constant-time comparison.
func TestSecureCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"abc", "ab", false},
		{"", "", true},
		{"a", "", false},
		{"long-string-here", "long-string-here", true},
		{"long-string-here", "long-string-herX", false},
	}

	for _, tc := range tests {
		got := vaultcrypto.SecureCompare(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("SecureCompare(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// This file used to carry a byte-slice twin of the test above, exercising
// crypto.SecureCompareBytes on three literal slices. That function
// had no caller outside tests: production compares strings through SecureCompare
// and byte slices through crypto/subtle directly. The two tests below attack the
// comparison where an attacker meets it instead — through a caller — so a
// forged value of the right length is refused, and a comparison that stopped at
// the first differing byte would be caught.

// A signature forged at the right length must be refused by the comparison
// rather than by a length check, and one differing only in its last digit is the
// case a prefix comparison accepts. HMACVerify recomputes and hands both to
// SecureCompare, which is the path every HMAC in the tree takes.
func TestForgedHMACSignatureIsRefusedAtFullLength(t *testing.T) {
	key := []byte("the-signing-key")
	message := []byte("state=abc&nonce=def")
	signature := vaultcrypto.HMACSign(message, key)

	if !vaultcrypto.HMACVerify(message, key, signature) {
		t.Fatal("a signature this key produced was refused")
	}
	for _, forged := range []string{
		strings.Repeat("0", len(signature)),
		signature[:len(signature)-1] + flipHexDigit(signature[len(signature)-1]),
		flipHexDigit(signature[0]) + signature[1:],
	} {
		if vaultcrypto.HMACVerify(message, key, forged) {
			t.Errorf("a forged signature of the right length was accepted: %q", forged)
		}
	}
}

// The same property for the password hash comparison, which is the byte-slice
// one and the only place in the tree an attacker's guess is compared against a
// stored secret. VerifyPassword derives a candidate and ends in
// subtle.ConstantTimeCompare; a stored hash differing in one byte must refuse
// the password that produced the original.
func TestNearMissPasswordHashIsRefused(t *testing.T) {
	const password = "correct horse battery staple"
	encoded, err := vaultcrypto.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if ok, err := vaultcrypto.VerifyPassword(password, encoded); err != nil || !ok {
		t.Fatalf("the right password was refused (ok=%v err=%v)", ok, err)
	}

	nearMiss := encoded[:len(encoded)-1] + flipBase64Char(encoded[len(encoded)-1])
	ok, err := vaultcrypto.VerifyPassword(password, nearMiss)
	if err != nil {
		t.Fatalf("verifying against a near-miss hash errored: %v", err)
	}
	if ok {
		t.Fatal("a stored hash differing in its final byte accepted the password")
	}
}

func flipHexDigit(c byte) string {
	if c == '0' {
		return "1"
	}
	return "0"
}

func flipBase64Char(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}
