package attack

import (
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

// TestSecureCompareBytes verifies constant-time byte comparison.
func TestSecureCompareBytes(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02, 0x03}
	c := []byte{0x01, 0x02, 0x04}
	d := []byte{0x01, 0x02}

	if !vaultcrypto.SecureCompareBytes(a, b) {
		t.Error("Equal byte slices should match")
	}
	if vaultcrypto.SecureCompareBytes(a, c) {
		t.Error("Different byte slices should not match")
	}
	if vaultcrypto.SecureCompareBytes(a, d) {
		t.Error("Different length byte slices should not match")
	}
}
