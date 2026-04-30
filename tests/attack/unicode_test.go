package attack

import (
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestUnicode_PasswordNormalization verifies that visually similar Unicode
// characters produce different password hashes (no silent normalization).
func TestUnicode_PasswordNormalization(t *testing.T) {
	// These are visually similar but different Unicode codepoints
	pairs := []struct {
		name string
		pw1  string
		pw2  string
	}{
		{
			"latin a vs cyrillic a",
			"password-with-a-here", "password-with-\u0430-here",
		}, // U+0061 vs U+0430
		{
			"latin e vs cyrillic e",
			"securevault-e-test", "securevault-\u0435-test",
		}, // U+0065 vs U+0435
		{
			"fullwidth vs ASCII",
			"test-password-123", "test-password-\uff11\uff12\uff13",
		}, // 123 vs fullwidth 123
		{
			"precomposed vs decomposed",
			"\u00e9cole-password!", "e\u0301cole-password!",
		}, // e-acute precomposed vs decomposed
	}

	for _, tt := range pairs {
		t.Run(tt.name, func(t *testing.T) {
			hash1, err := vaultcrypto.HashPassword(tt.pw1)
			if err != nil {
				t.Fatalf("HashPassword(pw1) failed: %v", err)
			}
			hash2, err := vaultcrypto.HashPassword(tt.pw2)
			if err != nil {
				t.Fatalf("HashPassword(pw2) failed: %v", err)
			}

			// pw1 should not verify against hash of pw2 (they are different bytes)
			match, _ := vaultcrypto.VerifyPassword(tt.pw1, hash2)
			if match {
				t.Fatal("Visually similar Unicode passwords should produce different hashes")
			}

			match, _ = vaultcrypto.VerifyPassword(tt.pw2, hash1)
			if match {
				t.Fatal("Visually similar Unicode passwords should produce different hashes (reverse)")
			}
		})
	}
}

// TestUnicode_ZeroWidthCharactersInPassword verifies that zero-width characters
// in passwords are not silently stripped.
func TestUnicode_ZeroWidthCharactersInPassword(t *testing.T) {
	base := "secure-vault-pass"
	withZWJ := "secure-vault-\u200dpass"  // zero-width joiner
	withZWNJ := "secure-vault-\u200cpass" // zero-width non-joiner
	withZWSP := "secure-vault-\u200bpass" // zero-width space

	baseHash, _ := vaultcrypto.HashPassword(base)

	variants := []struct {
		name string
		pw   string
	}{
		{"zero-width joiner", withZWJ},
		{"zero-width non-joiner", withZWNJ},
		{"zero-width space", withZWSP},
	}

	for _, tt := range variants {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := vaultcrypto.VerifyPassword(tt.pw, baseHash)
			if match {
				t.Fatalf("Password with %s should not match password without it", tt.name)
			}
		})
	}
}

// TestUnicode_FingerprintWithUnicodeComponents verifies fingerprints handle Unicode.
func TestUnicode_FingerprintWithUnicodeComponents(t *testing.T) {
	fp1 := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "Mozilla/5.0 (\u00e9cole)",
		AcceptLanguage: "fr-FR",
	})

	fp2 := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "Mozilla/5.0 (e\u0301cole)", // decomposed form
		AcceptLanguage: "fr-FR",
	})

	// These should produce DIFFERENT fingerprints (no normalization)
	if vaultcrypto.CompareFingerprints(fp1, fp2) {
		t.Fatal("Different Unicode normalization forms should produce different fingerprints")
	}
}

// TestUnicode_HMACWithUnicodeMessages verifies HMAC handles Unicode correctly.
func TestUnicode_HMACWithUnicodeMessages(t *testing.T) {
	key := []byte("hmac-key-for-unicode-test-32bytes")
	msg := []byte("message-with-\u00e9-precomposed")

	sig := vaultcrypto.HMACSign(msg, key)
	if !vaultcrypto.HMACVerify(msg, key, sig) {
		t.Fatal("HMAC should verify for Unicode message")
	}

	// Different normalization form should not verify
	msgDecomposed := []byte("message-with-e\u0301-decomposed")
	if vaultcrypto.HMACVerify(msgDecomposed, key, sig) {
		t.Fatal("HMAC with different Unicode normalization should not verify")
	}
}

// TestUnicode_SHA256DifferentNormalization verifies SHA256 distinguishes
// different Unicode normalization forms.
func TestUnicode_SHA256DifferentNormalization(t *testing.T) {
	hash1 := vaultcrypto.SHA256Hex("\u00e9")  // precomposed e-acute
	hash2 := vaultcrypto.SHA256Hex("e\u0301") // decomposed e + combining acute

	if hash1 == hash2 {
		t.Fatal("SHA256 should produce different hashes for different byte sequences")
	}
}
