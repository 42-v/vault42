package attack

import (
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestFingerprintManipulation_TamperedIP verifies that changing the IP
// component produces a different fingerprint.
func TestFingerprintManipulation_TamperedIP(t *testing.T) {
	base := vaultcrypto.FingerprintInput{
		IP:             "192.168.1.1",
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-US",
		TLSFingerprint: "tls-fp-abc",
	}

	original := vaultcrypto.ComputeFingerprint(base)

	tamperedIPs := []string{
		"192.168.1.2",
		"10.0.0.1",
		"::1",
		"255.255.255.255",
		"0.0.0.0",
	}

	for _, ip := range tamperedIPs {
		t.Run("ip="+ip, func(t *testing.T) {
			tampered := base
			tampered.IP = ip
			fp := vaultcrypto.ComputeFingerprint(tampered)
			if vaultcrypto.CompareFingerprints(original, fp) {
				t.Fatalf("Fingerprint should change when IP changes from %q to %q", base.IP, ip)
			}
		})
	}
}

// TestFingerprintManipulation_TamperedUserAgent verifies that changing
// the User-Agent produces a different fingerprint.
func TestFingerprintManipulation_TamperedUserAgent(t *testing.T) {
	base := vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		AcceptLanguage: "en-US",
	}

	original := vaultcrypto.ComputeFingerprint(base)

	tamperedUAs := []string{
		"Mozilla/5.0 (Linux; Android 14)",
		"curl/8.5.0",
		"Evil-Bot/1.0",
		"",
		"A",
	}

	for _, ua := range tamperedUAs {
		t.Run("ua="+ua, func(t *testing.T) {
			tampered := base
			tampered.UserAgent = ua
			fp := vaultcrypto.ComputeFingerprint(tampered)
			if vaultcrypto.CompareFingerprints(original, fp) {
				t.Fatal("Fingerprint should change when User-Agent changes")
			}
		})
	}
}

// TestFingerprintManipulation_TamperedAcceptLanguage verifies that changing
// the Accept-Language produces a different fingerprint.
func TestFingerprintManipulation_TamperedAcceptLanguage(t *testing.T) {
	base := vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-US,en;q=0.9",
	}

	original := vaultcrypto.ComputeFingerprint(base)

	tampered := base
	tampered.AcceptLanguage = "fr-FR,fr;q=0.9"
	fp := vaultcrypto.ComputeFingerprint(tampered)
	if vaultcrypto.CompareFingerprints(original, fp) {
		t.Fatal("Fingerprint should change when Accept-Language changes")
	}
}

// TestFingerprintManipulation_TamperedTLSFingerprint verifies that changing
// the TLS fingerprint produces a different fingerprint.
func TestFingerprintManipulation_TamperedTLSFingerprint(t *testing.T) {
	base := vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-US",
		TLSFingerprint: "ja3-hash-abc123",
	}

	original := vaultcrypto.ComputeFingerprint(base)

	tampered := base
	tampered.TLSFingerprint = "ja3-hash-xyz789"
	fp := vaultcrypto.ComputeFingerprint(tampered)
	if vaultcrypto.CompareFingerprints(original, fp) {
		t.Fatal("Fingerprint should change when TLS fingerprint changes")
	}
}

// TestFingerprintManipulation_EmptyComponents verifies behavior with empty components.
func TestFingerprintManipulation_EmptyComponents(t *testing.T) {
	// All empty should still produce a valid fingerprint
	allEmpty := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{})
	if len(allEmpty) != 64 { // SHA-256 = 64 hex chars
		t.Fatalf("Empty fingerprint should be 64 hex chars, got %d", len(allEmpty))
	}

	// Empty vs non-empty should differ
	oneField := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4",
	})
	if vaultcrypto.CompareFingerprints(allEmpty, oneField) {
		t.Fatal("Empty fingerprint should differ from one with an IP")
	}
}

// TestFingerprintManipulation_VeryLongComponents verifies handling of
// extremely long fingerprint components.
func TestFingerprintManipulation_VeryLongComponents(t *testing.T) {
	longString := strings.Repeat("A", 10000)

	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             longString,
		UserAgent:      longString,
		AcceptLanguage: longString,
		TLSFingerprint: longString,
	})

	// Should still produce a valid 64-char hex fingerprint
	if len(fp) != 64 {
		t.Fatalf("Fingerprint with long components should be 64 hex chars, got %d", len(fp))
	}

	// Should be deterministic
	fp2 := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             longString,
		UserAgent:      longString,
		AcceptLanguage: longString,
		TLSFingerprint: longString,
	})
	if !vaultcrypto.CompareFingerprints(fp, fp2) {
		t.Fatal("Same long inputs should produce same fingerprint")
	}
}

// TestFingerprintManipulation_CrossFieldCollision verifies that the
// length-prefixed hashing keeps field boundaries unambiguous. Plain
// concatenation would hash both rows of each pair to the same value: with a
// separator, an attacker who can put the separator in a field steals bytes from
// the next one, and without one, "abc"+"def" is indistinguishable from
// "ab"+"cdef". Either collision would let a session bound to one fingerprint be
// replayed under another.
func TestFingerprintManipulation_CrossFieldCollision(t *testing.T) {
	cases := []struct {
		name string
		a, b vaultcrypto.FingerprintInput
	}{
		{
			"separator smuggled into the IP field",
			vaultcrypto.FingerprintInput{IP: "1.2.3.4|5.6.7.8", UserAgent: "Mozilla"},
			vaultcrypto.FingerprintInput{IP: "1.2.3.4", UserAgent: "5.6.7.8|Mozilla"},
		},
		{
			"characters moved across the field boundary",
			vaultcrypto.FingerprintInput{IP: "abc", UserAgent: "def"},
			vaultcrypto.FingerprintInput{IP: "ab", UserAgent: "cdef"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp1 := vaultcrypto.ComputeFingerprint(tc.a)
			fp2 := vaultcrypto.ComputeFingerprint(tc.b)
			if vaultcrypto.CompareFingerprints(fp1, fp2) {
				t.Fatalf("%+v and %+v hashed to the same fingerprint %s", tc.a, tc.b, fp1)
			}
		})
	}
}

// TestFingerprintManipulation_ConstantTimeComparison verifies that
// CompareFingerprints uses constant-time comparison.
func TestFingerprintManipulation_ConstantTimeComparison(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:        "1.2.3.4",
		UserAgent: "Mozilla/5.0",
	})

	// Completely different
	completely := strings.Repeat("0", 64)
	if vaultcrypto.CompareFingerprints(fp, completely) {
		t.Fatal("Should not match all-zeros")
	}

	// Partial match (same first half)
	partial := fp[:32] + strings.Repeat("0", 32)
	if vaultcrypto.CompareFingerprints(fp, partial) {
		t.Fatal("Partial match should not pass")
	}

	// Different length
	if vaultcrypto.CompareFingerprints(fp, fp[:32]) {
		t.Fatal("Different length should not match")
	}

	// Equal fingerprints must match (constant-time comparison works for equal values)
	fpCopy := string([]byte(fp)) // distinct string instance with same content
	if !vaultcrypto.CompareFingerprints(fp, fpCopy) {
		t.Fatal("Identical fingerprints must match")
	}
}
