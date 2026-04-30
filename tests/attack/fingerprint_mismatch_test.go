package attack

import (
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestFingerprintMismatch verifies that different fingerprints don't match.
func TestFingerprintMismatch(t *testing.T) {
	fp1 := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-US",
	})

	// Different IP
	fp2 := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "5.6.7.8",
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-US",
	})

	if vaultcrypto.CompareFingerprints(fp1, fp2) {
		t.Fatal("Different IPs should produce different fingerprints")
	}

	// Different User-Agent
	fp3 := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "Evil-Bot/1.0",
		AcceptLanguage: "en-US",
	})

	if vaultcrypto.CompareFingerprints(fp1, fp3) {
		t.Fatal("Different User-Agents should produce different fingerprints")
	}

	// Same inputs should match
	fp4 := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-US",
	})

	if !vaultcrypto.CompareFingerprints(fp1, fp4) {
		t.Fatal("Same inputs should produce matching fingerprints")
	}
}

// TestFingerprintConstantTime verifies fingerprint comparison is constant-time.
func TestFingerprintConstantTime(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:        "1.2.3.4",
		UserAgent: "Mozilla/5.0",
	})

	// Completely different
	if vaultcrypto.CompareFingerprints(fp, "0000000000000000000000000000000000000000000000000000000000000000") {
		t.Fatal("Should not match zero hash")
	}

	// Partial match (same prefix)
	if vaultcrypto.CompareFingerprints(fp, fp[:32]+"0000000000000000000000000000000000000000") {
		t.Fatal("Partial match should not pass")
	}
}
