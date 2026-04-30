package crypto

import "testing"

func TestFingerprintSeparatorCollisionPrevented(t *testing.T) {
	// With the old pipe-separated approach, these two inputs would produce
	// the same fingerprint. With length-prefixed encoding, they should differ.
	fp1 := ComputeFingerprint(FingerprintInput{
		IP:             "192.168.1.1",
		UserAgent:      "Mozilla|5.0",
		AcceptLanguage: "en",
		TLSFingerprint: "",
	})
	fp2 := ComputeFingerprint(FingerprintInput{
		IP:             "192.168.1.1",
		UserAgent:      "Mozilla",
		AcceptLanguage: "5.0|en",
		TLSFingerprint: "",
	})
	if fp1 == fp2 {
		t.Error("fingerprints should differ when field boundaries are different (separator collision)")
	}
}

func TestFingerprintEmptyFields(t *testing.T) {
	// All empty fields should still produce a valid hash
	fp := ComputeFingerprint(FingerprintInput{})
	if len(fp) != 64 {
		t.Errorf("empty input fingerprint should be 64 hex chars, got %d", len(fp))
	}

	// Empty vs non-empty should differ
	fp2 := ComputeFingerprint(FingerprintInput{IP: "1.2.3.4"})
	if fp == fp2 {
		t.Error("empty input should differ from non-empty")
	}
}

func TestFingerprintFieldOrderMatters(t *testing.T) {
	// Swapping values between fields should produce different fingerprints
	fp1 := ComputeFingerprint(FingerprintInput{
		IP:        "valueA",
		UserAgent: "valueB",
	})
	fp2 := ComputeFingerprint(FingerprintInput{
		IP:        "valueB",
		UserAgent: "valueA",
	})
	if fp1 == fp2 {
		t.Error("swapping field values should produce different fingerprints")
	}
}

func TestFingerprintLengthPrefixedEncoding(t *testing.T) {
	// These should differ due to length prefix: "ab" + "c" vs "a" + "bc"
	fp1 := ComputeFingerprint(FingerprintInput{
		IP:             "ab",
		UserAgent:      "c",
		AcceptLanguage: "",
		TLSFingerprint: "",
	})
	fp2 := ComputeFingerprint(FingerprintInput{
		IP:             "a",
		UserAgent:      "bc",
		AcceptLanguage: "",
		TLSFingerprint: "",
	})
	if fp1 == fp2 {
		t.Error("length-prefixed encoding should prevent cross-field collisions")
	}
}
