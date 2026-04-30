package crypto

import "testing"

func TestComputeFingerprint(t *testing.T) {
	input := FingerprintInput{
		IP:             "192.168.1.1",
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-US",
		TLSFingerprint: "abc123",
	}

	fp := ComputeFingerprint(input)
	if len(fp) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("fingerprint should be 64 hex chars, got %d", len(fp))
	}

	// Same input → same output
	fp2 := ComputeFingerprint(input)
	if fp != fp2 {
		t.Error("same input should produce same fingerprint")
	}

	// Different input → different output
	input.IP = "10.0.0.1"
	fp3 := ComputeFingerprint(input)
	if fp == fp3 {
		t.Error("different IP should produce different fingerprint")
	}
}

func TestCompareFingerprints(t *testing.T) {
	a := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	b := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	if !CompareFingerprints(a, b) {
		t.Error("same fingerprints should match")
	}

	c := "1111111111111111111111111111111111111111111111111111111111111111"
	if CompareFingerprints(a, c) {
		t.Error("different fingerprints should not match")
	}
}
