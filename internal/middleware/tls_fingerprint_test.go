package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestTLSFingerprintEmpty(t *testing.T) {
	// No header configured — should return empty
	SetTLSFingerprintHeader("")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-TLS-Fingerprint", "ja4_value")

	if got := TLSFingerprint(req); got != "" {
		t.Errorf("TLSFingerprint() = %q, want empty (no header configured)", got)
	}
}

func TestTLSFingerprintConfigured(t *testing.T) {
	SetTLSFingerprintHeader("X-TLS-Fingerprint")
	defer SetTLSFingerprintHeader("") // cleanup

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-TLS-Fingerprint", "t13d1516h2_8daaf6152771_b0da82dd1658")

	got := TLSFingerprint(req)
	if got != "t13d1516h2_8daaf6152771_b0da82dd1658" {
		t.Errorf("TLSFingerprint() = %q, want JA4 value", got)
	}
}

func TestTLSFingerprintMissingHeader(t *testing.T) {
	SetTLSFingerprintHeader("X-TLS-Fingerprint")
	defer SetTLSFingerprintHeader("")

	// Request without the header
	req := httptest.NewRequest("GET", "/", nil)

	if got := TLSFingerprint(req); got != "" {
		t.Errorf("TLSFingerprint() = %q, want empty (header not in request)", got)
	}
}

func TestTLSFingerprintTrimmed(t *testing.T) {
	SetTLSFingerprintHeader("X-TLS-Fingerprint")
	defer SetTLSFingerprintHeader("")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-TLS-Fingerprint", "  ja4_value  ")

	got := TLSFingerprint(req)
	if got != "ja4_value" {
		t.Errorf("TLSFingerprint() = %q, want trimmed value", got)
	}
}

func TestSetTLSFingerprintHeaderOverwrites(t *testing.T) {
	SetTLSFingerprintHeader("X-Old-Header")
	SetTLSFingerprintHeader("X-New-Header")
	defer SetTLSFingerprintHeader("")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Old-Header", "old_value")
	req.Header.Set("X-New-Header", "new_value")

	got := TLSFingerprint(req)
	if got != "new_value" {
		t.Errorf("TLSFingerprint() = %q, want new_value (latest header name)", got)
	}
}
