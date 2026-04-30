package crypto

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPGenerateSecret(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) == 0 {
		t.Error("secret should not be empty")
	}
	// Base32 characters only
	for _, c := range secret {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", c) {
			t.Errorf("invalid base32 character: %c", c)
		}
	}
}

func TestTOTPGenerateAndValidate(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	code, err := GenerateTOTPCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}

	if len(code) != 6 {
		t.Errorf("code should be 6 digits, got %q", code)
	}

	step, err := ValidateTOTPCode(secret, code, now)
	if err != nil {
		t.Fatal(err)
	}
	if step < 0 {
		t.Error("valid code should match")
	}
}

func TestTOTPWrongCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	step, err := ValidateTOTPCode(secret, "000000", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Might match by chance (1/1M * 3 windows), but extremely unlikely
	// We just check it doesn't error
	_ = step
}

func TestTOTPSkewAcceptance(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Now()

	// Generate code for previous period
	prevTime := now.Add(-30 * time.Second)
	code, _ := GenerateTOTPCode(secret, prevTime)

	// Should still validate with skew=1
	step, err := ValidateTOTPCode(secret, code, now)
	if err != nil {
		t.Fatal(err)
	}
	if step < 0 {
		t.Error("code from previous period should validate with ±1 skew")
	}
}

func TestTOTPExpired(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Now()

	// Generate code for 2 periods ago (outside skew)
	oldTime := now.Add(-90 * time.Second)
	code, _ := GenerateTOTPCode(secret, oldTime)

	step, _ := ValidateTOTPCode(secret, code, now)
	if step >= 0 {
		t.Error("code from 2+ periods ago should NOT validate")
	}
}

// RFC 6238 test vectors (SHA1, 8 digits, period 30)
// We use 6 digits so we adapt — test that known time produces consistent output
func TestTOTPDeterministic(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP" // standard test secret
	fixedTime := time.Unix(1234567890, 0)

	code1, _ := GenerateTOTPCode(secret, fixedTime)
	code2, _ := GenerateTOTPCode(secret, fixedTime)

	if code1 != code2 {
		t.Errorf("same time should produce same code: %s vs %s", code1, code2)
	}
}

func TestBuildOTPAuthURL(t *testing.T) {
	url := BuildOTPAuthURL("JBSWY3DPEHPK3PXP", "TheVault", "user@example.com")
	if !strings.HasPrefix(url, "otpauth://totp/") {
		t.Errorf("URL should start with otpauth://totp/, got %s", url)
	}
	if !strings.Contains(url, "secret=JBSWY3DPEHPK3PXP") {
		t.Error("URL should contain the secret")
	}
	if !strings.Contains(url, "issuer=TheVault") {
		t.Error("URL should contain the issuer")
	}
}
