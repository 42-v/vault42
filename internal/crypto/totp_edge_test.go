package crypto

import (
	"strings"
	"testing"
	"time"
)

// TestTOTPEdge_BoundaryTimestamps tests TOTP generation at significant time boundaries.
func TestTOTPEdge_BoundaryTimestamps(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	boundaries := []struct {
		name string
		time time.Time
	}{
		{"unix_epoch", time.Unix(0, 0)},
		{"one_second", time.Unix(1, 0)},
		{"period_boundary_30", time.Unix(30, 0)},
		{"period_boundary_60", time.Unix(60, 0)},
		{"period_boundary_90", time.Unix(90, 0)},
		{"year_2000", time.Unix(946684800, 0)},
		{"year_2038", time.Unix(2147483647, 0)}, // Max int32
		{"year_2100", time.Unix(4102444800, 0)},
		{"large_timestamp", time.Unix(9999999999, 0)},
	}

	for _, tc := range boundaries {
		t.Run(tc.name, func(t *testing.T) {
			code, err := GenerateTOTPCode(secret, tc.time)
			if err != nil {
				t.Fatalf("GenerateTOTPCode failed at %s: %v", tc.name, err)
			}

			if len(code) != 6 {
				t.Fatalf("Code should be 6 digits at %s, got %q", tc.name, code)
			}

			for _, c := range code {
				if c < '0' || c > '9' {
					t.Fatalf("Code should be digits only at %s, got %q", tc.name, code)
				}
			}

			// Code should validate at the same time
			step, err := ValidateTOTPCode(secret, code, tc.time)
			if err != nil {
				t.Fatalf("ValidateTOTPCode failed at %s: %v", tc.name, err)
			}
			if step < 0 {
				t.Fatalf("Code should validate at its generation time for %s", tc.name)
			}
		})
	}
}

// TestTOTPEdge_NegativeTimestamp tests that negative timestamps are rejected.
func TestTOTPEdge_NegativeTimestamp(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	negativeTimes := []struct {
		name string
		time time.Time
	}{
		{"minus_one", time.Unix(-1, 0)},
		{"minus_30", time.Unix(-30, 0)},
		{"minus_large", time.Unix(-1000000, 0)},
	}

	for _, tc := range negativeTimes {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GenerateTOTPCode(secret, tc.time)
			if err == nil {
				t.Fatalf("Negative timestamp %s should return error", tc.name)
			}
			if !strings.Contains(err.Error(), "negative") {
				t.Fatalf("Error should mention negative, got: %v", err)
			}
		})
	}
}

// TestTOTPEdge_PeriodBoundaryValidation tests codes at the exact boundary
// between two TOTP periods.
func TestTOTPEdge_PeriodBoundaryValidation(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	// Generate code right at a period boundary
	// Period = 30 seconds, counter = unix / 30
	// At t=30, we're at the start of period 1
	// At t=29, we're at the end of period 0
	t.Run("end_of_period", func(t *testing.T) {
		// Pick a time at the end of a period
		boundaryTime := time.Unix(89, 0) // end of period 2 (60-89)
		nextTime := time.Unix(90, 0)     // start of period 3 (90-119)

		codeAtBoundary, _ := GenerateTOTPCode(secret, boundaryTime)
		codeAfterBoundary, _ := GenerateTOTPCode(secret, nextTime)

		// The code at period boundary and next period may differ
		// (unless they happen to be the same by chance)
		// Both should still be valid at their respective times
		step1, _ := ValidateTOTPCode(secret, codeAtBoundary, boundaryTime)
		if step1 < 0 {
			t.Fatal("Code at boundary should validate at boundary time")
		}

		step2, _ := ValidateTOTPCode(secret, codeAfterBoundary, nextTime)
		if step2 < 0 {
			t.Fatal("Code after boundary should validate at next time")
		}
	})
}

// TestTOTPEdge_ClockDrift tests TOTP validation with various clock offsets
// to verify the ±1 skew window works correctly.
func TestTOTPEdge_ClockDrift(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	// Use a time that's well within a period (not near boundary)
	// Period = 30s, pick a time at second 15 of a period
	baseTime := time.Unix(1700000015, 0) // Mid-period

	code, _ := GenerateTOTPCode(secret, baseTime)

	drifts := []struct {
		name     string
		offset   time.Duration
		shouldOK bool
	}{
		{"no_drift", 0, true},
		{"plus_10s", 10 * time.Second, true},    // Same period
		{"minus_10s", -10 * time.Second, true},  // Same period
		{"plus_20s", 20 * time.Second, true},    // Adjacent period
		{"minus_20s", -20 * time.Second, true},  // Same or adjacent
		{"plus_30s", 30 * time.Second, true},    // Adjacent period (±1 skew)
		{"minus_30s", -30 * time.Second, true},  // Adjacent period (±1 skew)
		{"plus_59s", 59 * time.Second, false},   // Beyond ±1 (might be period+2)
		{"minus_59s", -59 * time.Second, false}, // Beyond ±1 (might be period-2)
		{"plus_90s", 90 * time.Second, false},   // Definitely beyond
		{"minus_90s", -90 * time.Second, false}, // Definitely beyond
		{"plus_5min", 5 * time.Minute, false},
		{"minus_5min", -5 * time.Minute, false},
	}

	for _, tc := range drifts {
		t.Run(tc.name, func(t *testing.T) {
			verifyTime := baseTime.Add(tc.offset)
			step, _ := ValidateTOTPCode(secret, code, verifyTime)
			if tc.shouldOK && step < 0 {
				t.Fatalf("Code should validate with drift %v", tc.offset)
			}
			if !tc.shouldOK && step >= 0 {
				t.Fatalf("Code should NOT validate with drift %v (beyond ±1 window)", tc.offset)
			}
		})
	}
}

// TestTOTPEdge_ReplayDetection verifies the mechanism for detecting TOTP
// code replay. ValidateTOTPCode returns the time step, which can be stored
// and compared to detect reuse.
func TestTOTPEdge_ReplayDetection(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Now()

	code, _ := GenerateTOTPCode(secret, now)

	// First validation returns a step
	step1, err := ValidateTOTPCode(secret, code, now)
	if err != nil {
		t.Fatalf("First validation error: %v", err)
	}
	if step1 < 0 {
		t.Fatal("First validation should succeed")
	}

	// Second validation of the same code at the same time returns the same step.
	// The application layer MUST track used steps and reject duplicates.
	step2, _ := ValidateTOTPCode(secret, code, now)
	if step2 < 0 {
		t.Fatal("Second validation should succeed (crypto layer doesn't track state)")
	}

	// Both steps should be equal (same code, same time = same step)
	if step1 != step2 {
		t.Fatalf("Same code at same time should return same step: %d vs %d", step1, step2)
	}

	// The returned step value enables replay detection:
	// store step1, and on next validation check step >= lastUsedStep
	t.Logf("Replay detection: step=%d — application should reject this step on reuse", step1)
}

// TestTOTPEdge_InvalidSecretFormats tests TOTP with various invalid secrets.
func TestTOTPEdge_InvalidSecretFormats(t *testing.T) {
	now := time.Now()

	invalidSecrets := []struct {
		name   string
		secret string
	}{
		{"non_base32", "!!!invalid-base32!!!"},
		{"lowercase_valid", "jbswy3dpehpk3pxp"}, // lowercase should work (ToUpper is applied)
		{"with_padding", "JBSWY3DPEHPK3PXP===="},
		{"with_spaces", "JBSW Y3DP EHPK 3PXP"},
	}

	for _, tc := range invalidSecrets {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GenerateTOTPCode(tc.secret, now)
			// Some of these may work (lowercase), others should fail
			if tc.name == "lowercase_valid" && err != nil {
				t.Fatalf("Lowercase base32 should work: %v", err)
			}
			// Non-base32 should definitely fail
			if tc.name == "non_base32" && err == nil {
				t.Fatal("Non-base32 secret should fail")
			}
		})
	}
}

// TestTOTPEdge_OTPAuthURLSpecialChars tests OTPAuth URL generation with
// special characters in issuer and account name.
func TestTOTPEdge_OTPAuthURLSpecialChars(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	cases := []struct {
		name    string
		issuer  string
		account string
	}{
		{"normal", "TheVault", "user@example.com"},
		{"spaces", "The Vault", "user name@example.com"},
		{"unicode", "V\u00e4ult", "\u00fc\u00f1\u00eeuser@example.com"},
		{"ampersand", "Vault&Co", "user@domain.com"},
		{"colon", "Vault:Auth", "user@domain.com"},
		{"slash", "Vault/Auth", "user@domain.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := BuildOTPAuthURL(secret, tc.issuer, tc.account)

			if !strings.HasPrefix(url, "otpauth://totp/") {
				t.Fatalf("URL should start with otpauth://totp/, got %s", url)
			}
			if !strings.Contains(url, "secret="+secret) {
				t.Fatal("URL should contain the secret")
			}
			if !strings.Contains(url, "algorithm=SHA1") {
				t.Fatal("URL should specify SHA1 algorithm")
			}
			if !strings.Contains(url, "digits=6") {
				t.Fatal("URL should specify 6 digits")
			}
			if !strings.Contains(url, "period=30") {
				t.Fatal("URL should specify 30-second period")
			}
		})
	}
}

// TestTOTPEdge_SecretGeneration tests that generated secrets meet requirements.
func TestTOTPEdge_SecretGeneration(t *testing.T) {
	secrets := make(map[string]bool)

	for i := 0; i < 100; i++ {
		secret, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("GenerateTOTPSecret failed at %d: %v", i, err)
		}

		// Should be non-empty
		if secret == "" {
			t.Fatal("Secret should not be empty")
		}

		// Should be valid base32 (uppercase, no padding)
		for _, c := range secret {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", c) {
				t.Fatalf("Invalid base32 character: %c", c)
			}
		}

		// Should be unique
		if secrets[secret] {
			t.Fatalf("Duplicate secret at iteration %d", i)
		}
		secrets[secret] = true
	}
}

// TestTOTPEdge_ValidateCodeWithDifferentSecret verifies that a code generated
// with one secret does not validate with a different secret.
func TestTOTPEdge_ValidateCodeWithDifferentSecret(t *testing.T) {
	secret1, _ := GenerateTOTPSecret()
	secret2, _ := GenerateTOTPSecret()
	now := time.Now()

	code1, _ := GenerateTOTPCode(secret1, now)

	// Code from secret1 should NOT validate with secret2
	step, _ := ValidateTOTPCode(secret2, code1, now)
	if step >= 0 {
		t.Fatal("Code from different secret should not validate")
	}
}
