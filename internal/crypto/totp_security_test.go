package crypto

import "testing"

func TestIsValidTOTPCodeDigitsOnly(t *testing.T) {
	// This tests the TOTP code validation that was added in the handler package,
	// but we can test the underlying concept: TOTP codes should always be 6 digits.

	tests := []struct {
		name  string
		code  string
		valid bool
	}{
		{"valid 6 digits", "123456", true},
		{"valid all zeros", "000000", true},
		{"valid all nines", "999999", true},
		{"too short", "12345", false},
		{"too long", "1234567", false},
		{"empty", "", false},
		{"letters", "abcdef", false},
		{"mixed alphanumeric", "12ab34", false},
		{"unicode digits", "１２３４５６", false}, // fullwidth digits
		{"spaces", "123 56", false},
		{"newline injection", "12345\n", false},
		{"null byte", "12345\x00", false},
		{"negative sign", "-12345", false},
		{"decimal point", "12.456", false},
	}

	// We define the same validation function from the handler for testing
	isValid := func(code string) bool {
		if len(code) != 6 {
			return false
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValid(tt.code)
			if got != tt.valid {
				t.Errorf("isValidTOTPCode(%q) = %v, want %v", tt.code, got, tt.valid)
			}
		})
	}
}
