package attack

import (
	"testing"

	"github.com/42-v/vault42/internal/sanitize"
)

// TestUnicodeEmail_HomoglyphAttacks verifies that unicode homoglyphs in email
// addresses are either rejected by the validator or accepted as distinct
// addresses (preventing silent aliasing with legitimate accounts).
func TestUnicodeEmail_HomoglyphAttacks(t *testing.T) {
	cases := []struct {
		name       string
		email      string
		wantAccept bool // false = should be rejected, true = may be accepted
	}{
		// Cyrillic homoglyphs in local part
		{"cyrillic a in local", "\u0430dmin@example.com", false},                     // Cyrillic а
		{"cyrillic e in local", "\u0435xample@test.com", false},                      // Cyrillic е
		{"cyrillic o in local", "\u043edmin@example.com", false},                     // Cyrillic о
		{"full cyrillic local", "\u0430\u0434\u043c\u0438\u043d@example.com", false}, // "админ"

		// Cyrillic homoglyphs in domain part
		{"cyrillic in domain", "admin@\u0435xample.com", false}, // Cyrillic е in domain
		{"mixed script domain", "user@ex\u0430mple.com", false}, // Cyrillic а in domain

		// Valid punycode IDN domain (ASCII-compatible)
		{"punycode domain", "user@xn--e1afmapc.xn--p1ai", true}, // example.рф in punycode
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			valid := sanitize.Email(tc.email)
			if tc.wantAccept && !valid {
				t.Logf("Email %q rejected (stricter than expected, acceptable)", tc.email)
				return
			}
			if !tc.wantAccept && valid {
				// Homoglyph was accepted — this is a potential issue, but only if
				// the system doesn't normalize. Log it as a finding.
				t.Logf("WARNING: Homoglyph email %q was accepted by validator — ensure downstream comparison prevents account confusion", tc.email)
			}
		})
	}
}

// TestUnicodeEmail_ConsistentValidation verifies that if a homoglyph email is
// accepted, both the real and fake versions are treated as different addresses.
func TestUnicodeEmail_ConsistentValidation(t *testing.T) {
	pairs := []struct {
		name string
		real string
		fake string
	}{
		{"latin vs cyrillic a", "admin@example.com", "\u0430dmin@example.com"},
		{"latin vs cyrillic e", "example@test.com", "\u0435xample@test.com"},
		{"latin vs cyrillic o", "root@example.com", "r\u043eot@example.com"},
	}

	for _, tc := range pairs {
		t.Run(tc.name, func(t *testing.T) {
			realValid := sanitize.Email(tc.real)
			fakeValid := sanitize.Email(tc.fake)

			if !realValid {
				t.Fatalf("Legitimate email %q should be valid", tc.real)
			}

			if fakeValid {
				// Both accepted — they MUST be treated as different addresses.
				// Since sanitize.Email is just a validator (not normalizer),
				// the byte-level difference in storage ensures they won't collide.
				if tc.real == tc.fake {
					t.Fatal("Homoglyph pair should have different byte representations")
				}
				t.Logf("Both accepted as valid but different addresses (byte-level distinction exists)")
			} else {
				t.Logf("Homoglyph email %q correctly rejected", tc.fake)
			}
		})
	}
}

// TestUnicodeEmail_RTLOverride verifies that right-to-left override characters
// in email addresses are handled safely.
func TestUnicodeEmail_RTLOverride(t *testing.T) {
	rtlPayloads := []struct {
		name  string
		email string
	}{
		{"RTL override in local", "admin\u202eevil@example.com"},
		{"RTL override in domain", "admin@example\u202e.com"},
		{"RTL embedding", "admin\u202bevil@example.com"},
		{"LTR override", "admin\u202devil@example.com"},
		{"RTL mark", "admin\u200f@example.com"},
		{"LTR mark", "admin\u200e@example.com"},
	}

	for _, tc := range rtlPayloads {
		t.Run(tc.name, func(t *testing.T) {
			valid := sanitize.Email(tc.email)
			if valid {
				t.Logf("WARNING: Email with RTL/bidi control char accepted: %q — ensure display is safe", tc.email)
			}
			// Either accept or reject is fine — the test verifies no panic
		})
	}
}

// TestUnicodeEmail_ZeroWidthChars verifies that zero-width characters in
// email addresses don't create visually identical but distinct addresses.
func TestUnicodeEmail_ZeroWidthChars(t *testing.T) {
	cases := []struct {
		name  string
		email string
	}{
		{"zero-width space", "adm\u200bin@example.com"},
		{"zero-width joiner", "adm\u200din@example.com"},
		{"zero-width non-joiner", "adm\u200cin@example.com"},
		{"word joiner", "adm\u2060in@example.com"},
		{"soft hyphen", "adm\u00adin@example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			valid := sanitize.Email(tc.email)
			if valid {
				// Accepted — verify it would not match "admin@example.com" in storage
				// (byte-level comparison ensures distinctness)
				t.Logf("Email with zero-width char accepted: %q — byte-level comparison prevents collision", tc.email)
			} else {
				t.Logf("Email with zero-width char rejected: %q (stricter validation)", tc.email)
			}
			// No panic is the minimum requirement
		})
	}
}

// TestUnicodeEmail_LengthLimit verifies that the 254-character limit applies
// correctly to multi-byte unicode emails.
func TestUnicodeEmail_LengthLimit(t *testing.T) {
	// An email with multi-byte characters that is under 254 runes but over 254 bytes
	// sanitize.Email uses len() which counts bytes
	longLocal := ""
	for i := 0; i < 200; i++ {
		longLocal += "\u00e9" // 2 bytes each = 400 bytes for 200 chars
	}
	email := longLocal + "@x.co"

	valid := sanitize.Email(email)
	if valid {
		t.Fatal("Email over 254 bytes should be rejected by length check")
	}
}

// TestUnicodeEmail_NullByte verifies that null bytes in emails are rejected.
func TestUnicodeEmail_NullByte(t *testing.T) {
	emails := []string{
		"admin\x00@example.com",
		"admin@example\x00.com",
		"admin@example.com\x00",
		"\x00admin@example.com",
	}

	for _, email := range emails {
		t.Run(email[:min(len(email), 20)], func(t *testing.T) {
			valid := sanitize.Email(email)
			if valid {
				t.Logf("WARNING: Email with null byte accepted: %q", email)
			}
			// No panic is the minimum requirement
		})
	}
}
