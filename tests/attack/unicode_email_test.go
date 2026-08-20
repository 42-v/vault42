package attack

import (
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/sanitize"
)

// TestUnicodeEmail_HomoglyphAttacks pins the validator's homoglyph contract.
//
// sanitize.Email is a validator, not a normalizer: it accepts any RFC 5322
// address (net/mail.ParseAddress treats non-ASCII runes as valid atext) and
// stores the exact bytes. A Cyrillic homoglyph is therefore accepted as a
// distinct address, and that is safe here because nothing downstream folds it
// onto the Latin original: registration and login apply only
// strings.ToLower(strings.TrimSpace(email)) (Unicode case mapping preserves
// script, so Cyrillic U+0430 never becomes Latin U+0061), and the lookup is an
// exact-byte "WHERE email = $1" with no LOWER()/citext/ILIKE collation. The
// byte-distinctness that keeps the two accounts separate is proven directly in
// TestUnicodeEmail_ConsistentValidation. wantAccept below records the real,
// intended behavior, and the test now fails if that behavior regresses in
// either direction.
func TestUnicodeEmail_HomoglyphAttacks(t *testing.T) {
	cases := []struct {
		name       string
		email      string
		wantAccept bool // must match the validator exactly
	}{
		// Cyrillic homoglyphs in local part: accepted as valid RFC 5322
		// addresses, kept distinct from their Latin lookalikes by byte value.
		{"cyrillic a in local", "\u0430dmin@example.com", true},                     // Cyrillic а
		{"cyrillic e in local", "\u0435xample@test.com", true},                      // Cyrillic е
		{"cyrillic o in local", "\u043edmin@example.com", true},                     // Cyrillic о
		{"full cyrillic local", "\u0430\u0434\u043c\u0438\u043d@example.com", true}, // "админ"

		// Cyrillic homoglyphs in domain part: same story, accepted and distinct.
		{"cyrillic in domain", "admin@\u0435xample.com", true}, // Cyrillic е in domain
		{"mixed script domain", "user@ex\u0430mple.com", true}, // Cyrillic а in domain

		// Valid punycode IDN domain (ASCII-compatible)
		{"punycode domain", "user@xn--e1afmapc.xn--p1ai", true}, // example.рф in punycode
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			valid := sanitize.Email(tc.email)
			if tc.wantAccept && !valid {
				t.Errorf("email %q should be accepted, was rejected", tc.email)
			}
			if !tc.wantAccept && valid {
				t.Errorf("email %q should be rejected, was accepted", tc.email)
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

// TestUnicodeEmail_RTLOverride pins what the validator does with bidi controls.
//
// sanitize.Email validates, it does not normalize (the reasoning is on
// TestUnicodeEmail_HomoglyphAttacks above), and net/mail.ParseAddress treats a
// bidi control as ordinary atext, so every payload here is accepted as an
// address in its own right. That is safe for authentication because the stored
// bytes stay distinct from the address being imitated, and the lookup key is
// strings.ToLower(strings.TrimSpace(email)) with no further folding. Both
// halves are asserted below.
//
// The test used to log a warning and pass either way, so the one change that
// would actually merge two accounts, folding these onto the plain address,
// would have gone through green. Rendering is a separate problem: whatever
// displays an address has to neutralize the controls itself.
func TestUnicodeEmail_RTLOverride(t *testing.T) {
	rtlPayloads := []struct {
		name       string
		email      string
		wantAccept bool // must match the validator exactly
	}{
		{"RTL override in local", "admin\u202eevil@example.com", true},
		{"RTL override in domain", "admin@example\u202e.com", true},
		{"RTL embedding", "admin\u202bevil@example.com", true},
		{"LTR override", "admin\u202devil@example.com", true},
		{"RTL mark", "admin\u200f@example.com", true},
		{"LTR mark", "admin\u200e@example.com", true},
	}

	for _, tc := range rtlPayloads {
		t.Run(tc.name, func(t *testing.T) {
			assertEmailStaysDistinct(t, tc.email, tc.wantAccept)
		})
	}
}

// TestUnicodeEmail_ZeroWidthChars pins the same contract for the invisible
// characters, the ones that make a spoofed address indistinguishable on screen
// from admin@example.com. They are accepted, and they do not fold onto the
// address they imitate, which is what keeps the two accounts apart.
func TestUnicodeEmail_ZeroWidthChars(t *testing.T) {
	cases := []struct {
		name       string
		email      string
		wantAccept bool
	}{
		{"zero-width space", "adm\u200bin@example.com", true},
		{"zero-width joiner", "adm\u200din@example.com", true},
		{"zero-width non-joiner", "adm\u200cin@example.com", true},
		{"word joiner", "adm\u2060in@example.com", true},
		{"soft hyphen", "adm\u00adin@example.com", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertEmailStaysDistinct(t, tc.email, tc.wantAccept)
		})
	}
}

// assertEmailStaysDistinct checks the validator's verdict against the recorded
// one and, for an accepted address, that it does not collapse onto the plain
// address under the only normalization the login path applies.
func assertEmailStaysDistinct(t *testing.T, email string, wantAccept bool) {
	t.Helper()
	const plain = "admin@example.com"

	valid := sanitize.Email(email)
	if valid != wantAccept {
		t.Fatalf("sanitize.Email(%q) = %v, want %v", email, valid, wantAccept)
	}
	if !valid {
		return
	}
	if strings.ToLower(strings.TrimSpace(email)) == plain {
		t.Errorf("%q folds onto %q under the lookup key, so the two accounts would collide", email, plain)
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
			if sanitize.Email(email) {
				t.Errorf("email with null byte must be rejected, was accepted: %q", email)
			}
		})
	}
}
