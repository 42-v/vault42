package fuzz

import (
	"strings"
	"testing"
)

// FuzzEmailValidation feeds random strings to basic email validation logic.
func FuzzEmailValidation(f *testing.F) {
	f.Add("user@example.com")
	f.Add("")
	f.Add("@")
	f.Add("user@")
	f.Add("@domain")
	f.Add("a@b.c")
	f.Add("very-long" + strings.Repeat("a", 300) + "@example.com")
	f.Add("user@" + strings.Repeat("x", 300))
	f.Add("\x00@\x00")

	f.Fuzz(func(t *testing.T, email string) {
		// Basic email validation (same logic as service/auth.go)
		// Should never panic
		_ = isValidEmail(email)
	})
}

func isValidEmail(email string) bool {
	if len(email) < 3 || len(email) > 254 {
		return false
	}
	at := strings.LastIndex(email, "@")
	if at < 1 || at > len(email)-3 {
		return false
	}
	domain := email[at+1:]
	return strings.Contains(domain, ".")
}
