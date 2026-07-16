package service

import "testing"

// maskEmail feeds audit metadata. The edge shapes (no @, empty local part,
// single-char local part) never come from sanitize.Email-validated input, but
// erasure retries and imported rows can carry them, and the mask must never
// leak more than the first character.
func TestMaskEmail(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"alice@example.com", "a***@example.com"},
		{"a@example.com", "a***@example.com"},
		{"@example.com", "***"},
		{"no-at-sign", "***"},
	}
	for _, tt := range tests {
		if got := maskEmail(tt.in); got != tt.want {
			t.Errorf("maskEmail(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
