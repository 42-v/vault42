package crypto

import "testing"

func TestArgon2CountersAccessible(t *testing.T) {
	// Argon2ActiveCount and Argon2RejectedCount are read concurrently by the
	// metrics handler; we just confirm they return sane initial values.
	if got := Argon2ActiveCount(); got < 0 {
		t.Fatalf("Argon2ActiveCount = %d, want >= 0", got)
	}
	if got := Argon2RejectedCount(); got < 0 {
		t.Fatalf("Argon2RejectedCount = %d, want >= 0", got)
	}
	if got := Argon2MaxConcurrent(); got <= 0 {
		t.Fatalf("Argon2MaxConcurrent = %d, want > 0", got)
	}
}
