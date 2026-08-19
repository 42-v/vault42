package config

import (
	"strings"
	"testing"
)

// keystore.StartRefreshLoop passes this straight to time.NewTicker, which
// panics on a non-positive interval. The panic happens in the refresh
// goroutine after the listener is up, so the process takes the request that
// arrives in that window with it and then crash-loops, with a runtime panic
// rather than a configuration error as the only clue.
func TestLoadRefusesAKeyRefreshIntervalThatWouldPanicTheRefreshLoop(t *testing.T) {
	for _, value := range []string{"0", "0s", "-30s"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv("VAULT_KEY_REFRESH_INTERVAL", value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted VAULT_KEY_REFRESH_INTERVAL=%q; time.NewTicker panics on it", value)
			}
			if !strings.Contains(err.Error(), "VAULT_KEY_REFRESH_INTERVAL") {
				t.Fatalf("error %q does not name VAULT_KEY_REFRESH_INTERVAL", err)
			}
		})
	}
}

// A negative duration is never what an operator means, and each of these is
// read by a caller that treats "less than now" as "already expired": a negative
// access token TTL issues tokens that are expired at the moment they are
// signed, and a negative session lifetime kills every session on its first
// refresh. Zero is a documented "disabled" for the session bound and a
// documented "use the profile default" for the TTLs, so only the negative side
// is refused here.
func TestLoadRefusesANegativeDuration(t *testing.T) {
	for _, key := range []string{
		"VAULT_ACCESS_TOKEN_TTL",
		"VAULT_REFRESH_TOKEN_TTL",
		"VAULT_REMEMBER_ME_TTL",
		"VAULT_MAX_SESSION_LIFETIME",
		"VAULT_SHUTDOWN_TIMEOUT",
		"VAULT_AUDIT_FLUSH_INTERVAL",
		"VAULT_KEY_RETENTION_PERIOD",
		"VAULT_MINT_TOKEN_TTL",
		"VAULT_MINT_MAX_TTL",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv(key, "-1h")

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted %s=-1h", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Fatalf("error %q does not name %s", err, key)
			}
		})
	}
}

// A retention horizon in days becomes a duration by multiplication, and the
// sweepers run only when it is positive. VAULT_AUDIT_RETENTION_DAYS=-30 leaves
// the sweeper switched off while the operator's config records a 30-day
// horizon, so the audit table keeps personal data forever against the retention
// table in docs/PRIVACY.md, and VAULT_RECOVERY_RETENTION_DAYS=-30 does the same
// to the erasure escrow.
func TestLoadRefusesANegativeRetentionHorizon(t *testing.T) {
	for _, key := range []string{"VAULT_AUDIT_RETENTION_DAYS", "VAULT_RECOVERY_RETENTION_DAYS"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv(key, "-30")

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted %s=-30; the sweeper stays off while the config claims a horizon", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Fatalf("error %q does not name %s", err, key)
			}
		})
	}
}

// The password floor is the only length control on the registration and reset
// paths: AuthService.Register and PasswordHandler compare the rune count
// against this number and nothing else enforces a minimum.
// VAULT_PASSWORD_MIN_LENGTH=0 accepts an empty password, and any value under
// the NIST SP 800-63B-4 §3.1.1.2 floor of 15 accepts one an offline attacker
// enumerates. The dev profile keeps a lower floor — the §3.1.1.1 verifier
// minimum of 8 — because a local login is not a deployment, but it no longer
// bypasses the check entirely.
func TestLoadRefusesAPasswordFloorBelowTheNISTMinimumOutsideDev(t *testing.T) {
	for _, value := range []string{"0", "4", "-1", "8", "14"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "embedded")
			t.Setenv("VAULT_PASSWORD_MIN_LENGTH", value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted VAULT_PASSWORD_MIN_LENGTH=%q outside dev", value)
			}
			if !strings.Contains(err.Error(), "VAULT_PASSWORD_MIN_LENGTH") {
				t.Fatalf("error %q does not name VAULT_PASSWORD_MIN_LENGTH", err)
			}
		})
	}

	t.Run("15 is accepted outside dev", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "embedded")
		t.Setenv("VAULT_PASSWORD_MIN_LENGTH", "15")

		c, err := Load()
		if err != nil {
			t.Fatalf("Load rejected the documented 15-character minimum: %v", err)
		}
		if c.PasswordMinLength != 15 {
			t.Fatalf("PasswordMinLength = %d, want 15", c.PasswordMinLength)
		}
	})

	t.Run("dev may relax it only to the verifier minimum", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "dev")
		t.Setenv("VAULT_PASSWORD_MIN_LENGTH", "8")

		c, err := Load()
		if err != nil {
			t.Fatalf("dev profile rejected the verifier minimum: %v", err)
		}
		if c.PasswordMinLength != 8 {
			t.Fatalf("PasswordMinLength = %d, want 8", c.PasswordMinLength)
		}
	})

	t.Run("dev does not bypass the floor", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "dev")
		t.Setenv("VAULT_PASSWORD_MIN_LENGTH", "4")

		if _, err := Load(); err == nil {
			t.Fatal("dev profile accepted VAULT_PASSWORD_MIN_LENGTH=4; the dev escape hatch must still have a floor")
		}
	})
}
