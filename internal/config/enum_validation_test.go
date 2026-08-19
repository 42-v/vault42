package config

import (
	"strings"
	"testing"
)

// VAULT_PROFILE selects which security controls exist at all, and every
// profile-keyed guard in this package and in the server compares it against one
// exact string. An unrecognized value used to become production silently, so
// VAULT_PROFILE=Honeypot produced a deployment whose trap users triggered
// nothing: server.go mounts the honeypot alerter only when the profile is
// exactly "honeypot", and the deception deployment then ran as an ordinary
// vault with fake accounts in it and no webhook.
func TestLoadRefusesAProfileNameItDoesNotKnow(t *testing.T) {
	for _, value := range []string{"staging", "prod", "development", "honeypot-eu"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted VAULT_PROFILE=%q; an unknown profile must refuse to start rather than silently become production", value)
			}
			if !strings.Contains(err.Error(), "VAULT_PROFILE") {
				t.Fatalf("error %q does not name VAULT_PROFILE", err)
			}
		})
	}
}

// A correct profile name in the wrong case is the operator's intent, not an
// unknown profile. Refusing it would turn a working deployment into a boot
// loop on upgrade, and silently rewriting it to production is how the honeypot
// alerter went missing.
func TestAProfileNameIsRecognizedRegardlessOfCaseAndSurroundingSpace(t *testing.T) {
	tests := map[string]Profile{
		"Production": ProfileProduction,
		"EMBEDDED":   ProfileEmbedded,
		"Dev":        ProfileDev,
		"Honeypot":   ProfileHoneypot,
		" honeypot ": ProfileHoneypot,
	}

	for value, want := range tests {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", value)

			c, err := Load()
			if err != nil {
				t.Fatalf("Load rejected VAULT_PROFILE=%q: %v", value, err)
			}
			if c.Profile != want {
				t.Fatalf("VAULT_PROFILE=%q became profile %q, want %q", value, c.Profile, want)
			}
		})
	}
}

// DB_SSLMODE is a closed set that pgx parses, and an unrecognized spelling only
// surfaces as "sslmode is invalid" from inside the first connection attempt,
// after the startup banner has printed the value back as if it were accepted.
// Catching it here names the variable and the legal values instead.
func TestLoadRefusesADatabaseSSLModePostgresWouldNotAccept(t *testing.T) {
	for _, value := range []string{"Require", "verify_full", "enabled", "off"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv("DB_SSLMODE", value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted DB_SSLMODE=%q", value)
			}
			if !strings.Contains(err.Error(), "DB_SSLMODE") {
				t.Fatalf("error %q does not name DB_SSLMODE", err)
			}
		})
	}
}

// The in-pod Postgres deployments (values-bridge, values-local,
// values-embedded, values-honeypot) all set sslmode=disable deliberately, so
// every legal mode must keep loading.
func TestEveryPostgresSSLModeThatPgxAcceptsStillLoads(t *testing.T) {
	for _, value := range []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv("DB_SSLMODE", value)

			c, err := Load()
			if err != nil {
				t.Fatalf("Load rejected DB_SSLMODE=%q: %v", value, err)
			}
			if c.DBSSLMode != value {
				t.Fatalf("DBSSLMode = %q, want %q", c.DBSSLMode, value)
			}
		})
	}
}

// VAULT_EMAIL_PROVIDER picks which backend sends address verification, password
// reset and email OTP messages. An unrecognized value falls through to the SMTP
// branch, so VAULT_EMAIL_PROVIDER=SendGrid with only a SendGrid key configured
// and an SMTP host set sends through SMTP, and with neither configured the
// sender is nil and every verification mail is dropped without an error.
func TestLoadRefusesAnEmailProviderItHasNoBackendFor(t *testing.T) {
	for _, value := range []string{"SendGrid", "ses", "postmark"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv("VAULT_EMAIL_PROVIDER", value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted VAULT_EMAIL_PROVIDER=%q", value)
			}
			if !strings.Contains(err.Error(), "VAULT_EMAIL_PROVIDER") {
				t.Fatalf("error %q does not name VAULT_EMAIL_PROVIDER", err)
			}
		})
	}
}

// CACHE_BACKEND is the known instance of this defect: the production guard
// compares it against the exact string "redis", so a near-miss spelling skipped
// the REDIS_ADDR requirement and fell through the factory to a per-process
// memory cache. The factory now rejects the unknown name, but the config must
// refuse it too, because the guard that requires REDIS_ADDR runs first.
func TestLoadRefusesACacheBackendThatHasNoImplementation(t *testing.T) {
	for _, value := range []string{"Redis", "valkey", "REDIS", "in-memory"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv("CACHE_BACKEND", value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted CACHE_BACKEND=%q", value)
			}
			if !strings.Contains(err.Error(), "CACHE_BACKEND") {
				t.Fatalf("error %q does not name CACHE_BACKEND", err)
			}
		})
	}
}

// The three implemented backends must keep loading, and an unset value must
// keep meaning "whatever the profile chose" (memory on embedded, redis on
// production).
func TestEveryImplementedCacheBackendStillLoads(t *testing.T) {
	for _, value := range []string{"redis", "memory", "postgres"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv("CACHE_BACKEND", value)

			c, err := Load()
			if err != nil {
				t.Fatalf("Load rejected CACHE_BACKEND=%q: %v", value, err)
			}
			if c.CacheBackend != value {
				t.Fatalf("CacheBackend = %q, want %q", c.CacheBackend, value)
			}
		})
	}
}
