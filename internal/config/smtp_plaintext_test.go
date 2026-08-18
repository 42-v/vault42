package config

import (
	"strings"
	"testing"
)

// VAULT_SMTP_ALLOW_PLAINTEXT turns off the STARTTLS requirement on the mail
// path, so it is scoped to the relay it was introduced for: a hop on this
// machine. Set against a remote host it does not accept a local trade-off, it
// mails one-time codes and reset links across a network in cleartext.
func TestLoadScopesThePlaintextSMTPOptOutToALoopbackRelay(t *testing.T) {
	t.Run("default is off", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "embedded")

		c, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if c.SMTPAllowPlaintext {
			t.Fatal("SMTPAllowPlaintext defaulted to true; STARTTLS must be required unless an operator opts out")
		}
	})

	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		t.Run("accepted for "+host, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "embedded")
			t.Setenv("VAULT_SMTP_ALLOW_PLAINTEXT", "true")
			t.Setenv("SMTP_HOST", host)

			c, err := Load()
			if err != nil {
				t.Fatalf("Load rejected a loopback relay: %v", err)
			}
			if !c.SMTPAllowPlaintext {
				t.Fatal("SMTPAllowPlaintext = false, want true")
			}
		})
	}

	for _, host := range []string{"smtp.example.com", "10.0.0.5", ""} {
		t.Run("refused for "+host, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "embedded")
			t.Setenv("VAULT_SMTP_ALLOW_PLAINTEXT", "true")
			t.Setenv("SMTP_HOST", host)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted the plaintext opt-out for SMTP_HOST=%q", host)
			}
			if !strings.Contains(err.Error(), "VAULT_SMTP_ALLOW_PLAINTEXT") {
				t.Fatalf("error %q does not name VAULT_SMTP_ALLOW_PLAINTEXT", err)
			}
		})
	}

	t.Run("dev may point it anywhere", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "dev")
		t.Setenv("VAULT_SMTP_ALLOW_PLAINTEXT", "true")
		t.Setenv("SMTP_HOST", "mailhog")

		c, err := Load()
		if err != nil {
			t.Fatalf("dev profile rejected the plaintext opt-out: %v", err)
		}
		if !c.SMTPAllowPlaintext {
			t.Fatal("SMTPAllowPlaintext = false, want true")
		}
	})
}
