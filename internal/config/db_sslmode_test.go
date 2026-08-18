package config

import "testing"

// An unencrypted database link is the same class of exposure as an unencrypted
// listener, and the same file already refuses to start on the listener: M5
// returns an error for TLSEnabled=false without VAULT_ALLOW_PLAINTEXT, fourteen
// lines above where DB_SSLMODE merely logged a warning and booted. The database
// connection carries the role password in its startup packet and then every row
// of every table — password hashes, encrypted TOTP secrets, identity ciphertext
// — so the weaker treatment was the wrong way round.
//
// "prefer" is the mode that has to be caught with the others: it negotiates TLS
// and falls back to plaintext without an error, so it looks encrypted in the
// manifest and is not on the wire.
func TestUnencryptedDBSSLModeRefusesToStartOutsideDev(t *testing.T) {
	for _, mode := range []string{"disable", "allow", "prefer"} {
		t.Run(mode, func(t *testing.T) {
			c := prodConfig()
			c.DBSSLMode = mode
			err := c.Validate()
			if err == nil {
				t.Fatalf("DB_SSLMODE=%s must refuse to start in the %s profile; "+
					"a warning that boots anyway is not a control", mode, c.Profile)
			}
		})
	}
}

// Every encrypted mode still boots untouched.
func TestEncryptedDBSSLModesStillValidate(t *testing.T) {
	for _, mode := range []string{"require", "verify-ca", "verify-full"} {
		t.Run(mode, func(t *testing.T) {
			c := prodConfig()
			c.DBSSLMode = mode
			if err := c.Validate(); err != nil {
				t.Fatalf("DB_SSLMODE=%s must validate: %v", mode, err)
			}
		})
	}
}

// The same-pod Postgres deployments the chart overlays ship (bridge, embedded,
// honeypot, local) legitimately run over a loopback or in-cluster link with no
// TLS. They get an explicit opt-in rather than a silent pass, exactly like
// VAULT_ALLOW_PLAINTEXT for the listener and VAULT_ALLOW_RATE_LIMIT_DISABLED for
// the limiter: the operator writes the override down, so the posture is visible
// in the manifest instead of in a log line nobody reads.
func TestPlaintextDBOverrideAllowsAnUnencryptedLink(t *testing.T) {
	t.Setenv("VAULT_ALLOW_PLAINTEXT_DB", "true")
	c := prodConfig()
	c.DBSSLMode = "disable"
	if err := c.Validate(); err != nil {
		t.Fatalf("VAULT_ALLOW_PLAINTEXT_DB=true must permit DB_SSLMODE=disable: %v", err)
	}
}

// Dev is exempt because Validate returns before every non-dev check; this pins
// that the exemption is deliberate rather than incidental, so a later reordering
// that drags the dev short-circuit below this check fails here.
func TestDevProfileStillAcceptsAnUnencryptedDBLink(t *testing.T) {
	c := &Config{Profile: ProfileDev, DBSSLMode: "disable"}
	if err := c.Validate(); err != nil {
		t.Fatalf("dev profile must still accept DB_SSLMODE=disable: %v", err)
	}
}
