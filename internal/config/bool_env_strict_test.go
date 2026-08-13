package config

import (
	"strings"
	"testing"
)

// A boolean environment variable whose value is not a recognized spelling must
// refuse to start.
//
// The parser accepted "true", "1" and "yes" and answered false for everything
// else, so VAULT_MFA_REQUIRED=True left every account password-only while
// /auth/capabilities advertised mfa_required=false, VAULT_DPOP_ENABLED=True
// left the token endpoints accepting replayed bearer proofs, and
// VAULT_HIBP_CHECK=True let breached passwords through the registration form.
// Each of those is an operator who typed the control and got its absence, with
// no error, no log line and nothing on /readyz.
func TestLoadRefusesABooleanSpellingItCannotParse(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"transposed letters on the MFA switch", "VAULT_MFA_REQUIRED", "ture"},
		{"enabled instead of true on the breach check", "VAULT_HIBP_CHECK", "enabled"},
		{"a word for it on the DPoP switch", "VAULT_DPOP_ENABLED", "required"},
		{"a number that is not 0 or 1 on the metrics switch", "VAULT_METRICS_ENABLED", "2"},
		{"strict instead of true on the session limit", "VAULT_STRICT_SESSION_LIMIT", "strict"},
		{"always instead of true on the secure-cookie override", "VAULT_FORCE_SECURE_COOKIES", "always"},
		{"allow instead of true on the plaintext escape hatch", "VAULT_ALLOW_PLAINTEXT", "allow"},
		{"another language on the TLS switch", "VAULT_TLS_ENABLED", "ja"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv(tt.key, tt.value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted %s=%q; an unrecognized boolean must refuse to start, not mean false", tt.key, tt.value)
			}
			if !strings.Contains(err.Error(), tt.key) {
				t.Fatalf("error %q does not name %s, so the operator cannot tell which variable is wrong", err, tt.key)
			}
		})
	}
}

// Every spelling an operator plausibly writes must resolve to the value they
// wrote, not to false. Helm renders booleans lowercase, but hand-written
// manifests, systemd unit files and docker run lines carry "True", "yes" and
// "on", and each of those used to disable the control it was turning on.
func TestBooleanEnvironmentVariablesAcceptEverySpellingAnOperatorWrites(t *testing.T) {
	trueValues := []string{"true", "True", "TRUE", "t", "1", "yes", "YES", "y", "on", "ON", " true "}
	falseValues := []string{"false", "False", "FALSE", "f", "0", "no", "NO", "n", "off", "OFF", " false "}

	for _, v := range trueValues {
		t.Run("VAULT_MFA_REQUIRED="+v+" requires MFA", func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv("VAULT_MFA_REQUIRED", v)
			c, err := Load()
			if err != nil {
				t.Fatalf("Load rejected VAULT_MFA_REQUIRED=%q: %v", v, err)
			}
			if !c.MFARequired {
				t.Fatalf("VAULT_MFA_REQUIRED=%q left MFA optional", v)
			}
		})
	}

	for _, v := range falseValues {
		t.Run("VAULT_MFA_REQUIRED="+v+" does not require MFA", func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv("VAULT_MFA_REQUIRED", v)
			c, err := Load()
			if err != nil {
				t.Fatalf("Load rejected VAULT_MFA_REQUIRED=%q: %v", v, err)
			}
			if c.MFARequired {
				t.Fatalf("VAULT_MFA_REQUIRED=%q required MFA", v)
			}
		})
	}
}

// The two parsers in this package used to disagree: Load read the value with
// envBool ("true"/"1"/"yes") and the profile defaults re-read it with
// strconv.ParseBool ("true"/"1"/"t"/"TRUE"…). VAULT_AUTO_MIGRATE=no reached the
// embedded profile as an unparseable value, took the profile default, and the
// process ran migrations with the vault_mig role against a database the
// operator had told it to leave alone.
//
// The dev profile is left out on purpose: docs/config.md records that it sets
// auto-migration unconditionally.
func TestAnExplicitFalseIsHonoredByEveryProfileDefault(t *testing.T) {
	for _, profile := range []string{"embedded", "production", "honeypot"} {
		t.Run(profile+" honors VAULT_AUTO_MIGRATE=no", func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", profile)
			t.Setenv("VAULT_AUTO_MIGRATE", "no")
			c, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if c.AutoMigrate {
				t.Fatalf("%s profile ran with AutoMigrate on after VAULT_AUTO_MIGRATE=no", profile)
			}
		})
	}
}

// An empty value is the same as an unset one: Helm renders a null value as ""
// and a profile default must still apply. Treating "" as a parse failure would
// turn every chart that leaves an optional boolean unset into a boot loop.
func TestAnEmptyBooleanValueLeavesTheProfileDefaultInPlace(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "production")
	t.Setenv("VAULT_TLS_ENABLED", "")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load rejected an empty VAULT_TLS_ENABLED: %v", err)
	}
	if !c.TLSEnabled {
		t.Fatal("an empty VAULT_TLS_ENABLED dropped the production TLS default")
	}
}
