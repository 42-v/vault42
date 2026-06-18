package config

import (
	"strings"
	"testing"
)

// M7: VAULT_EMBEDDED_TRUSTED_UPSTREAM auto-trusts whole private + loopback ranges
// and blindly honours X-Forwarded-For. It must be rejected outside the embedded
// profile so a misconfigured production deploy is caught at startup.
func TestEmbeddedTrustedUpstream_RejectedOutsideEmbedded(t *testing.T) {
	for _, prof := range []string{"production", "dev", "honeypot"} {
		t.Run(prof, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", prof)
			t.Setenv("VAULT_EMBEDDED_TRUSTED_UPSTREAM", "true")
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "embedded profile") {
				t.Fatalf("expected embedded-profile rejection in %s, got %v", prof, err)
			}
		})
	}
}
