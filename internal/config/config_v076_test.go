package config

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Load — invalid primary color rejected
// ---------------------------------------------------------------------------

func TestLoadInvalidPrimaryColor(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_PRIMARY_COLOR", "not-a-color")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid primary color")
	}
	if !contains(err.Error(), "VAULT_PRIMARY_COLOR") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Load — list-valued env vars are parsed into slices
// ---------------------------------------------------------------------------

func TestLoadListEnvVars(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_HONEYPOT_TRAP_USERS", "Admin, ROOT ,")
	t.Setenv("IP_ALLOWLIST", "10.0.0.0/8, 1.2.3.4")
	t.Setenv("IP_BLOCKLIST", "9.9.9.9")
	t.Setenv("GEO_ALLOWLIST", "us, ca")
	t.Setenv("GEO_BLOCKLIST", "ru")
	t.Setenv("REAL_IP_HEADER", " CF-Connecting-IP ")
	t.Setenv("GEO_IP_HEADER", " CF-IPCountry ")
	t.Setenv("VAULT_TLS_FINGERPRINT_HEADER", " X-JA4 ")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// Trap users lowercased, blanks dropped.
	if len(cfg.HoneypotTrapUsers) != 2 || cfg.HoneypotTrapUsers[0] != "admin" || cfg.HoneypotTrapUsers[1] != "root" {
		t.Errorf("HoneypotTrapUsers = %v", cfg.HoneypotTrapUsers)
	}
	if len(cfg.IPAllowlist) != 2 || cfg.IPAllowlist[1] != "1.2.3.4" {
		t.Errorf("IPAllowlist = %v", cfg.IPAllowlist)
	}
	if len(cfg.IPBlocklist) != 1 || cfg.IPBlocklist[0] != "9.9.9.9" {
		t.Errorf("IPBlocklist = %v", cfg.IPBlocklist)
	}
	// Geo codes uppercased.
	if len(cfg.GeoAllowlist) != 2 || cfg.GeoAllowlist[0] != "US" {
		t.Errorf("GeoAllowlist = %v", cfg.GeoAllowlist)
	}
	if len(cfg.GeoBlocklist) != 1 || cfg.GeoBlocklist[0] != "RU" {
		t.Errorf("GeoBlocklist = %v", cfg.GeoBlocklist)
	}
	// Headers trimmed.
	if cfg.RealIPHeader != "CF-Connecting-IP" {
		t.Errorf("RealIPHeader = %q", cfg.RealIPHeader)
	}
	if cfg.GeoIPHeader != "CF-IPCountry" {
		t.Errorf("GeoIPHeader = %q", cfg.GeoIPHeader)
	}
	if cfg.TLSFingerprintHeader != "X-JA4" {
		t.Errorf("TLSFingerprintHeader = %q", cfg.TLSFingerprintHeader)
	}
}

// ---------------------------------------------------------------------------
// Load — embedded-trust shortcut auto-fills RealIPHeader when unset
// ---------------------------------------------------------------------------

func TestLoadEmbeddedTrustDefaultsRealIPHeader(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_EMBEDDED_TRUSTED_UPSTREAM", "true")
	// REAL_IP_HEADER deliberately unset so the default kicks in.

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxies) == 0 {
		t.Fatal("expected RFC1918 proxies to be auto-filled")
	}
	if cfg.RealIPHeader != "X-Forwarded-For" {
		t.Errorf("RealIPHeader = %q, want X-Forwarded-For", cfg.RealIPHeader)
	}
}

// ---------------------------------------------------------------------------
// loadSecrets — every secret-file branch populates its field
// ---------------------------------------------------------------------------

func TestLoadSecretsAllFields(t *testing.T) {
	dir := t.TempDir()
	writeSecret := func(name, value string) {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name+"_FILE", path)
	}

	t.Setenv("VAULT_PROFILE", "dev")

	writeSecret("REDIS_PASS", "redis-secret")
	writeSecret("SMTP_USER", "smtp-user")
	writeSecret("SMTP_PASS", "smtp-pass")
	writeSecret("SENDGRID_API_KEY", "sg-key")
	writeSecret("VAULT_OAUTH_GOOGLE_CLIENT_SECRET", "google-secret")
	writeSecret("VAULT_OAUTH_GITHUB_CLIENT_SECRET", "github-secret")
	writeSecret("VAULT_OAUTH_FACEBOOK_CLIENT_SECRET", "facebook-secret")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"RedisPass":                 cfg.RedisPass,
		"SMTPUser":                  cfg.SMTPUser,
		"SMTPPass":                  cfg.SMTPPass,
		"SendGridAPIKey":            cfg.SendGridAPIKey,
		"OAuthGoogleClientSecret":   cfg.OAuthGoogleClientSecret,
		"OAuthGitHubClientSecret":   cfg.OAuthGitHubClientSecret,
		"OAuthFacebookClientSecret": cfg.OAuthFacebookClientSecret,
	}
	wants := map[string]string{
		"RedisPass":                 "redis-secret",
		"SMTPUser":                  "smtp-user",
		"SMTPPass":                  "smtp-pass",
		"SendGridAPIKey":            "sg-key",
		"OAuthGoogleClientSecret":   "google-secret",
		"OAuthGitHubClientSecret":   "github-secret",
		"OAuthFacebookClientSecret": "facebook-secret",
	}
	for field, got := range cases {
		if got != wants[field] {
			t.Errorf("%s = %q, want %q", field, got, wants[field])
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
