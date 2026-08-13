package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// RPHost
// ---------------------------------------------------------------------------

func TestRPHost(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   string
	}{
		{"https simple", "https://example.com", "example.com"},
		{"https with port", "https://sub.example.com:8080", "sub.example.com"},
		{"http scheme", "http://localhost:3000", "localhost"},
		{"bare hostname", "https://auth.vault.io", "auth.vault.io"},
		{"with path", "https://example.com/callback", "example.com"},
		{"empty origin falls back", "", "localhost"},
		{"invalid URL falls back", "://broken", "localhost"},
		{"just hostname no scheme", "example.com", ""},
		// url.Parse("example.com") sets path="example.com", hostname=""
		// so RPHost returns "localhost"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Origin: tt.origin}
			got := c.RPHost()
			// For the "just hostname" case, url.Parse produces empty hostname
			if tt.name == "just hostname no scheme" {
				if got != "localhost" {
					t.Errorf("RPHost() = %q, want %q (fallback for schemeless)", got, "localhost")
				}
				return
			}
			if got != tt.want {
				t.Errorf("RPHost() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// LoadSecretOptional
// ---------------------------------------------------------------------------

func TestLoadSecretOptionalNotSet(t *testing.T) {
	// No env var set at all -> returns empty string, no error
	val := LoadSecretOptional("NONEXISTENT_OPT_SECRET")
	if val != "" {
		t.Errorf("LoadSecretOptional (unset) = %q, want empty", val)
	}
}

func TestLoadSecretOptionalWithFile(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "opt_secret")
	if err := os.WriteFile(secretFile, []byte("optional-val\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPT_TEST_FILE", secretFile)

	val := LoadSecretOptional("OPT_TEST")
	if val != "optional-val" {
		t.Errorf("LoadSecretOptional = %q, want %q", val, "optional-val")
	}
}

func TestLoadSecretOptionalMissingFile(t *testing.T) {
	// Env var set but file does not exist -> returns empty string (swallows error)
	t.Setenv("OPT_MISSING_FILE", "/nonexistent/path/secret")
	val := LoadSecretOptional("OPT_MISSING")
	if val != "" {
		t.Errorf("LoadSecretOptional (missing file) = %q, want empty", val)
	}
}

// ---------------------------------------------------------------------------
// envInt
// ---------------------------------------------------------------------------

func TestEnvInt(t *testing.T) {
	tests := []struct {
		name string
		val  string // env var value ("" means unset)
		def  int
		want int
	}{
		{"valid positive", "42", 0, 42},
		{"valid negative", "-5", 0, -5},
		{"valid zero", "0", 99, 0},
		{"empty uses default", "", 99, 99},
		{"non-numeric uses default", "abc", 10, 10},
		{"float uses default", "3.14", 10, 10},
		{"spaces uses default", " 7 ", 10, 10},
		{"large number", "999999", 0, 999999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "TEST_ENV_INT_" + tt.name
			if tt.val != "" || tt.name == "empty uses default" {
				t.Setenv(key, tt.val)
			}
			got := envInt(key, tt.def)
			if got != tt.want {
				t.Errorf("envInt(%q, %d) = %d, want %d", tt.val, tt.def, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// envDuration
// ---------------------------------------------------------------------------

func TestEnvDuration(t *testing.T) {
	tests := []struct {
		name string
		val  string
		def  time.Duration
		want time.Duration
	}{
		{"valid 5m", "5m", 0, 5 * time.Minute},
		{"valid 1h", "1h", 0, time.Hour},
		{"valid 30s", "30s", 0, 30 * time.Second},
		{"valid 250ms", "250ms", 0, 250 * time.Millisecond},
		{"empty uses default", "", 10 * time.Second, 10 * time.Second},
		{"invalid string uses default", "not-a-duration", 10 * time.Second, 10 * time.Second},
		{"just a number uses default", "42", 5 * time.Minute, 5 * time.Minute},
		{"zero duration", "0s", time.Hour, 0},
		{"negative duration", "-5m", 0, -5 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "TEST_ENV_DUR_" + tt.name
			if tt.val != "" || tt.name == "empty uses default" {
				t.Setenv(key, tt.val)
			}
			got := envDuration(key, tt.def)
			if got != tt.want {
				t.Errorf("envDuration(%q, %v) = %v, want %v", tt.val, tt.def, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// envBool
// ---------------------------------------------------------------------------

func TestEnvBool(t *testing.T) {
	tests := []struct {
		name string
		val  string
		want bool
	}{
		{"true", "true", true},
		{"1", "1", true},
		{"yes", "yes", true},
		{"false", "false", false},
		{"0", "0", false},
		{"empty", "", false},
		{"random string", "on", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "TEST_ENV_BOOL_" + tt.name
			t.Setenv(key, tt.val)
			got := envBool(key)
			if got != tt.want {
				t.Errorf("envBool(%q) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// envBoolDefault
// ---------------------------------------------------------------------------

func TestEnvBoolDefault(t *testing.T) {
	tests := []struct {
		name string
		val  string
		def  bool
		want bool
	}{
		{"empty returns default true", "", true, true},
		{"empty returns default false", "", false, false},
		{"true overrides", "true", false, true},
		{"false overrides", "false", true, false},
		{"1 is true", "1", false, true},
		{"no is false", "no", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "TEST_ENV_BOOLDEF_" + tt.name
			t.Setenv(key, tt.val)
			got := envBoolDefault(key, tt.def)
			if got != tt.want {
				t.Errorf("envBoolDefault(%q, %v) = %v, want %v", tt.val, tt.def, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// envOr
// ---------------------------------------------------------------------------

func TestEnvOr(t *testing.T) {
	t.Run("set returns value", func(t *testing.T) {
		t.Setenv("TEST_ENVOR_SET", "custom")
		got := envOr("TEST_ENVOR_SET", "fallback")
		if got != "custom" {
			t.Errorf("envOr = %q, want %q", got, "custom")
		}
	})

	t.Run("unset returns fallback", func(t *testing.T) {
		got := envOr("TEST_ENVOR_UNSET_XYZZY", "fallback")
		if got != "fallback" {
			t.Errorf("envOr = %q, want %q", got, "fallback")
		}
	})
}

// ---------------------------------------------------------------------------
// redact / redactStr
// ---------------------------------------------------------------------------

func TestRedact(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"nil bytes", nil, "<not set>"},
		{"empty bytes", []byte{}, "<not set>"},
		{"non-empty bytes", []byte("secret"), "<redacted>"},
		{"single byte", []byte{0x01}, "<redacted>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redact(tt.in)
			if got != tt.want {
				t.Errorf("redact(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRedactStr(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty string", "", "<not set>"},
		{"non-empty string", "secret", "<redacted>"},
		{"short string", "x", "<redacted>"},
		{"whitespace", " ", "<redacted>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactStr(tt.in)
			if got != tt.want {
				t.Errorf("redactStr(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Config.String
// ---------------------------------------------------------------------------

func TestConfigStringNotSetSecrets(t *testing.T) {
	cfg := &Config{
		Profile:    ProfileDev,
		ListenAddr: ":8080",
		DBHost:     "localhost",
		DBPort:     "5432",
		DBName:     "vault",
	}

	str := cfg.String()
	if !strings.Contains(str, "<not set>") {
		t.Error("String() should show <not set> for unset secrets")
	}
	if strings.Contains(str, "<redacted>") {
		t.Error("String() should not show <redacted> when secrets are empty")
	}
}

// ---------------------------------------------------------------------------
// Load with secret files
// ---------------------------------------------------------------------------

func TestLoadSecretsFromFiles(t *testing.T) {
	dir := t.TempDir()

	// Create secret files
	writeSecret := func(name, value string) {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name+"_FILE", path)
	}

	t.Setenv("VAULT_PROFILE", "dev")

	writeSecret("MASTER_KEY", "01234567890123456789012345678901")
	writeSecret("VAULT_PEPPER", "pepper-value")
	writeSecret("HMAC_SECRET", "01234567890123456789012345678901") // 32 bytes
	writeSecret("DB_MIG_PASSWORD", "mig-pass")
	writeSecret("DB_APP_PASSWORD", "app-pass")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if string(cfg.MasterKey) != "01234567890123456789012345678901" {
		t.Errorf("MasterKey not loaded: %q", cfg.MasterKey)
	}
	// ADMIN_TOKEN is not in this list on purpose: cli.New owns that read. See
	// TestLoadLeavesAdminTokenFileForTheCLI.
	if cfg.Pepper != "pepper-value" {
		t.Errorf("Pepper not loaded: %q", cfg.Pepper)
	}
	if string(cfg.HMACSecret) != "01234567890123456789012345678901" {
		t.Errorf("HMACSecret not loaded: %q", cfg.HMACSecret)
	}
	if cfg.DBMigPassword != "mig-pass" {
		t.Errorf("DBMigPassword not loaded: %q", cfg.DBMigPassword)
	}
	if cfg.DBAppPassword != "app-pass" {
		t.Errorf("DBAppPassword not loaded: %q", cfg.DBAppPassword)
	}
}

// ---------------------------------------------------------------------------
// Load with HMAC secret too short (production should error)
// ---------------------------------------------------------------------------

func TestLoadHMACTooShortProduction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hmac_short")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_PROFILE", "production")
	t.Setenv("HMAC_SECRET_FILE", path)

	_, err := Load()
	if err == nil {
		t.Error("production with short HMAC secret should return error")
	}
	if err != nil && !strings.Contains(err.Error(), "HMAC secret must be at least 32 bytes") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadHMACTooShortDevAllowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hmac_short")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("HMAC_SECRET_FILE", path)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("dev with short HMAC secret should not error: %v", err)
	}
	if string(cfg.HMACSecret) != "short" {
		t.Errorf("HMACSecret = %q, want %q", cfg.HMACSecret, "short")
	}
}

// ---------------------------------------------------------------------------
// Load with trusted proxies
// ---------------------------------------------------------------------------

func TestLoadTrustedProxies(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 172.16.0.0/12, 192.168.1.1")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.TrustedProxies) != 3 {
		t.Fatalf("expected 3 trusted proxies, got %d: %v", len(cfg.TrustedProxies), cfg.TrustedProxies)
	}
	if cfg.TrustedProxies[0] != "10.0.0.0/8" {
		t.Errorf("proxy[0] = %q, want %q", cfg.TrustedProxies[0], "10.0.0.0/8")
	}
}

func TestLoadTrustedProxiesEmpty(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	// Explicitly not setting TRUSTED_PROXIES

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.TrustedProxies) != 0 {
		t.Errorf("expected no trusted proxies, got %d", len(cfg.TrustedProxies))
	}
}

// ---------------------------------------------------------------------------
// Load with custom env var overrides
// ---------------------------------------------------------------------------

func TestLoadCustomTokenTTLs(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_ACCESS_TOKEN_TTL", "10m")
	t.Setenv("VAULT_REFRESH_TOKEN_TTL", "48h")
	t.Setenv("VAULT_REMEMBER_ME_TTL", "720h")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.AccessTokenTTL != 10*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want 10m", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 48*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 48h", cfg.RefreshTokenTTL)
	}
	if cfg.RememberMeTTL != 720*time.Hour {
		t.Errorf("RememberMeTTL = %v, want 720h", cfg.RememberMeTTL)
	}
}

func TestLoadUnknownProfileFallsBackToProduction(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "staging")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Profile != ProfileProduction {
		t.Errorf("unknown profile should fall back to production, got %q", cfg.Profile)
	}
	if !cfg.TLSEnabled {
		t.Error("should have production TLS defaults")
	}
}

func TestLoadPasswordMinLengthOverride(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_PASSWORD_MIN_LENGTH", "20")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.PasswordMinLength != 20 {
		t.Errorf("PasswordMinLength = %d, want 20", cfg.PasswordMinLength)
	}
}
