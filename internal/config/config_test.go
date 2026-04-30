package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDevProfile(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Profile != ProfileDev {
		t.Errorf("profile = %q, want dev", cfg.Profile)
	}
	// Dev extends production — inherits production base values
	if cfg.ListenAddr != ":8443" {
		t.Errorf("listen = %q, want :8443 (production base)", cfg.ListenAddr)
	}
	if !cfg.TLSEnabled {
		t.Error("dev should inherit TLS enabled from production")
	}
	if !cfg.RateLimitEnabled {
		t.Error("dev should inherit rate limiting from production")
	}
	if !cfg.AutoMigrate {
		t.Error("dev profile should auto-migrate")
	}
	if cfg.CacheBackend != "redis" {
		t.Errorf("cache = %q, want redis (production base)", cfg.CacheBackend)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("log_level = %q, want debug", cfg.LogLevel)
	}
	// Dev overrides RefreshTokenTTL to 24h (shorter than production's 7d)
	if cfg.RefreshTokenTTL != 24*time.Hour {
		t.Errorf("refresh_ttl = %v, want 24h", cfg.RefreshTokenTTL)
	}
	// Dev overrides ShutdownTimeout to 5s (shorter than production's 15s)
	if cfg.ShutdownTimeout != 5*time.Second {
		t.Errorf("shutdown_timeout = %v, want 5s", cfg.ShutdownTimeout)
	}
}

func TestLoadProductionProfile(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "production")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Profile != ProfileProduction {
		t.Errorf("profile = %q, want production", cfg.Profile)
	}
	if cfg.ListenAddr != ":8443" {
		t.Errorf("listen = %q, want :8443", cfg.ListenAddr)
	}
	if !cfg.TLSEnabled {
		t.Error("production should have TLS enabled")
	}
	if !cfg.RateLimitEnabled {
		t.Error("production should have rate limiting enabled")
	}
	if cfg.AutoMigrate {
		t.Error("production should NOT auto-migrate")
	}
	if cfg.CacheBackend != "redis" {
		t.Errorf("cache = %q, want redis", cfg.CacheBackend)
	}
	if cfg.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("refresh_ttl = %v, want 7d", cfg.RefreshTokenTTL)
	}
}

func TestLoadEmbeddedProfile(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "embedded")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.DBMaxConns != 5 {
		t.Errorf("db_max_conns = %d, want 5", cfg.DBMaxConns)
	}
	if cfg.AuditFlushInterval != 30*time.Second {
		t.Errorf("audit_flush = %v, want 30s", cfg.AuditFlushInterval)
	}
}

func TestLoadSecretFileAndZero(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "test_secret")
	secretValue := "super-secret-value-123"

	err := os.WriteFile(secretFile, []byte(secretValue+"\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("TEST_KEY_FILE", secretFile)

	val, err := LoadSecret("TEST_KEY")
	if err != nil {
		t.Fatal(err)
	}

	if val != secretValue {
		t.Errorf("secret = %q, want %q", val, secretValue)
	}

	// Verify file was deleted after reading
	if _, err := os.Stat(secretFile); !os.IsNotExist(err) {
		t.Error("secret file should be deleted after reading")
	}
}

func TestLoadSecretMissingEnvVar(t *testing.T) {
	_, err := LoadSecret("NONEXISTENT_VAR")
	if err == nil {
		t.Error("missing env var should return error")
	}
}

func TestLoadSecretMissingFile(t *testing.T) {
	t.Setenv("MISSING_FILE_FILE", "/nonexistent/path/secret")
	_, err := LoadSecret("MISSING_FILE")
	if err == nil {
		t.Error("missing file should return error")
	}
}

func TestConfigStringRedactsSecrets(t *testing.T) {
	cfg := &Config{
		Profile:        ProfileDev,
		ListenAddr:     ":8080",
		MasterKey:      []byte("super-secret-key-32-bytes-long!!"),
		AdminTokenHash: "$argon2id$...",
		Pepper:         "pepper-value",
		HMACSecret:     []byte("hmac-secret"),
		DBHost:         "localhost",
		DBPort:         "5432",
		DBName:         "vault",
		CacheBackend:   "memory",
	}

	str := cfg.String()

	// Should NOT contain actual secret values
	if strings.Contains(str, "super-secret") {
		t.Error("String() should not contain master key")
	}
	if strings.Contains(str, "argon2id") {
		t.Error("String() should not contain admin token hash")
	}
	if strings.Contains(str, "pepper-value") {
		t.Error("String() should not contain pepper")
	}
	if strings.Contains(str, "hmac-secret") {
		t.Error("String() should not contain HMAC secret")
	}

	// Should contain <redacted> for set secrets
	if !strings.Contains(str, "<redacted>") {
		t.Error("String() should show <redacted> for set secrets")
	}
}

func TestEnvOverridesProfileDefaults(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("LISTEN_ADDR", ":9999")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ListenAddr != ":9999" {
		t.Errorf("explicit env should override profile default: got %q", cfg.ListenAddr)
	}
}

func TestDatabaseURL(t *testing.T) {
	cfg := &Config{
		Profile:       ProfileDev,
		DBHost:        "postgres",
		DBPort:        "5432",
		DBName:        "vault",
		DBSSLMode:     "require",
		DBMigPassword: "mig-pass",
		DBAppPassword: "app-pass",
	}

	migURL := cfg.DatabaseURL("migration")
	if !strings.Contains(migURL, "vault_mig") {
		t.Error("migration URL should use vault_mig role")
	}
	if !strings.Contains(migURL, "mig-pass") {
		t.Error("migration URL should use mig password")
	}
	// Dev profile forces sslmode=disable
	if !strings.Contains(migURL, "sslmode=disable") {
		t.Error("dev profile should force sslmode=disable")
	}

	appURL := cfg.DatabaseURL("app")
	if !strings.Contains(appURL, "vault_app") {
		t.Error("app URL should use vault_app role")
	}
}

func TestPasswordMinLengthDefault(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	cfg, _ := Load()
	if cfg.PasswordMinLength != 15 {
		t.Errorf("default password min length = %d, want 15", cfg.PasswordMinLength)
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte("secret")
	ZeroBytes(b)
	for _, v := range b {
		if v != 0 {
			t.Error("ZeroBytes should zero all bytes")
			break
		}
	}
}

func TestDPoPEnabledDefault(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "production")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DPoPEnabled {
		t.Error("DPoPEnabled should default to false")
	}
}

func TestDPoPEnabledFromEnv(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "production")
	t.Setenv("VAULT_DPOP_ENABLED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DPoPEnabled {
		t.Error("DPoPEnabled should be true when VAULT_DPOP_ENABLED=true")
	}
}
