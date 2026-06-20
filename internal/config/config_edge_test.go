package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Profile defaults
// ---------------------------------------------------------------------------

func TestProfileDefaults_Production(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "production")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("listen addr", func(t *testing.T) {
		if cfg.ListenAddr != ":8443" {
			t.Errorf("ListenAddr = %q, want :8443", cfg.ListenAddr)
		}
	})

	t.Run("log level", func(t *testing.T) {
		if cfg.LogLevel != "warn" {
			t.Errorf("LogLevel = %q, want warn", cfg.LogLevel)
		}
	})

	t.Run("TLS enabled", func(t *testing.T) {
		if !cfg.TLSEnabled {
			t.Error("TLS should be enabled in production")
		}
	})

	t.Run("rate limit enabled", func(t *testing.T) {
		if !cfg.RateLimitEnabled {
			t.Error("rate limiting should be enabled in production")
		}
	})

	t.Run("auto migrate disabled", func(t *testing.T) {
		if cfg.AutoMigrate {
			t.Error("auto-migrate should be disabled in production")
		}
	})

	t.Run("CORS allow all forced off", func(t *testing.T) {
		if cfg.CORSAllowAll {
			t.Error("CORSAllowAll should be forced off in production")
		}
	})

	t.Run("cache backend is redis", func(t *testing.T) {
		if cfg.CacheBackend != "redis" {
			t.Errorf("CacheBackend = %q, want redis", cfg.CacheBackend)
		}
	})

	t.Run("DB max conns is 25", func(t *testing.T) {
		if cfg.DBMaxConns != 25 {
			t.Errorf("DBMaxConns = %d, want 25", cfg.DBMaxConns)
		}
	})

	t.Run("shutdown timeout is 15s", func(t *testing.T) {
		if cfg.ShutdownTimeout != 15*time.Second {
			t.Errorf("ShutdownTimeout = %v, want 15s", cfg.ShutdownTimeout)
		}
	})

	t.Run("refresh token TTL is 7 days", func(t *testing.T) {
		if cfg.RefreshTokenTTL != 7*24*time.Hour {
			t.Errorf("RefreshTokenTTL = %v, want 168h", cfg.RefreshTokenTTL)
		}
	})

	t.Run("access token TTL is 15m", func(t *testing.T) {
		if cfg.AccessTokenTTL != 15*time.Minute {
			t.Errorf("AccessTokenTTL = %v, want 15m", cfg.AccessTokenTTL)
		}
	})
}

func TestProfileDefaults_Embedded(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "embedded")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("listen addr", func(t *testing.T) {
		if cfg.ListenAddr != ":8443" {
			t.Errorf("ListenAddr = %q, want :8443", cfg.ListenAddr)
		}
	})

	t.Run("log level is info", func(t *testing.T) {
		if cfg.LogLevel != "info" {
			t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
		}
	})

	t.Run("TLS enabled", func(t *testing.T) {
		if !cfg.TLSEnabled {
			t.Error("TLS should be enabled in embedded")
		}
	})

	t.Run("rate limit enabled", func(t *testing.T) {
		if !cfg.RateLimitEnabled {
			t.Error("rate limiting should be enabled in embedded")
		}
	})

	t.Run("auto migrate enabled", func(t *testing.T) {
		if !cfg.AutoMigrate {
			t.Error("auto-migrate should be enabled in embedded")
		}
	})

	t.Run("cache backend is memory", func(t *testing.T) {
		if cfg.CacheBackend != "memory" {
			t.Errorf("CacheBackend = %q, want memory", cfg.CacheBackend)
		}
	})

	t.Run("DB max conns is 5", func(t *testing.T) {
		if cfg.DBMaxConns != 5 {
			t.Errorf("DBMaxConns = %d, want 5", cfg.DBMaxConns)
		}
	})

	t.Run("audit flush interval is 30s", func(t *testing.T) {
		if cfg.AuditFlushInterval != 30*time.Second {
			t.Errorf("AuditFlushInterval = %v, want 30s", cfg.AuditFlushInterval)
		}
	})

	t.Run("shutdown timeout is 5s", func(t *testing.T) {
		if cfg.ShutdownTimeout != 5*time.Second {
			t.Errorf("ShutdownTimeout = %v, want 5s", cfg.ShutdownTimeout)
		}
	})
}

func TestProfileDefaults_Dev(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// Dev extends production — inherits production base values
	t.Run("listen addr from production", func(t *testing.T) {
		if cfg.ListenAddr != ":8443" {
			t.Errorf("ListenAddr = %q, want :8443 (production base)", cfg.ListenAddr)
		}
	})

	t.Run("log level is debug", func(t *testing.T) {
		if cfg.LogLevel != "debug" {
			t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
		}
	})

	t.Run("TLS enabled from production", func(t *testing.T) {
		if !cfg.TLSEnabled {
			t.Error("dev should inherit TLS enabled from production")
		}
	})

	t.Run("CORS allow all enabled", func(t *testing.T) {
		if !cfg.CORSAllowAll {
			t.Error("CORSAllowAll should be enabled in dev")
		}
	})

	t.Run("rate limit enabled from production", func(t *testing.T) {
		if !cfg.RateLimitEnabled {
			t.Error("dev should inherit rate limiting from production")
		}
	})

	t.Run("auto migrate enabled", func(t *testing.T) {
		if !cfg.AutoMigrate {
			t.Error("auto-migrate should be enabled in dev")
		}
	})

	t.Run("cache backend is redis from production", func(t *testing.T) {
		if cfg.CacheBackend != "redis" {
			t.Errorf("CacheBackend = %q, want redis (production base)", cfg.CacheBackend)
		}
	})

	t.Run("DB max conns is 25 from production", func(t *testing.T) {
		if cfg.DBMaxConns != 25 {
			t.Errorf("DBMaxConns = %d, want 25 (production base)", cfg.DBMaxConns)
		}
	})

	t.Run("shutdown timeout is 5s", func(t *testing.T) {
		if cfg.ShutdownTimeout != 5*time.Second {
			t.Errorf("ShutdownTimeout = %v, want 5s", cfg.ShutdownTimeout)
		}
	})

	t.Run("refresh token TTL is 24h", func(t *testing.T) {
		if cfg.RefreshTokenTTL != 24*time.Hour {
			t.Errorf("RefreshTokenTTL = %v, want 24h", cfg.RefreshTokenTTL)
		}
	})
}

// ---------------------------------------------------------------------------
// Unknown profile falls back to production
// ---------------------------------------------------------------------------

func TestProfileDefaults_UnknownProfile(t *testing.T) {
	unknowns := []string{"staging", "testing", "qa", "sandbox", "", "PRODUCTION", "Dev"}

	for _, profile := range unknowns {
		t.Run("profile "+profile, func(t *testing.T) {
			// For empty profile, applyProfileDefaults defaults it
			if profile == "" {
				t.Setenv("VAULT_PROFILE", "")
				// envOr returns "production" for empty env var
				cfg, err := Load()
				if err != nil {
					t.Fatal(err)
				}
				if cfg.Profile != ProfileProduction {
					t.Errorf("empty profile should be production, got %q", cfg.Profile)
				}
				return
			}
			t.Setenv("VAULT_PROFILE", profile)
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Profile != ProfileProduction {
				t.Errorf("profile %q should fall back to production, got %q", profile, cfg.Profile)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Env var edge cases
// ---------------------------------------------------------------------------

func TestEnvVar_WhitespaceValues(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_PASSWORD_MIN_LENGTH", " ")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("whitespace password min length falls back to default", func(t *testing.T) {
		if cfg.PasswordMinLength != 15 {
			t.Errorf("PasswordMinLength = %d, want 15 (default)", cfg.PasswordMinLength)
		}
	})
}

func TestEnvVar_InvalidDurationFallback(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_ACCESS_TOKEN_TTL", "invalid-duration")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("invalid duration uses profile default", func(t *testing.T) {
		if cfg.AccessTokenTTL != 15*time.Minute {
			t.Errorf("AccessTokenTTL = %v, want 15m (profile default)", cfg.AccessTokenTTL)
		}
	})
}

func TestEnvVar_InvalidIntFallback(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_PASSWORD_MIN_LENGTH", "not-a-number")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("invalid int uses default", func(t *testing.T) {
		if cfg.PasswordMinLength != 15 {
			t.Errorf("PasswordMinLength = %d, want 15", cfg.PasswordMinLength)
		}
	})
}

func TestEnvVar_BoolVariations(t *testing.T) {
	trueValues := []string{"true", "1", "yes", ""} // "" defaults to true (envBoolDefault)
	falseValues := []string{"false", "0", "no", "off", "on", "TRUE", "YES"}

	for _, val := range trueValues {
		t.Run("VAULT_MFA_REQUIRED="+val, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv("VAULT_MFA_REQUIRED", val)
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.MFARequired {
				t.Errorf("MFARequired should be true for %q", val)
			}
		})
	}

	for _, val := range falseValues {
		t.Run("VAULT_MFA_REQUIRED="+val+" is false", func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv("VAULT_MFA_REQUIRED", val)
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MFARequired {
				t.Errorf("MFARequired should be false for %q", val)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Secret file loading edge cases
// ---------------------------------------------------------------------------

func TestLoadSecret_WhitespaceTrimmingEdgeCases(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"trailing newline", "secret\n", "secret"},
		{"trailing CR+LF", "secret\r\n", "secret"},
		{"leading and trailing spaces", "  secret  ", "secret"},
		{"only whitespace", "   \n\t  ", ""},
		{"embedded newlines preserved in trim", "sec\nret", "sec\nret"},
		{"tabs around value", "\tsecret\t", "secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, "secret_"+tt.name)
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			envKey := "TEST_TRIM_" + strings.ReplaceAll(tt.name, " ", "_")
			t.Setenv(envKey+"_FILE", path)

			val, err := LoadSecret(envKey)
			if err != nil {
				t.Fatal(err)
			}
			if val != tt.want {
				t.Errorf("got %q, want %q", val, tt.want)
			}
		})
	}
}

func TestLoadSecret_FileZeroedAfterRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zeroed_secret")
	secret := "my-critical-secret-value"
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZEROED_TEST_FILE", path)
	t.Setenv("VAULT_SECRET_FILE_CONSUME", "true") // opt into the destructive wipe (L5)

	val, err := LoadSecret("ZEROED_TEST")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("secret value is correct", func(t *testing.T) {
		if val != secret {
			t.Errorf("got %q, want %q", val, secret)
		}
	})

	t.Run("file is deleted after reading", func(t *testing.T) {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("secret file should be deleted after reading, but still exists")
		}
	})
}

func TestLoadSecret_NonExistentFile(t *testing.T) {
	t.Setenv("NOFILE_TEST_FILE", "/tmp/definitely-does-not-exist-vault-test")

	_, err := LoadSecret("NOFILE_TEST")

	t.Run("returns error", func(t *testing.T) {
		if err == nil {
			t.Error("missing file should return error")
		}
	})
}

func TestLoadSecret_EnvVarNotSet(t *testing.T) {
	_, err := LoadSecret("COMPLETELY_UNSET_VAR_XYZ")

	t.Run("returns error about _FILE not set", func(t *testing.T) {
		if err == nil {
			t.Error("unset env var should return error")
		}
		if !strings.Contains(err.Error(), "_FILE not set") {
			t.Errorf("error = %q, should mention _FILE not set", err.Error())
		}
	})
}

// ---------------------------------------------------------------------------
// Database URL
// ---------------------------------------------------------------------------

func TestDatabaseURL_DevForcesSSLDisable(t *testing.T) {
	cfg := &Config{
		Profile:       ProfileDev,
		DBHost:        "localhost",
		DBPort:        "5432",
		DBName:        "vault",
		DBSSLMode:     "verify-full",
		DBAppPassword: "pass",
	}

	url := cfg.DatabaseURL("app")

	t.Run("dev forces sslmode=disable", func(t *testing.T) {
		if !strings.Contains(url, "sslmode=disable") {
			t.Errorf("url = %q, should contain sslmode=disable in dev", url)
		}
	})
}

func TestDatabaseURL_ProductionPreservesSSLMode(t *testing.T) {
	cfg := &Config{
		Profile:       ProfileProduction,
		DBHost:        "db.prod.com",
		DBPort:        "5432",
		DBName:        "vault",
		DBSSLMode:     "verify-full",
		DBAppPassword: "pass",
	}

	url := cfg.DatabaseURL("app")

	t.Run("production preserves sslmode", func(t *testing.T) {
		if !strings.Contains(url, "sslmode=verify-full") {
			t.Errorf("url = %q, should contain sslmode=verify-full", url)
		}
	})
}

func TestDatabaseURL_MigrationRole(t *testing.T) {
	cfg := &Config{
		Profile:       ProfileProduction,
		DBHost:        "db.prod.com",
		DBPort:        "5432",
		DBName:        "vault",
		DBSSLMode:     "require",
		DBMigPassword: "mig-secret",
	}

	url := cfg.DatabaseURL("migration")

	t.Run("uses vault_mig user", func(t *testing.T) {
		if !strings.Contains(url, "vault_mig") {
			t.Errorf("url = %q, should contain vault_mig", url)
		}
	})

	t.Run("uses migration password", func(t *testing.T) {
		if !strings.Contains(url, "mig-secret") {
			t.Errorf("url = %q, should contain mig-secret", url)
		}
	})
}

func TestDatabaseURL_AppRole(t *testing.T) {
	cfg := &Config{
		Profile:       ProfileProduction,
		DBHost:        "db.prod.com",
		DBPort:        "5432",
		DBName:        "vault",
		DBSSLMode:     "require",
		DBAppPassword: "app-secret",
	}

	url := cfg.DatabaseURL("app")

	t.Run("uses vault_app user", func(t *testing.T) {
		if !strings.Contains(url, "vault_app") {
			t.Errorf("url = %q, should contain vault_app", url)
		}
	})

	t.Run("uses app password", func(t *testing.T) {
		if !strings.Contains(url, "app-secret") {
			t.Errorf("url = %q, should contain app-secret", url)
		}
	})
}

// ---------------------------------------------------------------------------
// RPHost edge cases
// ---------------------------------------------------------------------------

func TestRPHost_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   string
	}{
		{"IP address origin", "https://192.168.1.1:8080", "192.168.1.1"},
		{"IPv6 origin", "https://[::1]:8443", "::1"},
		{"subdomain chain", "https://a.b.c.d.example.com", "a.b.c.d.example.com"},
		{"port 443", "https://auth.vault.io:443", "auth.vault.io"},
		{"empty string", "", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Origin: tt.origin}
			got := c.RPHost()
			if got != tt.want {
				t.Errorf("RPHost() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ZeroBytes and ZeroString
// ---------------------------------------------------------------------------

func TestZeroBytes_Various(t *testing.T) {
	t.Run("zeroes all bytes", func(t *testing.T) {
		b := []byte("sensitive-data-12345")
		ZeroBytes(b)
		for i, v := range b {
			if v != 0 {
				t.Errorf("byte %d = %d, want 0", i, v)
			}
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		b := []byte{}
		ZeroBytes(b)
		// Should not panic
		if len(b) != 0 {
			t.Error("expected empty slice")
		}
	})

	t.Run("nil slice", func(t *testing.T) {
		var b []byte
		ZeroBytes(b)
		// Should not panic
	})

	t.Run("single byte", func(t *testing.T) {
		b := []byte{0xFF}
		ZeroBytes(b)
		if b[0] != 0 {
			t.Errorf("byte = %d, want 0", b[0])
		}
	})
}

func TestZeroString_Various(t *testing.T) {
	t.Run("clears string", func(t *testing.T) {
		s := "sensitive"
		ZeroString(&s)
		if s != "" {
			t.Errorf("string should be empty, got %q", s)
		}
	})

	t.Run("already empty", func(t *testing.T) {
		s := ""
		ZeroString(&s)
		if s != "" {
			t.Errorf("string should remain empty, got %q", s)
		}
	})
}

// ---------------------------------------------------------------------------
// Config.String output format
// ---------------------------------------------------------------------------

func TestConfigString_ContainsProfile(t *testing.T) {
	cfg := &Config{
		Profile:    ProfileDev,
		ListenAddr: ":8080",
		DBHost:     "localhost",
		DBPort:     "5432",
		DBName:     "vault",
	}

	str := cfg.String()

	t.Run("contains profile", func(t *testing.T) {
		if !strings.Contains(str, "profile=dev") {
			t.Errorf("String() = %q, should contain profile=dev", str)
		}
	})

	t.Run("contains listen addr", func(t *testing.T) {
		if !strings.Contains(str, "listen=:8080") {
			t.Errorf("String() = %q, should contain listen=:8080", str)
		}
	})

	t.Run("contains db info", func(t *testing.T) {
		if !strings.Contains(str, "db=localhost:5432/vault") {
			t.Errorf("String() = %q, should contain db info", str)
		}
	})

	t.Run("contains TTL info", func(t *testing.T) {
		if !strings.Contains(str, "access_ttl=") {
			t.Errorf("String() = %q, should contain access_ttl", str)
		}
	})
}

// ---------------------------------------------------------------------------
// Trusted proxies parsing
// ---------------------------------------------------------------------------

func TestTrustedProxies_Parsing(t *testing.T) {
	t.Run("single IP", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "dev")
		t.Setenv("TRUSTED_PROXIES", "10.0.0.1")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.TrustedProxies) != 1 || cfg.TrustedProxies[0] != "10.0.0.1" {
			t.Errorf("TrustedProxies = %v, want [10.0.0.1]", cfg.TrustedProxies)
		}
	})

	t.Run("multiple with extra spaces", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "dev")
		t.Setenv("TRUSTED_PROXIES", "  10.0.0.0/8 , 172.16.0.0/12 , 192.168.0.0/16  ")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.TrustedProxies) != 3 {
			t.Fatalf("expected 3 proxies, got %d: %v", len(cfg.TrustedProxies), cfg.TrustedProxies)
		}
		if cfg.TrustedProxies[0] != "10.0.0.0/8" {
			t.Errorf("proxy[0] = %q, want 10.0.0.0/8", cfg.TrustedProxies[0])
		}
	})

	t.Run("trailing comma ignored", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "dev")
		t.Setenv("TRUSTED_PROXIES", "10.0.0.1,")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.TrustedProxies) != 1 {
			t.Errorf("expected 1 proxy, got %d: %v", len(cfg.TrustedProxies), cfg.TrustedProxies)
		}
	})

	t.Run("empty value means no proxies", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "dev")
		// Not setting TRUSTED_PROXIES
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.TrustedProxies) != 0 {
			t.Errorf("expected 0 proxies, got %d", len(cfg.TrustedProxies))
		}
	})
}

// ---------------------------------------------------------------------------
// DB defaults
// ---------------------------------------------------------------------------

func TestDBDefaults(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("host defaults to localhost", func(t *testing.T) {
		if cfg.DBHost != "localhost" {
			t.Errorf("DBHost = %q, want localhost", cfg.DBHost)
		}
	})

	t.Run("port defaults to 5432", func(t *testing.T) {
		if cfg.DBPort != "5432" {
			t.Errorf("DBPort = %q, want 5432", cfg.DBPort)
		}
	})

	t.Run("name defaults to vault", func(t *testing.T) {
		if cfg.DBName != "vault" {
			t.Errorf("DBName = %q, want vault", cfg.DBName)
		}
	})

	t.Run("sslmode defaults to require", func(t *testing.T) {
		if cfg.DBSSLMode != "require" {
			t.Errorf("DBSSLMode = %q, want require", cfg.DBSSLMode)
		}
	})
}

// ---------------------------------------------------------------------------
// HIBP check default
// ---------------------------------------------------------------------------

func TestHIBPCheckDefault(t *testing.T) {
	t.Run("defaults to true", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "dev")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.HIBPCheck {
			t.Error("HIBPCheck should default to true")
		}
	})

	t.Run("can be disabled", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "dev")
		t.Setenv("VAULT_HIBP_CHECK", "false")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.HIBPCheck {
			t.Error("HIBPCheck should be false when set to false")
		}
	})
}

// ---------------------------------------------------------------------------
// Branding defaults
// ---------------------------------------------------------------------------

func TestBrandingDefaults(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("app name defaults", func(t *testing.T) {
		if cfg.AppName != "The Vault" {
			t.Errorf("AppName = %q, want 'The Vault'", cfg.AppName)
		}
	})

	t.Run("primary color defaults", func(t *testing.T) {
		if cfg.PrimaryColor != "#00FF42" {
			t.Errorf("PrimaryColor = %q, want #00FF42", cfg.PrimaryColor)
		}
	})
}

// ---------------------------------------------------------------------------
// Email defaults
// ---------------------------------------------------------------------------

func TestEmailDefaults(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("email provider defaults to smtp", func(t *testing.T) {
		if cfg.EmailProvider != "smtp" {
			t.Errorf("EmailProvider = %q, want smtp", cfg.EmailProvider)
		}
	})

	t.Run("SMTP port defaults to 587", func(t *testing.T) {
		if cfg.SMTPPort != "587" {
			t.Errorf("SMTPPort = %q, want 587", cfg.SMTPPort)
		}
	})
}

// ---------------------------------------------------------------------------
// Max sessions default
// ---------------------------------------------------------------------------

func TestMaxSessionsDefault(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("max sessions defaults to 10", func(t *testing.T) {
		if cfg.MaxSessionsPerUser != 10 {
			t.Errorf("MaxSessionsPerUser = %d, want 10", cfg.MaxSessionsPerUser)
		}
	})
}

func TestMaxSessionsOverride(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_MAX_SESSIONS_PER_USER", "5")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("max sessions can be overridden", func(t *testing.T) {
		if cfg.MaxSessionsPerUser != 5 {
			t.Errorf("MaxSessionsPerUser = %d, want 5", cfg.MaxSessionsPerUser)
		}
	})
}
