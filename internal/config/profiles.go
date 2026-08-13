package config

import (
	"os"
	"strconv"
	"time"
)

// Profile represents a deployment profile that controls default configuration values.
// Three profiles are supported: production, embedded, and dev. Dev extends the
// production baseline with overrides for local development convenience.
type Profile string

const (
	// ProfileProduction is the default profile with full security settings,
	// Redis cache, 7-day refresh tokens, and 25 database connections.
	ProfileProduction Profile = "production"
	// ProfileEmbedded is tuned for resource-constrained environments (e.g., RPi5)
	// with in-memory cache, 5 database connections, and auto-migration enabled.
	ProfileEmbedded Profile = "embedded"
	// ProfileDev extends ProfileProduction with permissive CORS, auto-migration,
	// 24-hour refresh tokens, and a 5-second shutdown timeout.
	ProfileDev Profile = "dev"
	// ProfileHoneypot extends ProfileProduction with auto-migration and the
	// embedded SPA, so the deployment looks like a real one to an attacker.
	ProfileHoneypot Profile = "honeypot"
)

// applyProfileDefaults sets default values based on the deployment profile.
// Dev extends production — it inherits all production defaults, then applies
// minimal overrides for local convenience.
func applyProfileDefaults(c *Config) {
	switch c.Profile {
	case ProfileDev:
		// Save pre-profile values to detect env var overrides
		origRefreshTTL := c.RefreshTokenTTL
		origShutdownTimeout := c.ShutdownTimeout
		rateLimitExplicit := os.Getenv("VAULT_RATE_LIMIT_ENABLED") != ""

		// Start from production base
		applyProductionDefaults(c)

		// Respect explicit rate limit override
		if rateLimitExplicit {
			c.RateLimitEnabled = envBool("VAULT_RATE_LIMIT_ENABLED")
		}

		// Dev overrides — only if not explicitly set via env vars
		c.AutoMigrate = true
		if os.Getenv("CORS_ALLOW_ALL") == "" {
			c.CORSAllowAll = true
		}
		if origRefreshTTL == 0 {
			c.RefreshTokenTTL = 24 * time.Hour
		}
		if origShutdownTimeout == 0 {
			c.ShutdownTimeout = 5 * time.Second
		}

	case ProfileEmbedded:
		setDefault(&c.ListenAddr, ":8443")
		setDefaultBool(&c.TLSEnabled, true, "VAULT_TLS_ENABLED")
		setDefaultBool(&c.RateLimitEnabled, true, "VAULT_RATE_LIMIT_ENABLED")
		setDefaultBool(&c.AutoMigrate, true, "VAULT_AUTO_MIGRATE")
		setDefaultDuration(&c.AccessTokenTTL, 15*time.Minute)
		setDefaultDuration(&c.RefreshTokenTTL, 24*time.Hour)
		setDefaultDuration(&c.RememberMeTTL, 30*24*time.Hour)
		setDefault(&c.CacheBackend, "memory")
		setDefaultInt(&c.DBMaxConns, 5)
		setDefaultDuration(&c.ShutdownTimeout, 5*time.Second)
		setDefaultDuration(&c.AuditFlushInterval, 30*time.Second)

	case ProfileHoneypot:
		applyProductionDefaults(c)
		// Honeypot overrides: easy deployment, looks real
		if os.Getenv("VAULT_AUTO_MIGRATE") == "" {
			c.AutoMigrate = true
		}
		if os.Getenv("VAULT_SERVE_FRONTEND") == "" {
			c.ServeFrontend = true // serve embedded SPA to look like a real app
		}

	case ProfileProduction:
		applyProductionDefaults(c)

	default:
		c.Profile = ProfileProduction
		applyProductionDefaults(c)
	}
}

// applyProductionDefaults sets the production baseline values.
func applyProductionDefaults(c *Config) {
	setDefault(&c.ListenAddr, ":8443")
	setDefaultBool(&c.TLSEnabled, true, "VAULT_TLS_ENABLED")
	setDefaultBool(&c.RateLimitEnabled, true, "VAULT_RATE_LIMIT_ENABLED")
	setDefaultBool(&c.AutoMigrate, false, "VAULT_AUTO_MIGRATE")
	// Production: always force CORSAllowAll off — use explicit CORS_ORIGINS instead.
	c.CORSAllowAll = false
	setDefaultDuration(&c.AccessTokenTTL, 15*time.Minute)
	setDefaultDuration(&c.RefreshTokenTTL, 7*24*time.Hour)
	setDefaultDuration(&c.RememberMeTTL, 30*24*time.Hour)
	setDefault(&c.CacheBackend, "redis")
	setDefaultInt(&c.DBMaxConns, 25)
	setDefaultDuration(&c.ShutdownTimeout, 15*time.Second)
}

func setDefault(field *string, val string) {
	if *field == "" {
		*field = val
	}
}

func setDefaultBool(field *bool, val bool, envKey string) {
	// Only apply default if the env var was not explicitly set.
	// os.LookupEnv distinguishes "not set" from "set to empty/false".
	v, exists := os.LookupEnv(envKey)
	if !exists {
		*field = val
		return
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		*field = val
		return
	}
	*field = parsed
}

func setDefaultInt(field *int, val int) {
	if *field == 0 {
		*field = val
	}
}

func setDefaultDuration(field *time.Duration, val time.Duration) {
	if *field == 0 {
		*field = val
	}
}
