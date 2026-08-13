package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/42-v/vault42/internal/config"
)

// Config holds all configuration for the admin gateway.
type Config struct {
	// ListenAddr is the bind address (ADMIN_GW_LISTEN_ADDR). Default: "127.0.0.1:9443".
	ListenAddr string

	// TLS configuration (mTLS required)
	TLSCertFile  string // ADMIN_GW_TLS_CERT_FILE — server certificate
	TLSKeyFile   string // ADMIN_GW_TLS_KEY_FILE — server private key
	ClientCAFile string // ADMIN_GW_CLIENT_CA_FILE — CA for mTLS client verification

	// Session configuration
	SessionTTL time.Duration // ADMIN_GW_SESSION_TTL — default: 1h
	MaxFailed  int           // ADMIN_GW_MAX_FAILED_LOGINS — default: 5
	LockoutDur time.Duration // ADMIN_GW_LOCKOUT_DURATION — default: 30m

	// Database (shared with vault, reached as the vault_admin role)
	// DBHost is the PostgreSQL hostname (DB_HOST). Default: "localhost".
	DBHost string
	// DBPort is the PostgreSQL port (DB_PORT). Default: "5432".
	DBPort string
	// DBName is the PostgreSQL database name (DB_NAME). Default: "vault".
	DBName string
	// DBSSLMode is the PostgreSQL SSL mode (DB_SSLMODE). Default: "require".
	DBSSLMode string
	// DBMaxConns is the maximum number of database connections (DB_MAX_CONNS).
	// Default: 5, an order of magnitude below the vault server's pool because
	// this is a single-operator admin plane, not a request-serving path.
	DBMaxConns int
	// DBPassword is the vault_admin role password (DB_ADMIN_PASSWORD_FILE).
	// vault_admin is a separate, more privileged role than the vault_app role
	// the server uses, which is why the admin gateway is a separate binary on
	// loopback rather than a route on the public server.
	DBPassword string

	// Master key for TOTP encryption (same as vault)
	MasterKey []byte

	// HMACSecret (HMAC_SECRET_FILE, same as vault) is needed to derive the
	// identity/blob pseudonyms during account erasure. Empty disables the
	// DELETE /admin/users/{id} cascade-by-pseudonym (it returns 503).
	HMACSecret []byte

	// RecoveryPublicKeyPEM (VAULT_RECOVERY_PUBLIC_KEY_FILE, same as vault) is the
	// RSA public key used to escrow account-erasure records. Empty disables escrow.
	RecoveryPublicKeyPEM []byte

	// Pepper is the optional HMAC-pepper applied to admin password hashes
	// (VAULT_PEPPER_FILE). Must match the value used by the user-side service
	// for hash-format parity (see internal/crypto/argon2.go applyPepper).
	Pepper string

	// Auto-migrate (create tables on first boot)
	AutoMigrate bool

	// DevMode relaxes loopback enforcement for development behind ingress
	DevMode bool

	// Killswitch panics (crashes pod) on non-loopback request when enabled (default: true).
	// Disabled automatically in dev mode.
	Killswitch bool

	// Shutdown timeout
	ShutdownTimeout time.Duration

	// SeedFile is the path to a JSON seed file for declarative admin user
	// creation at startup (VAULT_SEED_FILE). Empty = no seeding.
	SeedFile string
}

// LoadConfig reads configuration from environment variables.
func LoadConfig() (*Config, error) {
	c := &Config{
		ListenAddr:   envOr("ADMIN_GW_LISTEN_ADDR", "127.0.0.1:9443"),
		TLSCertFile:  os.Getenv("ADMIN_GW_TLS_CERT_FILE"),
		TLSKeyFile:   os.Getenv("ADMIN_GW_TLS_KEY_FILE"),
		ClientCAFile: os.Getenv("ADMIN_GW_CLIENT_CA_FILE"),

		SessionTTL: envDuration("ADMIN_GW_SESSION_TTL", time.Hour),
		MaxFailed:  envInt("ADMIN_GW_MAX_FAILED_LOGINS", 5),
		LockoutDur: envDuration("ADMIN_GW_LOCKOUT_DURATION", 30*time.Minute),

		DBHost:     envOr("DB_HOST", "localhost"),
		DBPort:     envOr("DB_PORT", "5432"),
		DBName:     envOr("DB_NAME", "vault"),
		DBSSLMode:  envOr("DB_SSLMODE", "require"),
		DBMaxConns: envInt("DB_MAX_CONNS", 5),

		AutoMigrate:     envBool("ADMIN_GW_AUTO_MIGRATE"),
		ShutdownTimeout: envDuration("ADMIN_GW_SHUTDOWN_TIMEOUT", 15*time.Second),
		SeedFile:        os.Getenv("VAULT_SEED_FILE"),
	}

	// Load secrets from _FILE env vars.
	//
	// The master key is raw bytes and must not go through loadSecret, whose
	// TrimSpace ate a byte off roughly one correctly generated key in twenty-two.
	// See config.LoadSecretBinary for the arithmetic.
	if mk, err := config.LoadSecretBinary("MASTER_KEY", 32); err == nil {
		c.MasterKey = mk
	}
	if pw, err := loadSecret("DB_ADMIN_PASSWORD"); err == nil {
		c.DBPassword = pw
	}
	if p, err := loadSecret("VAULT_PEPPER"); err == nil {
		c.Pepper = p
	}
	if hs, err := loadSecret("HMAC_SECRET"); err == nil {
		c.HMACSecret = []byte(hs)
	}
	if rk, err := loadSecret("VAULT_RECOVERY_PUBLIC_KEY"); err == nil {
		c.RecoveryPublicKeyPEM = []byte(rk)
	}

	// Validate required TLS config
	if c.TLSCertFile == "" {
		return nil, fmt.Errorf("ADMIN_GW_TLS_CERT_FILE is required")
	}
	if c.TLSKeyFile == "" {
		return nil, fmt.Errorf("ADMIN_GW_TLS_KEY_FILE is required")
	}
	if c.ClientCAFile == "" {
		return nil, fmt.Errorf("ADMIN_GW_CLIENT_CA_FILE is required")
	}

	// Validate listen address is loopback (relaxed in dev mode for k8s ingress access)
	c.DevMode = os.Getenv("ADMIN_GW_DEV_MODE") == "true"
	if !c.DevMode && !strings.HasPrefix(c.ListenAddr, "127.0.0.1:") && !strings.HasPrefix(c.ListenAddr, "[::1]:") && !strings.HasPrefix(c.ListenAddr, "localhost:") {
		return nil, fmt.Errorf("ADMIN_GW_LISTEN_ADDR must bind to loopback (127.0.0.1 or [::1]), got %q", c.ListenAddr)
	}

	// Killswitch: default on, off in dev mode. An explicit value must be a
	// recognised spelling; anything else refuses to start. The previous parse
	// treated every unrecognised value as off, so ADMIN_GW_KILLSWITCH=True
	// (or a typo) disabled the tripwire while leaving it unset kept it on.
	killswitch := os.Getenv("ADMIN_GW_KILLSWITCH")
	if killswitch == "" {
		c.Killswitch = !c.DevMode
	} else {
		on, err := parseKillswitch(killswitch)
		if err != nil {
			return nil, err
		}
		c.Killswitch = on
	}

	if len(c.MasterKey) != 32 {
		return nil, fmt.Errorf("MASTER_KEY_FILE is required (32 bytes for AES-256)")
	}

	return c, nil
}

// DatabaseURL builds a PostgreSQL connection string using the vault_admin role.
func (c *Config) DatabaseURL() string {
	return postgresURL("vault_admin", c.DBPassword, c.DBHost, c.DBPort, c.DBName, c.DBSSLMode)
}

// postgresURL builds a PostgreSQL URI with the password percent-encoded.
// Sprintf would splice the password into the userinfo verbatim, so '/', '?'
// and '#' make pgx report "invalid port after host", a space makes it report
// "invalid userinfo", and a '%' is decoded silently so the process
// authenticates as a different string than the one on disk.
//
// timezone matches internal/config's DatabaseURL. The gateway reads the same
// audit and key tables the server writes, so a gateway session left in the
// server's local zone would render one row's timestamps two different ways
// across the two products' responses.
func postgresURL(user, password, host, port, dbname, sslmode string) string {
	q := url.Values{}
	q.Set("sslmode", sslmode)
	q.Set("timezone", "UTC")

	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     host + ":" + port,
		Path:     dbname,
		RawQuery: q.Encode(),
	}
	return u.String()
}

// parseKillswitch accepts the same on/off spellings as envBool and refuses
// everything else. A killswitch that cannot be parsed must not start the
// process as if the operator had asked to disable it.
func parseKillswitch(v string) (bool, error) {
	switch v {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("ADMIN_GW_KILLSWITCH must be true, 1, yes, false, 0 or no (got %q)", v)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	v := os.Getenv(key)
	return v == "true" || v == "1" || v == "yes"
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func loadSecret(name string) (string, error) {
	filePath := os.Getenv(name + "_FILE")
	if filePath == "" {
		return "", fmt.Errorf("%s_FILE not set", name)
	}
	cleaned := filepath.Clean(filePath)
	data, err := os.ReadFile(cleaned) // #nosec G304 — path from operator-controlled env var
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	return strings.TrimSpace(string(data)), nil
}
