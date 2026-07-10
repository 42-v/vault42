// Package config loads and validates all configuration for The Vault from
// environment variables and secret files. It supports three deployment profiles
// (production, embedded, dev) and enforces the _FILE suffix convention for secrets.
package config

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for The Vault. Values are populated from
// environment variables by [Load], with profile-specific defaults applied
// for any unset fields. Secrets are loaded from files via the _FILE suffix
// convention (e.g., MASTER_KEY_FILE points to a file containing the key).
type Config struct {
	// Profile is the deployment profile (VAULT_PROFILE). Defaults to "production".
	Profile Profile

	// ListenAddr is the address the server binds to (LISTEN_ADDR). Default: ":8443".
	ListenAddr string
	// Origin is the public-facing URL, used for CORS, JWKS issuer, and cookie domain (VAULT_ORIGIN).
	Origin string
	// LogLevel controls log verbosity (LOG_LEVEL). Default: "warn" (production), "debug" (dev).
	LogLevel string

	// TLSEnabled enables HTTPS (VAULT_TLS_ENABLED). Default: true.
	TLSEnabled bool
	// TLSCertFile is the path to the TLS certificate PEM file (VAULT_TLS_CERT_FILE).
	TLSCertFile string
	// TLSKeyFile is the path to the TLS private key PEM file (VAULT_TLS_KEY_FILE).
	TLSKeyFile string

	// DBHost is the PostgreSQL hostname (DB_HOST). Default: "localhost".
	DBHost string
	// DBPort is the PostgreSQL port (DB_PORT). Default: "5432".
	DBPort string
	// DBName is the PostgreSQL database name (DB_NAME). Default: "vault".
	DBName string
	// DBSSLMode is the PostgreSQL SSL mode (DB_SSLMODE). Default: "require" (disabled in dev).
	DBSSLMode string
	// DBMaxConns is the maximum number of database connections (DB_MAX_CONNS). Default: 25 (production), 5 (embedded).
	DBMaxConns int

	// DBMigPassword is the password for the vault_mig migration role (DB_MIG_PASSWORD_FILE).
	DBMigPassword string
	// DBAppPassword is the password for the vault_app application role (DB_APP_PASSWORD_FILE).
	DBAppPassword string

	// MasterKey is the AES-256 encryption key (32 bytes) for TOTP secret encryption (MASTER_KEY_FILE).
	MasterKey []byte
	// KMSRootKey is the root secret (>= 32 bytes) from which per-kid KEKs are
	// derived for the POST /kms/unwrap envelope-unwrap oracle (KMS_ROOT_KEY_FILE).
	// When empty the KMS endpoint is not mounted. Kept cryptographically separate
	// from MasterKey (which encrypts data at rest) via HKDF domain separation.
	KMSRootKey []byte
	// AdminTokenHash is the Argon2id hash of the admin CLI token (ADMIN_TOKEN_FILE).
	AdminTokenHash string
	// Pepper is a server-side secret added to password hashes (VAULT_PEPPER_FILE).
	Pepper string
	// HMACSecret is the key used for HMAC-SHA256 signatures (HMAC_SECRET_FILE). Must be at least 32 bytes in non-dev profiles.
	HMACSecret []byte
	// RecoveryPublicKeyPEM is the PEM-encoded RSA recovery public key
	// (VAULT_RECOVERY_PUBLIC_KEY_FILE). When set, account erasure escrows an
	// encrypted recovery record that only the offline private key can decrypt.
	// When empty, recovery logging is disabled and erasure still proceeds.
	RecoveryPublicKeyPEM []byte

	// CacheBackend selects the cache implementation (CACHE_BACKEND): "redis", "memory", or "postgres".
	CacheBackend string
	// RedisAddr is the Redis server address (REDIS_ADDR), used when CacheBackend is "redis".
	RedisAddr string
	// RedisPass is the Redis password (REDIS_PASS_FILE).
	RedisPass string

	// AccessTokenTTL is the lifetime of JWT access tokens (VAULT_ACCESS_TOKEN_TTL). Default: 15m.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is the lifetime of refresh tokens (VAULT_REFRESH_TOKEN_TTL). Default: 7d (production), 24h (dev).
	RefreshTokenTTL time.Duration
	// RememberMeTTL is the extended refresh token lifetime when "remember me" is selected (VAULT_REMEMBER_ME_TTL). Default: 30d.
	RememberMeTTL time.Duration

	// RateLimitEnabled enables rate limiting on auth endpoints (VAULT_RATE_LIMIT_ENABLED). Default: true.
	RateLimitEnabled bool

	// EmailProvider selects the email sending backend (VAULT_EMAIL_PROVIDER): "smtp" or "sendgrid". Default: "smtp".
	EmailProvider string
	// SendGridAPIKey is the SendGrid API key for sending emails (SENDGRID_API_KEY_FILE).
	// Used when EmailProvider is "sendgrid" or when SMTPHost is empty and this key is set.
	SendGridAPIKey string
	// SMTPHost is the SMTP server hostname (SMTP_HOST).
	SMTPHost string
	// SMTPPort is the SMTP server port (SMTP_PORT). Default: "587".
	SMTPPort string
	// SMTPUser is the SMTP authentication username (SMTP_USER_FILE).
	SMTPUser string
	// SMTPPass is the SMTP authentication password (SMTP_PASS_FILE).
	SMTPPass string
	// EmailFrom is the sender address for outgoing emails (VAULT_EMAIL_FROM).
	EmailFrom string

	// OAuthGoogleClientID is the Google OAuth2 client ID (VAULT_OAUTH_GOOGLE_CLIENT_ID).
	OAuthGoogleClientID string
	// OAuthGoogleClientSecret is the Google OAuth2 client secret (VAULT_OAUTH_GOOGLE_CLIENT_SECRET_FILE).
	OAuthGoogleClientSecret string
	// OAuthGitHubClientID is the GitHub OAuth2 client ID (VAULT_OAUTH_GITHUB_CLIENT_ID).
	OAuthGitHubClientID string
	// OAuthGitHubClientSecret is the GitHub OAuth2 client secret (VAULT_OAUTH_GITHUB_CLIENT_SECRET_FILE).
	OAuthGitHubClientSecret string
	// OAuthFacebookClientID is the Facebook OAuth2 client ID (VAULT_OAUTH_FACEBOOK_CLIENT_ID).
	OAuthFacebookClientID string
	// OAuthFacebookClientSecret is the Facebook OAuth2 client secret (VAULT_OAUTH_FACEBOOK_CLIENT_SECRET_FILE).
	OAuthFacebookClientSecret string

	// OIDCProviders holds generic OpenID Connect providers (Okta, Auth0, Keycloak,
	// Entra, …) registered via VAULT_OIDC_PROVIDERS + per-name env vars.
	OIDCProviders []OIDCProviderConfig

	// PasswordMinLength is the minimum password length (VAULT_PASSWORD_MIN_LENGTH). Default: 15 (NIST SP 800-63B).
	PasswordMinLength int
	// HIBPCheck enables Have I Been Pwned breach checking for passwords (VAULT_HIBP_CHECK). Default: true.
	HIBPCheck bool
	// MFARequired forces all users to set up two-factor authentication (VAULT_MFA_REQUIRED).
	MFARequired bool
	// RegistrationEnabled controls whether public user registration is allowed (VAULT_REGISTRATION_ENABLED). Default: true.
	RegistrationEnabled bool
	// MaxSessionsPerUser limits the number of concurrent refresh token families per user (VAULT_MAX_SESSIONS_PER_USER). Default: 10.
	MaxSessionsPerUser int
	// StrictSessionLimit makes the concurrent-session check fail closed when the
	// underlying count query errors, instead of allowing the login (VAULT_STRICT_SESSION_LIMIT). Default: false.
	StrictSessionLimit bool

	// AppName is the application display name used in emails and UI (VAULT_APP_NAME). Default: "The Vault".
	AppName string
	// LogoURL is an optional URL to the application logo for email templates (VAULT_LOGO_URL).
	LogoURL string
	// PrimaryColor is the primary branding color hex code (VAULT_PRIMARY_COLOR). Default: "#00FF42".
	PrimaryColor string
	// EmailFromName is an optional global display name for the From line (VAULT_EMAIL_FROM_NAME).
	EmailFromName string
	// EmailFromAllowedDomains lists domains permitted for per-app From-address
	// overrides (VAULT_EMAIL_FROM_ALLOWED_DOMAINS, comma-separated). A per-app
	// from_address whose domain is not listed falls back to EmailFrom; an empty
	// list disables address overrides entirely (display-name overrides still apply).
	EmailFromAllowedDomains []string
	// MaxEmailTemplateSize caps the byte size of a custom email template body
	// accepted by the admin API (VAULT_MAX_EMAIL_TEMPLATE_SIZE). Default: 65536.
	MaxEmailTemplateSize int

	// CORSOrigins is a comma-separated list of allowed CORS origins (CORS_ORIGINS).
	CORSOrigins string
	// CORSAllowAll permits all CORS origins (CORS_ALLOW_ALL). Only true in dev profile by default.
	CORSAllowAll bool

	// TrustedProxies is a list of CIDR ranges or IPs trusted to set X-Forwarded-For (TRUSTED_PROXIES).
	TrustedProxies []string

	// RealIPHeader is the HTTP header containing the real client IP set by a trusted proxy (REAL_IP_HEADER).
	// Only trusted when the direct connection comes from a trusted proxy.
	// Examples: "CF-Connecting-IP" (Cloudflare), "X-Real-IP" (nginx), "Tailscale-User-Login" (Tailscale).
	// Empty = disabled (use X-Forwarded-For parsing only).
	RealIPHeader string

	// EmbeddedTrustedUpstream toggles a one-shot setup for vault42 running
	// behind a sibling reverse proxy in the same private network — typical
	// of embedded deployments where another app (e.g. Hermod coordinator)
	// terminates TLS and forwards auth calls to vault42 over the cluster
	// network. When true and TrustedProxies is empty, auto-populates with
	// RFC1918 ranges (10/8, 172.16/12, 192.168/16) plus IPv6 ULA (fc00::/7).
	// When true and RealIPHeader is empty, defaults to "X-Forwarded-For".
	// (VAULT_EMBEDDED_TRUSTED_UPSTREAM). Default: false.
	EmbeddedTrustedUpstream bool

	// GeoIPHeader is the HTTP header containing the client's country code (GEO_IP_HEADER).
	// Only used for geo-fencing when set. Examples: "CF-IPCountry" (Cloudflare), "X-Geo-Country" (custom).
	// Empty = geo-fencing disabled regardless of GeoAllowlist/GeoBlocklist.
	GeoIPHeader string

	// TLSFingerprintHeader is the HTTP header containing a TLS fingerprint (e.g. JA4) set by
	// the TLS-terminating proxy (VAULT_TLS_FINGERPRINT_HEADER). Since Vault typically runs
	// behind nginx-ingress or similar, it cannot compute JA4 directly — the proxy must extract
	// it during the TLS handshake and pass it as a header. Empty = TLS fingerprint not included
	// in device fingerprint computation (backward compatible).
	TLSFingerprintHeader string

	// IPAllowlist is a list of CIDR ranges or IPs allowed to access the service (IP_ALLOWLIST).
	// Empty = allow all. When set, only matching IPs are permitted.
	IPAllowlist []string
	// IPBlocklist is a list of CIDR ranges or IPs denied access (IP_BLOCKLIST).
	// Empty = block none. Evaluated after IPAllowlist.
	IPBlocklist []string
	// GeoAllowlist is a list of ISO 3166-1 alpha-2 country codes allowed access (GEO_ALLOWLIST).
	// Empty = allow all countries. Requires GeoIPHeader to be set.
	GeoAllowlist []string
	// GeoBlocklist is a list of ISO 3166-1 alpha-2 country codes denied access (GEO_BLOCKLIST).
	// Empty = block no countries. Requires GeoIPHeader to be set.
	GeoBlocklist []string

	// AutoMigrate enables automatic database schema migration at startup (VAULT_AUTO_MIGRATE). Default: false (production), true (dev/embedded).
	AutoMigrate bool

	// ShutdownTimeout is the maximum duration to wait for in-flight requests during graceful shutdown (VAULT_SHUTDOWN_TIMEOUT). Default: 15s (production), 5s (dev).
	ShutdownTimeout time.Duration

	// AuditFlushInterval is the interval for flushing buffered audit log entries (VAULT_AUDIT_FLUSH_INTERVAL). Zero disables batching.
	AuditFlushInterval time.Duration

	// AuditBufferSize is the maximum number of audit entries buffered before new entries are dropped (VAULT_AUDIT_BUFFER_SIZE). Default: 1000.
	AuditBufferSize int

	// EmailTemplatesDir is an optional directory containing custom HTML email templates (VAULT_EMAIL_TEMPLATES_DIR).
	// Templates in this directory override the embedded defaults by filename match.
	EmailTemplatesDir string

	// ForceSecureCookies forces the Secure flag on cookies even when TLS is not enabled locally
	// (VAULT_FORCE_SECURE_COOKIES). Useful behind TLS-terminating proxies like Cloudflare Tunnel.
	ForceSecureCookies bool

	// ServeFrontend enables serving the embedded Vue SPA from the Go binary (VAULT_SERVE_FRONTEND).
	// Default: false (secure by default — use a separate nginx container).
	// The honeypot profile enables this by default.
	ServeFrontend bool

	// BlobMinSize is the minimum single blob size in bytes (VAULT_BLOB_MIN_SIZE). Default: 0 (disabled).
	// The handler already rejects empty blobs, so a minimum is not needed unless you
	// want to enforce a policy floor (e.g. "no files under 1KB").
	BlobMinSize int
	// BlobMaxSize is the maximum single blob size in bytes (VAULT_BLOB_MAX_SIZE). Default: 10MB.
	BlobMaxSize int
	// BlobMaxPerUser is the maximum number of blobs per user (VAULT_BLOB_MAX_PER_USER). Default: 50.
	BlobMaxPerUser int
	// BlobQuotaBytes is the total storage quota per user in bytes (VAULT_BLOB_QUOTA_BYTES). Default: 10MB.
	// Set to 0 to disable the blob storage feature entirely.
	BlobQuotaBytes int

	// HoneypotWebhookURL is the URL to POST honeypot alerts to (VAULT_HONEYPOT_WEBHOOK).
	// Only used when Profile is "honeypot".
	HoneypotWebhookURL string

	// HoneypotTrapUsers is a list of fake usernames/emails that trigger honeypot alerts (VAULT_HONEYPOT_TRAP_USERS).
	// Comma-separated. Only used when Profile is "honeypot".
	HoneypotTrapUsers []string

	// DPoPEnabled enables DPoP (Demonstrating Proof-of-Possession) validation on token
	// endpoints (VAULT_DPOP_ENABLED). When enabled, the DPoP middleware validates proof
	// headers on /auth/login, /auth/refresh, the 2FA verify endpoints, and the
	// POST /kms/unwrap key-release oracle (anti-replay) per RFC 9449.
	// Default: false.
	DPoPEnabled bool

	// MetricsEnabled enables the Prometheus-compatible /metrics endpoint (VAULT_METRICS_ENABLED).
	// When enabled, operational counters (argon2 semaphore, login, token) are exposed in
	// Prometheus text exposition format. Protect with NetworkPolicy in production.
	// Default: false.
	MetricsEnabled bool

	// KeyRotationDB enables database-backed key storage and rotation (VAULT_KEY_ROTATION_DB).
	// When true, signing keys are stored encrypted in PostgreSQL and refreshed periodically.
	// When false (default), the existing file-based SIGNING_KEY_FILE behavior is used.
	KeyRotationDB bool

	// KeyRetentionPeriod is how long retired signing keys remain in JWKS after rotation
	// (VAULT_KEY_RETENTION_PERIOD). Default: 1h.
	KeyRetentionPeriod time.Duration

	// KeyRefreshInterval is how often pods refresh signing keys from the database
	// (VAULT_KEY_REFRESH_INTERVAL). Default: 60s.
	KeyRefreshInterval time.Duration

	// SeedFile is the path to a JSON seed file for declarative user and client
	// creation at startup (VAULT_SEED_FILE). Empty = no seeding.
	SeedFile string
}

// Load reads configuration from environment variables and secret files,
// applies profile-specific defaults, and returns a validated Config.
// Secrets are loaded via the _FILE suffix convention (see [LoadSecret]).
//
//nolint:gocognit // each env var is one branch; splitting hides defaults across files
func Load() (*Config, error) {
	c := &Config{
		Profile: Profile(envOr("VAULT_PROFILE", "production")),

		ListenAddr: os.Getenv("LISTEN_ADDR"),
		Origin:     os.Getenv("VAULT_ORIGIN"),
		LogLevel:   os.Getenv("LOG_LEVEL"),

		TLSEnabled:  envBool("VAULT_TLS_ENABLED"),
		TLSCertFile: os.Getenv("VAULT_TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("VAULT_TLS_KEY_FILE"),

		DBHost:     envOr("DB_HOST", "localhost"),
		DBPort:     envOr("DB_PORT", "5432"),
		DBName:     envOr("DB_NAME", "vault"),
		DBSSLMode:  envOr("DB_SSLMODE", "require"),
		DBMaxConns: envInt("DB_MAX_CONNS", 0),

		CacheBackend: os.Getenv("CACHE_BACKEND"),
		RedisAddr:    os.Getenv("REDIS_ADDR"),

		EmailProvider: envOr("VAULT_EMAIL_PROVIDER", "smtp"),
		SMTPHost:      os.Getenv("SMTP_HOST"),
		SMTPPort:      envOr("SMTP_PORT", "587"),
		EmailFrom:     os.Getenv("VAULT_EMAIL_FROM"),

		OAuthGoogleClientID:   os.Getenv("VAULT_OAUTH_GOOGLE_CLIENT_ID"),
		OAuthGitHubClientID:   os.Getenv("VAULT_OAUTH_GITHUB_CLIENT_ID"),
		OAuthFacebookClientID: os.Getenv("VAULT_OAUTH_FACEBOOK_CLIENT_ID"),

		PasswordMinLength:   envInt("VAULT_PASSWORD_MIN_LENGTH", 15),
		HIBPCheck:           envBoolDefault("VAULT_HIBP_CHECK", true),
		MFARequired:         envBoolDefault("VAULT_MFA_REQUIRED", true),
		RegistrationEnabled: envBoolDefault("VAULT_REGISTRATION_ENABLED", true),
		MaxSessionsPerUser:  envInt("VAULT_MAX_SESSIONS_PER_USER", 10),
		StrictSessionLimit:  envBool("VAULT_STRICT_SESSION_LIMIT"),

		AppName:                 envOr("VAULT_APP_NAME", "The Vault"),
		LogoURL:                 os.Getenv("VAULT_LOGO_URL"),
		PrimaryColor:            envOr("VAULT_PRIMARY_COLOR", "#00FF42"),
		EmailFromName:           os.Getenv("VAULT_EMAIL_FROM_NAME"),
		EmailFromAllowedDomains: splitTrimLower(os.Getenv("VAULT_EMAIL_FROM_ALLOWED_DOMAINS")),
		MaxEmailTemplateSize:    envInt("VAULT_MAX_EMAIL_TEMPLATE_SIZE", 65536),

		CORSOrigins:  os.Getenv("CORS_ORIGINS"),
		CORSAllowAll: envBool("CORS_ALLOW_ALL"),

		AccessTokenTTL:          envDuration("VAULT_ACCESS_TOKEN_TTL", 0),
		RefreshTokenTTL:         envDuration("VAULT_REFRESH_TOKEN_TTL", 0),
		RememberMeTTL:           envDuration("VAULT_REMEMBER_ME_TTL", 0),
		ShutdownTimeout:         envDuration("VAULT_SHUTDOWN_TIMEOUT", 0),
		AuditFlushInterval:      envDuration("VAULT_AUDIT_FLUSH_INTERVAL", 0),
		AutoMigrate:             envBool("VAULT_AUTO_MIGRATE"),
		RateLimitEnabled:        envBoolDefault("VAULT_RATE_LIMIT_ENABLED", true),
		EmbeddedTrustedUpstream: envBool("VAULT_EMBEDDED_TRUSTED_UPSTREAM"),

		EmailTemplatesDir:  os.Getenv("VAULT_EMAIL_TEMPLATES_DIR"),
		ForceSecureCookies: envBool("VAULT_FORCE_SECURE_COOKIES"),
		ServeFrontend:      envBool("VAULT_SERVE_FRONTEND"),

		BlobMinSize:    envInt("VAULT_BLOB_MIN_SIZE", 0),
		BlobMaxSize:    envInt("VAULT_BLOB_MAX_SIZE", 10*1024*1024),
		BlobMaxPerUser: envInt("VAULT_BLOB_MAX_PER_USER", 50),
		BlobQuotaBytes: envInt("VAULT_BLOB_QUOTA_BYTES", 10*1024*1024),

		AuditBufferSize: envInt("VAULT_AUDIT_BUFFER_SIZE", 1000),

		HoneypotWebhookURL: os.Getenv("VAULT_HONEYPOT_WEBHOOK"),

		DPoPEnabled:    envBool("VAULT_DPOP_ENABLED"),
		MetricsEnabled: envBool("VAULT_METRICS_ENABLED"),

		KeyRotationDB:      envBool("VAULT_KEY_ROTATION_DB"),
		KeyRetentionPeriod: envDuration("VAULT_KEY_RETENTION_PERIOD", time.Hour),
		KeyRefreshInterval: envDuration("VAULT_KEY_REFRESH_INTERVAL", 60*time.Second),

		SeedFile: os.Getenv("VAULT_SEED_FILE"),
	}

	// Load honeypot trap users from comma-separated list
	if tu := os.Getenv("VAULT_HONEYPOT_TRAP_USERS"); tu != "" {
		for _, entry := range strings.Split(tu, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				c.HoneypotTrapUsers = append(c.HoneypotTrapUsers, strings.ToLower(entry))
			}
		}
	}

	// Load trusted proxies from comma-separated CIDR/IP list
	if tp := os.Getenv("TRUSTED_PROXIES"); tp != "" {
		for _, entry := range strings.Split(tp, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				c.TrustedProxies = append(c.TrustedProxies, entry)
			}
		}
	}

	// Real IP header (proxy-specific, e.g. "CF-Connecting-IP")
	c.RealIPHeader = strings.TrimSpace(os.Getenv("REAL_IP_HEADER"))

	// Geo IP header (proxy-specific, e.g. "CF-IPCountry")
	c.GeoIPHeader = strings.TrimSpace(os.Getenv("GEO_IP_HEADER"))

	// TLS fingerprint header (proxy-specific, e.g. "X-TLS-Fingerprint")
	c.TLSFingerprintHeader = strings.TrimSpace(os.Getenv("VAULT_TLS_FINGERPRINT_HEADER"))

	// Load IP allowlist/blocklist from comma-separated CIDR/IP list
	if v := os.Getenv("IP_ALLOWLIST"); v != "" {
		for _, entry := range strings.Split(v, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				c.IPAllowlist = append(c.IPAllowlist, entry)
			}
		}
	}
	if v := os.Getenv("IP_BLOCKLIST"); v != "" {
		for _, entry := range strings.Split(v, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				c.IPBlocklist = append(c.IPBlocklist, entry)
			}
		}
	}

	// Load geo allowlist/blocklist (uppercase country codes)
	if v := os.Getenv("GEO_ALLOWLIST"); v != "" {
		for _, entry := range strings.Split(v, ",") {
			entry = strings.TrimSpace(strings.ToUpper(entry))
			if entry != "" {
				c.GeoAllowlist = append(c.GeoAllowlist, entry)
			}
		}
	}
	if v := os.Getenv("GEO_BLOCKLIST"); v != "" {
		for _, entry := range strings.Split(v, ",") {
			entry = strings.TrimSpace(strings.ToUpper(entry))
			if entry != "" {
				c.GeoBlocklist = append(c.GeoBlocklist, entry)
			}
		}
	}

	// Apply profile defaults for any unset values
	applyProfileDefaults(c)

	// Embedded-trust shortcut: when an operator sets
	// VAULT_EMBEDDED_TRUSTED_UPSTREAM=true, vault42 is running behind a
	// sibling proxy on the same private network (typical Hermod/k8s pod
	// pattern). Auto-trust RFC1918 ranges so X-Forwarded-For from that
	// upstream is honoured for ClientIP() — required for per-attacker
	// rate-limit + audit attribution. Explicit TRUSTED_PROXIES /
	// REAL_IP_HEADER env values always win; this only fills the gaps.
	if c.EmbeddedTrustedUpstream {
		// Fail closed: this shortcut auto-trusts whole RFC1918 + loopback ranges
		// and blindly honours X-Forwarded-For, collapsing per-IP rate-limit and
		// audit attribution on a flat network. Only the embedded sidecar profile
		// may use it; anywhere else, set TRUSTED_PROXIES/REAL_IP_HEADER explicitly
		// (audit M7).
		if c.Profile != ProfileEmbedded {
			return nil, fmt.Errorf("VAULT_EMBEDDED_TRUSTED_UPSTREAM is only valid in the embedded profile (got %s); set TRUSTED_PROXIES and REAL_IP_HEADER explicitly", c.Profile)
		}
		if len(c.TrustedProxies) == 0 {
			c.TrustedProxies = []string{
				"10.0.0.0/8",     // RFC1918 large
				"172.16.0.0/12",  // RFC1918 medium
				"192.168.0.0/16", // RFC1918 small
				"fc00::/7",       // IPv6 ULA
				"127.0.0.0/8",    // loopback (sidecar pattern)
				"::1/128",        // IPv6 loopback
			}
		}
		if c.RealIPHeader == "" {
			c.RealIPHeader = "X-Forwarded-For"
		}
	}

	// Load secrets from _FILE env vars
	c.loadSecrets()

	// Register generic OIDC providers from env.
	c.loadOIDCProviders()

	// Validate primary color format (defense-in-depth: prevents CSS injection in email templates)
	if !isValidHexColor(c.PrimaryColor) {
		return nil, fmt.Errorf("invalid VAULT_PRIMARY_COLOR %q: must be hex format #RRGGBB", c.PrimaryColor)
	}

	// Enforce HMAC secret minimum length in non-dev profiles
	if len(c.HMACSecret) > 0 && len(c.HMACSecret) < 32 {
		if c.Profile != ProfileDev {
			return nil, fmt.Errorf("HMAC secret must be at least 32 bytes (got %d)", len(c.HMACSecret))
		}
		log.Println("SECURITY WARNING: HMAC secret is shorter than 32 bytes")
	}

	return c, nil
}

// Validate enforces fail-closed deployment invariants for non-dev profiles. It
// is called at startup (cmd/vault) — separate from Load() so config parsing
// stays side-effect free. Covers audit findings M4/M5/M6/L3: a non-dev server
// must not run with an empty HMAC key (weakens OAuth-state/backup-code/email-OTP
// signing), empty pepper (weakens password hashing), empty origin (disables JWT
// issuer/audience binding), or plaintext serving (drops the Secure cookie flag).
func (c *Config) Validate() error {
	if c.Profile == ProfileDev {
		return nil
	}
	if len(c.HMACSecret) < 32 {
		return fmt.Errorf("HMAC_SECRET_FILE required (>=32 bytes) in %s profile (got %d)", c.Profile, len(c.HMACSecret))
	}
	if len(c.Pepper) < 32 {
		return fmt.Errorf("VAULT_PEPPER_FILE required (>=32 bytes) in %s profile (got %d)", c.Profile, len(c.Pepper))
	}
	if c.Origin == "" {
		return fmt.Errorf("VAULT_ORIGIN required in %s profile", c.Profile)
	}
	// Rate limiting is the brute-force defense on the auth endpoints; refuse to
	// silently run a non-dev server with it disabled.
	if !c.RateLimitEnabled && !envBool("VAULT_ALLOW_RATE_LIMIT_DISABLED") {
		return fmt.Errorf("refusing to disable rate limiting in %s profile; set VAULT_ALLOW_RATE_LIMIT_DISABLED=true to override", c.Profile)
	}
	// M5: refuse to silently disable TLS.
	if !c.TLSEnabled && !c.ForceSecureCookies && !envBool("VAULT_ALLOW_PLAINTEXT") {
		return fmt.Errorf("refusing to disable TLS in %s profile; set VAULT_ALLOW_PLAINTEXT=true (e.g. behind a TLS-terminating proxy) to override", c.Profile)
	}
	// M4: TLS enabled but no cert/key silently falls back to plaintext while the
	// Secure cookie flag is set. Require certs unless proxy-termination is opted in.
	if c.TLSEnabled && (c.TLSCertFile == "" || c.TLSKeyFile == "") && !c.ForceSecureCookies {
		return fmt.Errorf("VAULT_TLS_CERT_FILE and VAULT_TLS_KEY_FILE required when TLS is enabled in %s profile (or set VAULT_FORCE_SECURE_COOKIES=true for proxy termination)", c.Profile)
	}
	// Recovery escrow is recommended but not mandatory: without it, an accidental
	// or malicious account deletion is unrecoverable. Warn rather than hard-fail so
	// operators can opt out deliberately.
	if len(c.RecoveryPublicKeyPEM) == 0 {
		log.Printf("SECURITY WARNING: VAULT_RECOVERY_PUBLIC_KEY_FILE not set — account erasures will not be recoverable")
	}
	return nil
}

func (c *Config) loadSecrets() {
	if mk, err := LoadSecret("MASTER_KEY"); err == nil {
		c.MasterKey = []byte(mk)
	}
	if kr, err := LoadSecret("KMS_ROOT_KEY"); err == nil {
		c.KMSRootKey = []byte(kr)
	}
	if at, err := LoadSecret("ADMIN_TOKEN"); err == nil {
		c.AdminTokenHash = at
	}
	if p, err := LoadSecret("VAULT_PEPPER"); err == nil {
		c.Pepper = p
	}
	if hs, err := LoadSecret("HMAC_SECRET"); err == nil {
		c.HMACSecret = []byte(hs)
	}
	if rk, err := LoadSecret("VAULT_RECOVERY_PUBLIC_KEY"); err == nil {
		c.RecoveryPublicKeyPEM = []byte(rk)
	}
	if dp, err := LoadSecret("DB_MIG_PASSWORD"); err == nil {
		c.DBMigPassword = dp
	}
	if dp, err := LoadSecret("DB_APP_PASSWORD"); err == nil {
		c.DBAppPassword = dp
	}
	if rp, err := LoadSecret("REDIS_PASS"); err == nil {
		c.RedisPass = rp
	}
	if su, err := LoadSecret("SMTP_USER"); err == nil {
		c.SMTPUser = su
	}
	if sp, err := LoadSecret("SMTP_PASS"); err == nil {
		c.SMTPPass = sp
	}
	if sg, err := LoadSecret("SENDGRID_API_KEY"); err == nil {
		c.SendGridAPIKey = sg
	}
	if gs, err := LoadSecret("VAULT_OAUTH_GOOGLE_CLIENT_SECRET"); err == nil {
		c.OAuthGoogleClientSecret = gs
	}
	if gs, err := LoadSecret("VAULT_OAUTH_GITHUB_CLIENT_SECRET"); err == nil {
		c.OAuthGitHubClientSecret = gs
	}
	if fs, err := LoadSecret("VAULT_OAUTH_FACEBOOK_CLIENT_SECRET"); err == nil {
		c.OAuthFacebookClientSecret = fs
	}
}

// OIDCProviderConfig describes one generic OpenID Connect provider.
type OIDCProviderConfig struct {
	Name         string // provider key used in routes/state (e.g. "okta")
	Issuer       string // issuer base URL (discovery: {issuer}/.well-known/openid-configuration)
	ClientID     string
	ClientSecret string
	Scopes       string // optional, space-delimited; "" -> "openid email profile"
}

// loadOIDCProviders parses VAULT_OIDC_PROVIDERS (comma-separated provider names)
// and, for each NAME, reads VAULT_OIDC_<NAME>_{ISSUER,CLIENT_ID,SCOPES} plus the
// client secret via the _FILE convention (VAULT_OIDC_<NAME>_CLIENT_SECRET[_FILE]).
// Providers missing an issuer or client id are skipped.
func (c *Config) loadOIDCProviders() {
	list := os.Getenv("VAULT_OIDC_PROVIDERS")
	if list == "" {
		return
	}
	for _, raw := range strings.Split(list, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		envKey := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		prefix := "VAULT_OIDC_" + envKey + "_"
		issuer := os.Getenv(prefix + "ISSUER")
		clientID := os.Getenv(prefix + "CLIENT_ID")
		if issuer == "" || clientID == "" {
			continue
		}
		secret, _ := LoadSecret(prefix + "CLIENT_SECRET")
		c.OIDCProviders = append(c.OIDCProviders, OIDCProviderConfig{
			Name:         name,
			Issuer:       issuer,
			ClientID:     clientID,
			ClientSecret: secret,
			Scopes:       os.Getenv(prefix + "SCOPES"),
		})
	}
}

// DatabaseURL builds a PostgreSQL connection string for the given role.
// The role must be "migration" (uses vault_mig) or any other value (uses vault_app).
// SSL mode is forced to "disable" in dev profile.
func (c *Config) DatabaseURL(role string) string {
	password := c.DBAppPassword
	user := "vault_app"
	if role == "migration" {
		password = c.DBMigPassword
		user = "vault_mig"
	}
	sslmode := c.DBSSLMode
	if c.Profile == ProfileDev {
		sslmode = "disable"
	}
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     c.DBHost + ":" + c.DBPort,
		Path:     c.DBName,
		RawQuery: "sslmode=" + sslmode,
	}
	return u.String()
}

// RPHost returns the hostname from Origin, used as WebAuthn RPID.
func (c *Config) RPHost() string {
	if u, err := url.Parse(c.Origin); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "localhost"
}

// String returns a redacted config summary (safe for logging).
// String renders a configuration summary suitable for boot-time logging.
// Every secret-bearing field is explicitly routed through redact()/redactStr()
// so static analyzers can see the sanitizer; new secret fields added to Config
// MUST also be added here with an explicit redactor, never printed raw.
func (c *Config) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "profile=%s listen=%s origin=%s\n", c.Profile, c.ListenAddr, c.Origin)
	fmt.Fprintf(&b, "tls=%v db=%s:%s/%s cache=%s\n", c.TLSEnabled, c.DBHost, c.DBPort, c.DBName, c.CacheBackend)
	fmt.Fprintf(&b, "master_key=%s kms_root_key=%s admin_token=%s pepper=%s hmac=%s recovery_pubkey=%s\n",
		redact(c.MasterKey), redact(c.KMSRootKey), redactStr(c.AdminTokenHash), redactStr(c.Pepper), redact(c.HMACSecret), presence(c.RecoveryPublicKeyPEM))
	fmt.Fprintf(&b, "db_mig_pass=%s db_app_pass=%s redis_pass=%s\n",
		redactStr(c.DBMigPassword), redactStr(c.DBAppPassword), redactStr(c.RedisPass))
	fmt.Fprintf(&b, "sendgrid_key=%s smtp_user=%s smtp_pass=%s\n",
		redactStr(c.SendGridAPIKey), redactStr(c.SMTPUser), redactStr(c.SMTPPass))
	fmt.Fprintf(&b, "oauth_secrets=google:%s github:%s facebook:%s\n",
		redactStr(c.OAuthGoogleClientSecret), redactStr(c.OAuthGitHubClientSecret), redactStr(c.OAuthFacebookClientSecret))
	fmt.Fprintf(&b, "access_ttl=%s refresh_ttl=%s remember_ttl=%s\n",
		c.AccessTokenTTL, c.RefreshTokenTTL, c.RememberMeTTL)
	return b.String()
}

func redact(b []byte) string {
	if len(b) == 0 {
		return "<not set>"
	}
	return "<redacted>"
}

func redactStr(s string) string {
	if s == "" {
		return "<not set>"
	}
	return "<redacted>"
}

// presence reports whether non-secret key material is configured without
// redacting it (a public key is not sensitive, but its absence is operationally
// relevant).
func presence(b []byte) string {
	if len(b) == 0 {
		return "<not set>"
	}
	return "set"
}

// isValidHexColor validates a CSS hex color like "#00FF42".
func isValidHexColor(s string) bool {
	if len(s) != 7 || s[0] != '#' {
		return false
	}
	for _, c := range s[1:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// splitTrimLower splits a comma-separated list into lowercased, trimmed,
// non-empty entries. Returns nil for an empty/blank input.
func splitTrimLower(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, raw := range strings.Split(s, ",") {
		if v := strings.ToLower(strings.TrimSpace(raw)); v != "" {
			out = append(out, v)
		}
	}
	return out
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

func envBoolDefault(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v == "true" || v == "1" || v == "yes"
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
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
