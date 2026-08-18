// Package config loads and validates all configuration for The Vault from
// environment variables and secret files. It supports three deployment profiles
// (production, embedded, dev) and enforces the _FILE suffix convention for secrets.
package config

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
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
	// DBStatementTimeout is the server-side ceiling on a single statement
	// (DB_STATEMENT_TIMEOUT). Default 10s; zero disables it. Without it,
	// DBMaxConns pathological queries pin the whole pool and the service stops
	// serving with no error anywhere.
	DBStatementTimeout time.Duration
	// DBLockTimeout is the server-side ceiling on waiting for a lock
	// (DB_LOCK_TIMEOUT). Default 3s; zero disables it.
	DBLockTimeout time.Duration

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
	// SMTPAllowPlaintext permits delivery to an SMTP server that does not
	// advertise STARTTLS (VAULT_SMTP_ALLOW_PLAINTEXT). Default: false — every
	// message carries a bearer secret, so a relay that cannot be upgraded is a
	// failed send. Outside dev the opt-out is accepted only for a loopback
	// SMTP_HOST, which is the one hop that never leaves the machine.
	SMTPAllowPlaintext bool
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

	// MaxSessionLifetime bounds the total age of a refresh-token family, measured
	// from its creation and independent of how often it is refreshed
	// (VAULT_MAX_SESSION_LIFETIME). Without it, rotation grants a fresh full TTL
	// every time and a continuously-refreshing client holds a session forever.
	// Default 720h, matching RememberMeTTL so a session may live as long as the
	// longest single token and never longer. NIST SP 800-63B-4 AAL2 wants 12h;
	// that is a deployment decision, not the default. 0 disables the bound.
	MaxSessionLifetime time.Duration

	// MintEnabled mounts POST /mint (VAULT_MINT_ENABLED). Off by default: the endpoint
	// signs assertions for subjects vault42 never authenticated, so enabling it by
	// accident is an authentication bypass rather than a degraded control. When false
	// the route is not registered at all.
	MintEnabled bool

	// MintAudience is the aud claim stamped on minted tokens (VAULT_MINT_AUDIENCE).
	// Required when MintEnabled, and MUST differ from Origin: a minted token carrying
	// vault42's own audience would authenticate against vault42 itself, turning the
	// oracle into account takeover for every user.
	MintAudience string

	// MintTokenTTL is the lifetime of a minted token when the caller names none
	// (VAULT_MINT_TOKEN_TTL). Default 5m. Minted tokens cannot be revoked, so the
	// lifetime is the only bound on a leaked one.
	MintTokenTTL time.Duration

	// MintMaxTTL caps the caller-requested lifetime (VAULT_MINT_MAX_TTL). Default 5m,
	// with a hard 15m ceiling enforced in service.NewMintService. A request above the
	// cap is refused rather than clamped, so a misconfigured caller is visible.
	MintMaxTTL time.Duration

	// MintAllowedRoles is the allow-list of roles a minted token may carry
	// (VAULT_MINT_ROLES, comma-separated). Empty by default, meaning no role may be
	// minted. The admin-reserved names are refused at construction regardless.
	MintAllowedRoles []string

	// MintAllowedScopes is the allow-list of scopes a minted token may carry
	// (VAULT_MINT_SCOPES, comma-separated). Empty by default. Capability scopes such
	// as kms:unwrap and mint:token are refused regardless of configuration.
	MintAllowedScopes []string

	// SvcDocEnabled mounts the service-scoped JSON document store (VAULT_SVCDOC_ENABLED).
	// Off by default: it is new surface reachable by every existing client-credentials
	// holder, so enabling it is an explicit operator decision.
	SvcDocEnabled bool

	// SvcDocSharedEnabled allows a service to publish a document readable by all other
	// services (VAULT_SVCDOC_SHARED_ENABLED). Off by default; documents are private to
	// the writing service unless this is set and the write asks for it.
	SvcDocSharedEnabled bool

	// SvcDocMaxSize is the per-document ceiling in bytes (VAULT_SVCDOC_MAX_SIZE).
	// Default 65536.
	SvcDocMaxSize int

	// SvcDocMaxPerSubject is the document count ceiling per (subject, service)
	// (VAULT_SVCDOC_MAX_PER_SUBJECT). Default 32.
	SvcDocMaxPerSubject int

	// SvcDocQuotaBytes is the total stored-byte ceiling per subject
	// (VAULT_SVCDOC_QUOTA_BYTES). Default 1 MiB.
	SvcDocQuotaBytes int

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

	// AuditRetentionPeriod is how long audit entries are kept before the sweeper
	// purges them (VAULT_AUDIT_RETENTION_DAYS, in days). Audit rows hold personal
	// data (user ID, IP, user agent, fingerprint hash), so Art. 5(1)(e) caps how
	// long they may live. Default: 0 — disabled. Deleting security logs is not a
	// safe default, so the operator must pick a horizon consistent with the
	// retention table in docs/PRIVACY.md §4.
	AuditRetentionPeriod time.Duration

	// RecoveryRetentionPeriod is how long account-recovery escrow records are kept
	// before the sweeper purges them (VAULT_RECOVERY_RETENTION_DAYS, in days). Each
	// record holds the erased user's email, creation date, roles and display name
	// encrypted to the offline recovery key, and the escrow is exempt from the
	// erasure cascade by design, so Art. 5(1)(e) caps how long it may live.
	// Default: 0 — disabled. The escrow is the only recoverable copy of an erased
	// account, so destroying it is an explicit operator choice, consistent with the
	// retention table in docs/PRIVACY.md §4.
	RecoveryRetentionPeriod time.Duration

	// KeyRefreshInterval is how often pods refresh signing keys from the database
	// (VAULT_KEY_REFRESH_INTERVAL). Default: 60s.
	KeyRefreshInterval time.Duration

	// File is the path to a JSON seed file for declarative user and client
	// creation at startup (VAULT_SEED_FILE). Empty = no seeding.
	File string
}

// Load reads configuration from environment variables and secret files,
// applies profile-specific defaults, and returns a validated Config.
// Secrets are loaded via the _FILE suffix convention (see [LoadSecret]).
//
// The body stays one long straight line of assignments on purpose: every
// setting and its default are readable in the order they are applied, and
// splitting that across functions would scatter the defaults. What is
// extracted is only the parsing that repeats (see envList).
func Load() (*Config, error) {
	// Ahead of everything, including the secret files: VAULT_SECRET_FILE_CONSUME
	// makes the first read of a secret destructive, so a config that is going to
	// be refused must be refused before it deletes the operator's key material.
	if err := checkEnvValues(); err != nil {
		return nil, err
	}
	profile, err := parseProfile(envOr("VAULT_PROFILE", "production"))
	if err != nil {
		return nil, err
	}

	c := &Config{
		Profile: profile,

		ListenAddr: os.Getenv("LISTEN_ADDR"),
		Origin:     os.Getenv("VAULT_ORIGIN"),

		TLSEnabled:  envBool("VAULT_TLS_ENABLED"),
		TLSCertFile: os.Getenv("VAULT_TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("VAULT_TLS_KEY_FILE"),

		DBHost:     envOr("DB_HOST", "localhost"),
		DBPort:     envOr("DB_PORT", "5432"),
		DBName:     envOr("DB_NAME", "vault"),
		DBSSLMode:  envOr("DB_SSLMODE", "require"),
		DBMaxConns: envInt("DB_MAX_CONNS", 0),

		DBStatementTimeout: envDuration("DB_STATEMENT_TIMEOUT", 10*time.Second),
		DBLockTimeout:      envDuration("DB_LOCK_TIMEOUT", 3*time.Second),

		CacheBackend: os.Getenv("CACHE_BACKEND"),
		RedisAddr:    os.Getenv("REDIS_ADDR"),

		EmailProvider: envOr("VAULT_EMAIL_PROVIDER", "smtp"),
		SMTPHost:      os.Getenv("SMTP_HOST"),
		SMTPPort:      envOr("SMTP_PORT", "587"),
		EmailFrom:     os.Getenv("VAULT_EMAIL_FROM"),

		SMTPAllowPlaintext: envBool("VAULT_SMTP_ALLOW_PLAINTEXT"),

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

		MaxSessionLifetime: envDuration("VAULT_MAX_SESSION_LIFETIME", 720*time.Hour),

		MintEnabled:  envBool("VAULT_MINT_ENABLED"),
		MintAudience: strings.TrimSpace(os.Getenv("VAULT_MINT_AUDIENCE")),
		MintTokenTTL: envDuration("VAULT_MINT_TOKEN_TTL", 5*time.Minute),
		MintMaxTTL:   envDuration("VAULT_MINT_MAX_TTL", 5*time.Minute),

		SvcDocEnabled:       envBool("VAULT_SVCDOC_ENABLED"),
		SvcDocSharedEnabled: envBool("VAULT_SVCDOC_SHARED_ENABLED"),
		SvcDocMaxSize:       envInt("VAULT_SVCDOC_MAX_SIZE", 64*1024),
		SvcDocMaxPerSubject: envInt("VAULT_SVCDOC_MAX_PER_SUBJECT", 32),
		SvcDocQuotaBytes:    envInt("VAULT_SVCDOC_QUOTA_BYTES", 1024*1024),

		KeyRotationDB:      envBool("VAULT_KEY_ROTATION_DB"),
		KeyRetentionPeriod: envDuration("VAULT_KEY_RETENTION_PERIOD", time.Hour),

		AuditRetentionPeriod:    time.Duration(envInt("VAULT_AUDIT_RETENTION_DAYS", 0)) * 24 * time.Hour,
		RecoveryRetentionPeriod: time.Duration(envInt("VAULT_RECOVERY_RETENTION_DAYS", 0)) * 24 * time.Hour,

		KeyRefreshInterval: envDuration("VAULT_KEY_REFRESH_INTERVAL", 60*time.Second),

		File: os.Getenv("VAULT_SEED_FILE"),
	}

	// Load honeypot trap users from comma-separated list
	c.HoneypotTrapUsers = envListFold("VAULT_HONEYPOT_TRAP_USERS", strings.ToLower)

	// Load trusted proxies from comma-separated CIDR/IP list
	c.TrustedProxies = envList("TRUSTED_PROXIES")

	// Real IP header (proxy-specific, e.g. "CF-Connecting-IP")
	c.RealIPHeader = strings.TrimSpace(os.Getenv("REAL_IP_HEADER"))

	// Geo IP header (proxy-specific, e.g. "CF-IPCountry")
	c.GeoIPHeader = strings.TrimSpace(os.Getenv("GEO_IP_HEADER"))

	// TLS fingerprint header (proxy-specific, e.g. "X-TLS-Fingerprint")
	c.TLSFingerprintHeader = strings.TrimSpace(os.Getenv("VAULT_TLS_FINGERPRINT_HEADER"))

	// Mint allow-lists. Absent means empty, which denies every role and scope: a
	// signing oracle that grants nothing is the safe failure, so no default is
	// substituted here.
	c.MintAllowedRoles = envList("VAULT_MINT_ROLES")
	c.MintAllowedScopes = envList("VAULT_MINT_SCOPES")

	// Load IP allowlist/blocklist from comma-separated CIDR/IP list
	c.IPAllowlist = envList("IP_ALLOWLIST")
	c.IPBlocklist = envList("IP_BLOCKLIST")

	// Load geo allowlist/blocklist (uppercase country codes)
	c.GeoAllowlist = envListFold("GEO_ALLOWLIST", strings.ToUpper)
	c.GeoBlocklist = envListFold("GEO_BLOCKLIST", strings.ToUpper)

	// Apply profile defaults for any unset values
	applyProfileDefaults(c)

	// Embedded-trust shortcut: when an operator sets
	// VAULT_EMBEDDED_TRUSTED_UPSTREAM=true, vault42 is running behind a
	// sibling proxy on the same private network (typical Hermod/k8s pod
	// pattern). Auto-trust RFC1918 ranges so X-Forwarded-For from that
	// upstream is honored for ClientIP() — required for per-attacker
	// rate-limit + audit attribution. Explicit TRUSTED_PROXIES /
	// REAL_IP_HEADER env values always win; this only fills the gaps.
	if c.EmbeddedTrustedUpstream {
		// Fail closed: this shortcut auto-trusts whole RFC1918 + loopback ranges
		// and blindly honors X-Forwarded-For, collapsing per-IP rate-limit and
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

	// The password floor is the only length control on registration and reset:
	// AuthService.Register and PasswordHandler both compare the rune count
	// against this number and nothing downstream enforces a minimum of its own,
	// so a deployment that sets it to 4 accepts a password an offline attacker
	// enumerates in seconds. Dev gets a lower floor, not an absent one; a local
	// login is not a deployment, but a build that accepts a four-character
	// password is not a password check either.
	// The plaintext-SMTP opt-out is scoped to the relay it was meant for. An
	// operator who sets it against a remote host is not accepting a local hop,
	// they are mailing one-time codes across a network in cleartext.
	if c.SMTPAllowPlaintext && c.Profile != ProfileDev && !isLoopbackSMTPHost(c.SMTPHost) {
		return nil, fmt.Errorf("VAULT_SMTP_ALLOW_PLAINTEXT is accepted only for a loopback SMTP_HOST in %s profile (got %q)", c.Profile, c.SMTPHost)
	}

	if floor := passwordFloorFor(c.Profile); c.PasswordMinLength < floor {
		return nil, fmt.Errorf("VAULT_PASSWORD_MIN_LENGTH must be at least %d in %s profile (got %d)", floor, c.Profile, c.PasswordMinLength)
	}

	// Enforce HMAC secret minimum length in non-dev profiles
	if len(c.HMACSecret) > 0 && len(c.HMACSecret) < 32 {
		if c.Profile != ProfileDev {
			return nil, fmt.Errorf("HMAC secret must be at least 32 bytes (got %d)", len(c.HMACSecret))
		}
		log.Println("SECURITY WARNING: HMAC secret is shorter than 32 bytes")
	}

	// LOG_LEVEL is read here only to announce that it does nothing. It used to be
	// parsed into a Config field, defaulted per profile and documented as "log
	// verbosity" while no vault42 binary ever read it, so LOG_LEVEL=error and
	// LOG_LEVEL=debug produced byte-for-byte identical output and an operator who
	// set it to cut log exposure got none. Rejecting the variable outright would
	// be the worse failure: docs/spec.md records LOG_LEVEL among the unprefixed
	// names a co-located deployment is likely to have already set for other
	// software, so a hard error would turn an inherited variable into a boot loop.
	// One line at startup is what keeps the no-op from being silent again.
	if os.Getenv("LOG_LEVEL") != "" {
		log.Println("NOTICE: LOG_LEVEL is set but vault42 has no log-verbosity control; it is ignored and every log line is emitted")
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
	// Checked ahead of the dev short-circuit, for the reason checkMintAudience
	// documents.
	if err := c.checkMintAudience(); err != nil {
		return err
	}
	// Also checked ahead of the dev short-circuit. A dev operator who mounts an
	// admin token and gets a generated one instead learns the wrong thing about
	// where the credential comes from, and carries that into production.
	if err := c.checkAdminTokenFile(); err != nil {
		return err
	}
	if c.Profile == ProfileDev {
		return nil
	}
	if len(c.HMACSecret) < 32 {
		return fmt.Errorf("HMAC_SECRET_FILE required (>=32 bytes) in %s profile (got %d)", c.Profile, len(c.HMACSecret))
	}
	if len(c.Pepper) < 32 {
		return fmt.Errorf("VAULT_PEPPER_FILE required (>=32 bytes) in %s profile (got %d)", c.Profile, len(c.Pepper))
	}
	// Production is the only profile that must have a master key at boot.
	// HMAC and pepper already refuse to start without theirs; the master key
	// is the one secret that used to be checked only when something first
	// tried to encrypt, so a production vault42 would come up with no key
	// and TOTP, identity, blobs and service documents would fail at request
	// time. Embedded, honeypot and dev keep that trade-off.
	if c.Profile == ProfileProduction && len(c.MasterKey) != 32 {
		return fmt.Errorf("MASTER_KEY_FILE required (32 bytes) in %s profile (got %d)", c.Profile, len(c.MasterKey))
	}
	if c.Origin == "" {
		return fmt.Errorf("VAULT_ORIGIN required in %s profile", c.Profile)
	}
	// Rate limiting is the brute-force defense on the auth endpoints; refuse to
	// silently run a non-dev server with it disabled.
	if !c.RateLimitEnabled && !envBool("VAULT_ALLOW_RATE_LIMIT_DISABLED") {
		return fmt.Errorf("refusing to disable rate limiting in %s profile; set VAULT_ALLOW_RATE_LIMIT_DISABLED=true to override", c.Profile)
	}
	// The rate limiter above only limits what it can see. Production defaults
	// CACHE_BACKEND to redis, and the cache is where every cross-pod control
	// lives: the login and password-reset limiters, the KMS unwrap budget, the
	// OAuth state written by one pod and read by another, and the TOTP replay
	// guard. An unset REDIS_ADDR failed the ping, main logged one line and
	// substituted an in-process memory cache, and the server reported itself
	// healthy while every one of those silently became per-pod. With four
	// replicas the login limiter admits four times its configured attempts and
	// an OAuth callback landing on the wrong pod cannot find its own state.
	//
	// Production only. The embedded profile is a single process, where the
	// memory cache is not a downgrade but the same thing by another name, and
	// nothing there is shared across replicas to lose.
	if c.Profile == ProfileProduction && c.CacheBackend == "redis" && c.RedisAddr == "" {
		return fmt.Errorf("REDIS_ADDR required when CACHE_BACKEND=redis in %s profile; without it the cache falls back to per-process memory and every shared-state control degrades by the replica count", c.Profile)
	}
	// M5 and M4 stay inline rather than moving to a checkTLSTermination helper
	// like the guards above and below them. Two compliance gates read the text of
	// Validate itself and fail if the TLS refusals are not in it:
	// TestOWASP_A02_2025_ProductionProfileRefusesInsecureDefaults reads only as far
	// as the next func, and TestASVS_V12_2_1_PlaintextRequiresAnExplicitOverride
	// wants VAULT_ALLOW_PLAINTEXT under this signature. Extracting them passes the
	// linter and silently converts a checked claim into an unchecked one.
	//
	// M5: refuse to silently disable TLS.
	if !c.TLSEnabled && !c.ForceSecureCookies && !envBool("VAULT_ALLOW_PLAINTEXT") {
		return fmt.Errorf("refusing to disable TLS in %s profile; set VAULT_ALLOW_PLAINTEXT=true (e.g. behind a TLS-terminating proxy) to override", c.Profile)
	}
	// M4: TLS enabled but no cert/key silently falls back to plaintext while the
	// Secure cookie flag is set. Require certs unless proxy-termination is opted in.
	if c.TLSEnabled && (c.TLSCertFile == "" || c.TLSKeyFile == "") && !c.ForceSecureCookies {
		return fmt.Errorf("VAULT_TLS_CERT_FILE and VAULT_TLS_KEY_FILE required when TLS is enabled in %s profile (or set VAULT_FORCE_SECURE_COOKIES=true for proxy termination)", c.Profile)
	}
	if err := c.checkGeoFence(); err != nil {
		return err
	}
	if err := c.checkDatabaseLink(); err != nil {
		return err
	}
	c.warnOnDegradedControls()
	return nil
}

// checkMintAudience refuses a mint oracle whose tokens authenticate against
// vault42 itself.
//
// A mint audience equal to the issuer makes every minted token valid against
// vault42, so the oracle becomes account takeover for any subject. Validate
// runs this ahead of the dev short-circuit because that is not a
// production-only hazard, and a dev deployment that teaches the wrong
// configuration gets copied.
func (c *Config) checkMintAudience() error {
	if !c.MintEnabled {
		return nil
	}
	if c.MintAudience == "" {
		return fmt.Errorf("VAULT_MINT_AUDIENCE required when VAULT_MINT_ENABLED is set")
	}
	if c.MintAudience == c.Origin {
		return fmt.Errorf("VAULT_MINT_AUDIENCE must differ from VAULT_ORIGIN; a minted token carrying vault42's own audience authenticates against vault42")
	}
	return nil
}

// warnOnDegradedControls reports the settings that cost a deployment a control
// without costing it a boot. Each one refuses to hard-fail on purpose: the
// effect is a weaker deployment rather than an open door, and a deployment
// already running this way must not stop booting on upgrade.
func (c *Config) warnOnDegradedControls() {
	// A proxy header nobody is trusted to set is a header that is never read.
	// ClientIP returns the peer address when TrustedProxies is empty, so every
	// client behind the ingress shares one rate-limit bucket, one lockout counter
	// and one address in the audit log, and the operator's evidence that
	// per-client attribution works is the variable they set. The effect is lost
	// attribution, not a lost gate.
	if len(c.TrustedProxies) == 0 {
		for _, h := range []struct{ name, value string }{
			{"REAL_IP_HEADER", c.RealIPHeader},
			{"VAULT_TLS_FINGERPRINT_HEADER", c.TLSFingerprintHeader},
		} {
			if h.value != "" {
				log.Printf("SECURITY WARNING: %s is set but TRUSTED_PROXIES is empty; the header is never read and every client is attributed to the address of the hop in front of vault42", h.name)
			}
		}
	}
	// Recovery escrow is recommended but not mandatory: without it, an accidental
	// or malicious account deletion is unrecoverable. Warn rather than hard-fail so
	// operators can opt out deliberately.
	if len(c.RecoveryPublicKeyPEM) == 0 {
		log.Printf("SECURITY WARNING: VAULT_RECOVERY_PUBLIC_KEY_FILE not set — account erasures will not be recoverable")
	}
}

// checkDatabaseLink refuses a non-dev database connection that is not
// encrypted.
//
// The connection carries the role password in the startup packet and every
// row of every table after it, including the encrypted TOTP secrets and the
// password hashes. Three of the six legal modes do not guarantee it is
// encrypted, and "prefer" is the one to watch: it negotiates TLS and falls
// back to plaintext without telling anyone.
//
// This refuses rather than warns, and it refuses for the same reason Validate's
// M5 guard refuses a disabled listener: an unencrypted link is a control that
// is absent, and a SECURITY WARNING that boots anyway is indistinguishable from
// no control at all once the log scrolls. Deployments that run Postgres in the
// same pod legitimately want "disable"
// (charts/vault/values-{bridge,embedded,honeypot,local}.yaml), so they say so
// in the manifest with VAULT_ALLOW_PLAINTEXT_DB — the shape
// VAULT_ALLOW_PLAINTEXT and VAULT_ALLOW_RATE_LIMIT_DISABLED already use, which
// keeps the posture visible where an operator reviews it.
//
// Only the modes that are explicitly unencrypted refuse. An empty DBSSLMode
// is unreachable through Load (envOr defaults it to "require" and the enum
// check rejects every other spelling) and keeps the warning, so a Config
// assembled in code is judged on what it says rather than on what it omits.
func (c *Config) checkDatabaseLink() error {
	if slices.Contains(unencryptedSSLModes, c.DBSSLMode) && !envBool("VAULT_ALLOW_PLAINTEXT_DB") {
		return fmt.Errorf("refusing to use an unencrypted database connection in %s profile: DB_SSLMODE=%s carries the role password and every row in cleartext; set VAULT_ALLOW_PLAINTEXT_DB=true when the link is private (same-pod or loopback Postgres)", c.Profile, c.DBSSLMode)
	}
	if !slices.Contains(encryptedSSLModes, c.DBSSLMode) {
		log.Printf("SECURITY WARNING: DB_SSLMODE=%s does not guarantee an encrypted database connection in %s profile; role passwords and every row travel in cleartext unless the link is private", c.DBSSLMode, c.Profile)
	}
	return nil
}

// checkGeoFence refuses a geo-fence that cannot fire.
//
// middleware.IPAccess runs the geo ladder only when GEO_IP_HEADER is set, and
// reads the country only from a hop listed in TRUSTED_PROXIES. Miss either and
// the country is never established: a blocklist then refuses nobody while the
// operator's config records the countries they believe are banned, and an
// allowlist refuses everybody. Both halves are configured in the same place and
// neither used to be checked anywhere.
func (c *Config) checkGeoFence() error {
	if len(c.GeoAllowlist) == 0 && len(c.GeoBlocklist) == 0 {
		return nil
	}
	if c.GeoIPHeader == "" {
		return fmt.Errorf("GEO_IP_HEADER required when GEO_ALLOWLIST or GEO_BLOCKLIST is set in %s profile; without it the country is never read and the geo fence never fires", c.Profile)
	}
	if len(c.TrustedProxies) == 0 {
		return fmt.Errorf("TRUSTED_PROXIES required when GEO_IP_HEADER is set in %s profile; the country is believed only from a trusted hop, so with no trusted proxy the geo fence never fires", c.Profile)
	}
	return nil
}

// isLoopbackSMTPHost reports whether SMTP_HOST names a relay on this machine.
// "localhost" is accepted by name because that is how a sidecar relay is
// usually addressed; everything else has to resolve to a loopback literal.
func isLoopbackSMTPHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// passwordMinLengthFloor is the shortest VAULT_PASSWORD_MIN_LENGTH accepted
// outside dev, and it is the figure docs/COMPLIANCE.md and README.md publish.
// NIST SP 800-63B-4 §3.1.1.2 raised the floor for a password used as the only
// authenticator from 8 to 15 characters, and vault42 permits single-factor
// login (MFA is configurable), so 15 is the number an operator may not go
// under. It equals the package default deliberately: a claim that the product
// enforces 15 is false the moment the enforced floor is lower than the figure.
const passwordMinLengthFloor = 15

// devPasswordMinLengthFloor is the shortest VAULT_PASSWORD_MIN_LENGTH accepted
// in the dev profile. Dev deliberately sits below the published floor so a
// seeded local account does not need a 15-character secret, but it is still a
// floor: NIST SP 800-63B-4 §3.1.1.1 requires a verifier to accept memorized
// secrets of at least 8 characters, and a build that accepts fewer is not
// exercising the password path the deployment profiles run.
const devPasswordMinLengthFloor = 8

// passwordFloorFor returns the shortest VAULT_PASSWORD_MIN_LENGTH the profile
// accepts. Every profile has one; dev's is merely lower.
func passwordFloorFor(p Profile) int {
	if p == ProfileDev {
		return devPasswordMinLengthFloor
	}
	return passwordMinLengthFloor
}

// argon2idPrefix marks the PHC-encoded form of an Argon2id hash. Its presence
// is what tells ADMIN_TOKEN_FILE's two accepted forms apart: a hash, which is
// stored verbatim, or a plaintext token, which cli.InitAdminToken hashes before
// storing. A random token cannot collide with it.
const argon2idPrefix = "$argon2id$"

// adminTokenMinLength is the shortest plaintext ADMIN_TOKEN_FILE accepted
// outside dev. The admin CLI can add clients and revoke every session, and
// nothing rate limits it, so a token an operator could type is a bad one.
// scripts/generate-secrets.sh writes 64 hex characters.
const adminTokenMinLength = 16

// checkAdminTokenFile refuses to start on an ADMIN_TOKEN_FILE the admin CLI
// could never use.
//
// That file is the operator's only way to choose the admin credential rather
// than have one minted on first boot and printed to stdout, which under systemd
// is the journal (docs/localhost-profile.md §4.5 counts that on its threat
// table). Every way of getting it wrong used to be silent, because the value
// was parsed into a config field that nothing read: an absent mount, an empty
// file or a truncated hash all produced a server that started clean and then
// rejected the operator's token with "Admin authentication required."
//
// The file is read here without consuming it. internal/cli performs the real
// read, and VAULT_SECRET_FILE_CONSUME makes the first read destructive, so a
// LoadSecret call here would delete the file before its only consumer saw it.
func (c *Config) checkAdminTokenFile() error {
	path := os.Getenv("ADMIN_TOKEN_FILE")
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- path from operator env var (_FILE convention), cleaned with filepath.Clean
	if err != nil {
		return fmt.Errorf("read ADMIN_TOKEN_FILE %q: %w", path, err)
	}

	secret := strings.TrimSpace(string(data))
	switch {
	case secret == "":
		return fmt.Errorf("ADMIN_TOKEN_FILE %q is empty; it must hold either the admin token or its Argon2id hash", path)
	case strings.HasPrefix(secret, argon2idPrefix):
		if !isArgon2idHash(secret) {
			return fmt.Errorf("ADMIN_TOKEN_FILE %q holds a malformed Argon2id hash; no token can ever verify against it", path)
		}
	case len(secret) < adminTokenMinLength:
		if c.Profile != ProfileDev {
			return fmt.Errorf("admin token in ADMIN_TOKEN_FILE %q is %d characters; %s profile requires at least %d", path, len(secret), c.Profile, adminTokenMinLength)
		}
		log.Printf("SECURITY WARNING: admin token in ADMIN_TOKEN_FILE is shorter than %d characters", adminTokenMinLength)
	}
	return nil
}

// isArgon2idHash reports whether s has the full PHC layout
// $argon2id$v=..$m=..,t=..,p=..$salt$hash. A prefix-only check would admit a
// truncated hash, which parses as nothing and locks the CLI out for good.
func isArgon2idHash(s string) bool {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	for _, p := range parts[2:] {
		if p == "" {
			return false
		}
	}
	return true
}

func (c *Config) loadSecrets() {
	if mk, err := LoadSecretBinary("MASTER_KEY", 32); err == nil {
		c.MasterKey = mk
	}
	if kr, err := LoadSecret("KMS_ROOT_KEY"); err == nil {
		c.KMSRootKey = []byte(kr)
	}
	// ADMIN_TOKEN is deliberately absent: cli.New reads it, the same way
	// cmd/vault reads SIGNING_KEY. Loading it here consumed the file (see
	// VAULT_SECRET_FILE_CONSUME) on behalf of a field nothing ever read.
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
	// timezone is a startup runtime parameter, so pgx sends it in the startup
	// packet and every session the pool opens is already in UTC.
	//
	// docs/spec.md promises RFC 3339 in UTC for every timestamp the API emits,
	// and nothing enforced it. Postgres renders a timestamptz in the session's
	// TimeZone, pgx builds a time.Time carrying that offset, and the handlers
	// marshal it through unchanged, so the offset in a response body was
	// whatever zone the database server happened to run in. Both spellings name
	// the same instant and both are valid RFC 3339, which is why nothing ever
	// failed; what breaks is comparing timestamps as strings, and a client
	// slicing the first ten characters for a date gets the wrong day for two
	// hours every night.
	//
	// Setting it on the connection is one place rather than dozens of marshal
	// sites, and a handler added later returning a new timestamp inherits it.
	q := url.Values{}
	q.Set("sslmode", sslmode)
	q.Set("timezone", "UTC")

	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     c.DBHost + ":" + c.DBPort,
		Path:     c.DBName,
		RawQuery: q.Encode(),
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
	fmt.Fprintf(&b, "master_key=%s kms_root_key=%s pepper=%s hmac=%s recovery_pubkey=%s\n",
		redact(c.MasterKey), redact(c.KMSRootKey), redactStr(c.Pepper), redact(c.HMACSecret), presence(c.RecoveryPublicKeyPEM))
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

// envList reads a comma-separated environment variable. Blank entries are
// dropped rather than kept as empty strings, so a trailing comma or a list
// wrapped over lines in a manifest does not add a member that matches nothing
// but still makes the list non-empty — and a non-empty allowlist is the
// difference between "no restriction" and "only these" for the IP and geo
// fences. An unset variable yields nil, matching the append-based form this
// replaced.
func envList(key string) []string {
	var out []string
	for _, entry := range strings.Split(os.Getenv(key), ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}
	return out
}

// envListFold is envList for the lists whose members are compared without
// regard to case: trap usernames are held lowercase and country codes
// uppercase, folded once here so no comparison downstream has to remember to.
func envListFold(key string, fold func(string) string) []string {
	out := envList(key)
	for i, entry := range out {
		out[i] = fold(entry)
	}
	return out
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envBool and envBoolDefault answer with the profile default when the value is
// one parseBoolEnv refuses. Load rejects those before any of this runs, so the
// fallback only covers a Config assembled without Load.
func envBool(key string) bool {
	return envBoolDefault(key, false)
}

func envBoolDefault(key string, def bool) bool {
	v, set, err := parseBoolEnv(key)
	if err != nil || !set {
		return def
	}
	return v
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
