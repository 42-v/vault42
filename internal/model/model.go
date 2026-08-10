// Package model defines the domain types used across all layers of The Vault.
//
// These are persistence types, not wire types. Every public response is built
// from an explicit view struct in the handler that owns the endpoint. The JSON
// tags here exist so that a direct serialization, if one is ever added by
// mistake, still produces the snake_case shape the rest of the API uses instead
// of Go field names.
//
// Fields carrying credential material or a privacy-sensitive derived identifier
// are tagged json:"-". A view that genuinely needs one must name it explicitly,
// so no accidental serialization can put it on the wire.
package model

import "time"

// User represents a registered user.
//
// Roles carries the JWT "roles" claim issued at login. Empty defaults to
// ["user"] in the auth flow. Reserved admin-tier role names ("admin",
// "super_admin") are rejected by the seed validator and filtered before
// JWT issuance — those tiers belong to AdminUser and are reachable only
// through the admin gateway.
type User struct {
	ID               string     `json:"id"`
	Email            string     `json:"email"`
	EmailVerified    bool       `json:"email_verified"`
	PasswordHash     string     `json:"-"`
	DisplayName      string     `json:"display_name"`
	AvatarURL        string     `json:"avatar_url"`
	Locale           string     `json:"locale"`
	MFARequired      bool       `json:"mfa_required"`
	LockedUntil      *time.Time `json:"locked_until"`
	FailedLoginCount int        `json:"failed_login_count"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Roles            []string   `json:"roles"`
	// Account-state flags (legacy-platform parity, migration 004).
	Disabled    bool       `json:"disabled"`
	Banned      bool       `json:"banned"`
	BanReason   string     `json:"ban_reason"`
	LastLoginAt *time.Time `json:"last_login_at"`
	Deleted     bool       `json:"deleted"`
	DeletedAt   *time.Time `json:"deleted_at"`
	// Account import (the legacy platform migration, migration 006).
	ImportPending bool   `json:"import_pending"`
	ImportedFrom  string `json:"imported_from"`
	LegacyID      string `json:"legacy_id"`
}

// PasswordHistory tracks previous password hashes to prevent reuse.
type PasswordHistory struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// SocialAccount links an OAuth provider to a user.
type SocialAccount struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	Provider        string    `json:"provider"`
	ProviderUserID  string    `json:"provider_user_id"`
	Email           string    `json:"email"`
	AccessTokenEnc  string    `json:"-"`
	RefreshTokenEnc string    `json:"-"`
	CreatedAt       time.Time `json:"created_at"`
}

// AccountRecovery is one append-only escrow record written when a user account
// is erased. Payload is a hybrid-asymmetric ciphertext (see crypto.EncryptRecovery)
// of the recoverable profile (email, created_at, roles, display_name). The
// server cannot decrypt it — only the holder of the offline recovery private
// key can, to restore the deleted user from backup. Pseudonym is an HMAC of the
// user id so a record can be correlated to a (soft-deleted) user without
// storing the plaintext identity here.
type AccountRecovery struct {
	ID        string    `json:"id"`
	Pseudonym string    `json:"-"`
	Payload   []byte    `json:"-"`
	DeletedAt time.Time `json:"deleted_at"`
	DeletedBy string    `json:"deleted_by"`
	Reason    string    `json:"reason"`
}

// Client represents a registered service client.
type Client struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	SecretHash   string    `json:"-"`
	Role         string    `json:"role"`
	Scopes       []string  `json:"scopes"`
	RedirectURIs []string  `json:"redirect_uris"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RefreshToken represents a stored refresh token.
type RefreshToken struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	ClientID        string    `json:"client_id"`
	TokenHash       string    `json:"-"`
	FamilyID        string    `json:"family_id"`
	DeviceID        string    `json:"device_id"`
	FingerprintHash string    `json:"-"`
	ExpiresAt       time.Time `json:"expires_at"`
	Used            bool      `json:"used"`
	Revoked         bool      `json:"revoked"`
	CreatedAt       time.Time `json:"created_at"`
}

// Device represents a known device/fingerprint for a user.
type Device struct {
	ID              string     `json:"id"`
	UserID          string     `json:"user_id"`
	FingerprintHash string     `json:"-"`
	FriendlyName    string     `json:"friendly_name"`
	Trusted         bool       `json:"trusted"`
	TrustedUntil    *time.Time `json:"trusted_until"`
	IP              string     `json:"ip"`
	UserAgent       string     `json:"user_agent"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	FirstSeenAt     time.Time  `json:"first_seen_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

// TOTPSecret holds an encrypted TOTP secret for a user.
type TOTPSecret struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	SecretEnc string    `json:"-"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

// WebAuthnCredential holds a WebAuthn credential for a user.
type WebAuthnCredential struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	CredentialID []byte `json:"credential_id"`
	PublicKey    []byte `json:"public_key"`
	SignCount    int    `json:"sign_count"`
	// Flags is the raw authenticator flags byte (UP/UV/BE/BS) from the last
	// verified ceremony. go-webauthn rejects a login whose BackupEligible flag
	// disagrees with the stored one, so this has to survive round trips. Zero
	// means no flags were ever recorded: user presence is mandatory in every
	// ceremony, so a genuine value always has at least bit 0 set.
	Flags        int       `json:"flags"`
	FriendlyName string    `json:"friendly_name"`
	CreatedAt    time.Time `json:"created_at"`
}

// BackupCode holds a hashed backup code for a user.
type BackupCode struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	CodeHash  string     `json:"-"`
	Used      bool       `json:"used"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `json:"created_at"`
}

// RateLimit represents a rate limit counter entry.
type RateLimit struct {
	Key         string    `json:"key"`
	WindowStart time.Time `json:"window_start"`
	Count       int       `json:"count"`
}

// AuditEntry represents an audit log entry.
//
// FingerprintHash is an HMAC of a device fingerprint: it correlates events
// across accounts and is never part of a response. DeviceID is the identifier
// an operator can act on, and that is what the admin audit view carries.
type AuditEntry struct {
	ID              string                 `json:"id"`
	Timestamp       time.Time              `json:"timestamp"`
	EventType       string                 `json:"event_type"`
	UserID          string                 `json:"user_id"`
	ClientID        string                 `json:"client_id"`
	IP              string                 `json:"ip"`
	UserAgent       string                 `json:"user_agent"`
	FingerprintHash string                 `json:"-"`
	DeviceID        string                 `json:"device_id"`
	Metadata        map[string]interface{} `json:"metadata"`
	RiskScore       int                    `json:"risk_score"`
}

// AdminConfig represents a key-value configuration entry.
type AdminConfig struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IdentityProfile holds encrypted PII for a user, keyed by pseudonym.
type IdentityProfile struct {
	PseudonymID string    `json:"pseudonym_id"`
	DataEnc     []byte    `json:"-"`
	Version     int       `json:"version"`
	UpdatedAt   time.Time `json:"updated_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// Blob holds an encrypted user data blob, keyed by pseudonym.
type Blob struct {
	ID          string    `json:"id"`
	PseudonymID string    `json:"pseudonym_id"`
	RefHash     string    `json:"-"` // HMAC of the reference name (empty for unnamed blobs)
	LabelEnc    []byte    `json:"-"`
	DataEnc     []byte    `json:"-"`
	SizeBytes   int       `json:"size_bytes"`
	StoredBytes int       `json:"stored_bytes"`
	Checksum    string    `json:"checksum"`
	CreatedAt   time.Time `json:"created_at"`
}

// BlobQuota summarizes a user's blob storage usage.
type BlobQuota struct {
	UsedBytes int `json:"used_bytes"`
	UsedCount int `json:"used_count"`
}

// AdminRole represents a role from the auth.admin_roles reference table.
type AdminRole struct {
	Role        string `json:"role"`
	Description string `json:"description"`
	Rank        int    `json:"rank"`
}

// AppRole is an entry in the custom roles catalog (auth.app_roles). User roles
// are validated against this catalog at JWT issuance. Reserved=true entries are
// catalog-protected and cannot be deleted via the admin API.
type AppRole struct {
	Name        string    `json:"name"`
	Namespace   string    `json:"namespace"`
	Description string    `json:"description"`
	Reserved    bool      `json:"reserved"`
	CreatedAt   time.Time `json:"created_at"`
}

// EmailBranding holds the per-app white-label overrides applied to auth emails.
// App is the tenant slug (e.g. "acme"). Any empty field falls back to the
// global default at render time. FromAddress is honoured only when its domain
// is on the configured From allowlist (see config.EmailFromAllowedDomains).
type EmailBranding struct {
	App          string    `json:"app"`
	AppName      string    `json:"app_name"`
	LogoURL      string    `json:"logo_url"`
	PrimaryColor string    `json:"primary_color"`
	FromName     string    `json:"from_name"`
	FromAddress  string    `json:"from_address"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	UpdatedBy    string    `json:"updated_by"`
}

// EmailTemplate is a per-app, per-type full override of an auth email body.
// TemplateName is one of the email.Template* constants. When absent or
// disabled, the global template is rendered with the app's branding instead.
type EmailTemplate struct {
	ID           string    `json:"id"`
	App          string    `json:"app"`
	TemplateName string    `json:"template_name"`
	Subject      string    `json:"subject"`
	HTMLContent  string    `json:"html_content"`
	TextContent  string    `json:"text_content"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by"`
	UpdatedAt    time.Time `json:"updated_at"`
	UpdatedBy    string    `json:"updated_by"`
}

// AdminUser represents an admin gateway operator account.
// Admin accounts are stored in auth.admin_users, fully decoupled from auth.users.
// The Role field is populated from the auth.admin_roles reference table via JOIN.
type AdminUser struct {
	ID               string     `json:"id"`
	Username         string     `json:"username"`
	PasswordHash     string     `json:"-"`
	Role             string     `json:"role"`
	TOTPSecretEnc    string     `json:"-"`
	TOTPVerified     bool       `json:"totp_verified"`
	LockedUntil      *time.Time `json:"locked_until"`
	FailedLoginCount int        `json:"failed_login_count"`
	LastTOTPCounter  int64      `json:"-"`
	LastLoginAt      *time.Time `json:"last_login_at"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	CreatedBy        string     `json:"created_by"`
}

// AdminSession represents an active admin gateway session.
type AdminSession struct {
	ID        string    `json:"id"`
	AdminID   string    `json:"admin_id"`
	TokenHash string    `json:"-"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}
