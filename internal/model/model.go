// Package model defines the domain types used across all layers of The Vault.
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
	ID               string
	Email            string
	EmailVerified    bool
	PasswordHash     string
	DisplayName      string
	AvatarURL        string
	Locale           string
	MFARequired      bool
	LockedUntil      *time.Time
	FailedLoginCount int
	CreatedAt        time.Time
	UpdatedAt        time.Time
	Roles            []string
	// Account-state flags (BeOn3 parity, migration 004).
	Disabled    bool
	Banned      bool
	BanReason   string
	LastLoginAt *time.Time
	Deleted     bool
	DeletedAt   *time.Time
}

// PasswordHistory tracks previous password hashes to prevent reuse.
type PasswordHistory struct {
	ID           string
	UserID       string
	PasswordHash string
	CreatedAt    time.Time
}

// SocialAccount links an OAuth provider to a user.
type SocialAccount struct {
	ID              string
	UserID          string
	Provider        string
	ProviderUserID  string
	Email           string
	AccessTokenEnc  string
	RefreshTokenEnc string
	CreatedAt       time.Time
}

// Client represents a registered service client.
type Client struct {
	ID           string
	Name         string
	SecretHash   string
	Role         string
	Scopes       []string
	RedirectURIs []string
	Active       bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// RefreshToken represents a stored refresh token.
type RefreshToken struct {
	ID              string
	UserID          string
	ClientID        string
	TokenHash       string
	FamilyID        string
	DeviceID        string
	FingerprintHash string
	ExpiresAt       time.Time
	Used            bool
	Revoked         bool
	CreatedAt       time.Time
}

// Device represents a known device/fingerprint for a user.
type Device struct {
	ID              string
	UserID          string
	FingerprintHash string
	FriendlyName    string
	Trusted         bool
	TrustedUntil    *time.Time
	IP              string
	UserAgent       string
	LastSeenAt      *time.Time
	FirstSeenAt     time.Time
	CreatedAt       time.Time
}

// TOTPSecret holds an encrypted TOTP secret for a user.
type TOTPSecret struct {
	ID        string
	UserID    string
	SecretEnc string
	Verified  bool
	CreatedAt time.Time
}

// WebAuthnCredential holds a WebAuthn credential for a user.
type WebAuthnCredential struct {
	ID           string
	UserID       string
	CredentialID []byte
	PublicKey    []byte
	SignCount    int
	FriendlyName string
	CreatedAt    time.Time
}

// BackupCode holds a hashed backup code for a user.
type BackupCode struct {
	ID        string
	UserID    string
	CodeHash  string
	Used      bool
	UsedAt    *time.Time
	CreatedAt time.Time
}

// RateLimit represents a rate limit counter entry.
type RateLimit struct {
	Key         string
	WindowStart time.Time
	Count       int
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	ID              string
	Timestamp       time.Time
	EventType       string
	UserID          string
	ClientID        string
	IP              string
	UserAgent       string
	FingerprintHash string
	DeviceID        string
	Metadata        map[string]interface{}
	RiskScore       int
}

// AdminConfig represents a key-value configuration entry.
type AdminConfig struct {
	Key       string
	Value     string
	UpdatedAt time.Time
}

// IdentityProfile holds encrypted PII for a user, keyed by pseudonym.
type IdentityProfile struct {
	PseudonymID string
	DataEnc     []byte
	Version     int
	UpdatedAt   time.Time
	CreatedAt   time.Time
}

// Blob holds an encrypted user data blob, keyed by pseudonym.
type Blob struct {
	ID          string
	PseudonymID string
	RefHash     string // HMAC of the reference name (empty for unnamed blobs)
	LabelEnc    []byte
	DataEnc     []byte
	SizeBytes   int
	StoredBytes int
	Checksum    string
	CreatedAt   time.Time
}

// BlobQuota summarizes a user's blob storage usage.
type BlobQuota struct {
	UsedBytes int
	UsedCount int
}

// AdminRole represents a role from the auth.admin_roles reference table.
type AdminRole struct {
	Role        string
	Description string
	Rank        int
}

// AdminUser represents an admin gateway operator account.
// Admin accounts are stored in auth.admin_users, fully decoupled from auth.users.
// The Role field is populated from the auth.admin_roles reference table via JOIN.
type AdminUser struct {
	ID               string
	Username         string
	PasswordHash     string
	Role             string
	TOTPSecretEnc    string
	TOTPVerified     bool
	LockedUntil      *time.Time
	FailedLoginCount int
	LastTOTPCounter  int64
	LastLoginAt      *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	CreatedBy        string
}

// AdminSession represents an active admin gateway session.
type AdminSession struct {
	ID        string
	AdminID   string
	TokenHash string
	IP        string
	UserAgent string
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool
}
