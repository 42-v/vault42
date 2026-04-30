// Package repository defines the persistence interfaces for all domain entities.
// Implementations are provided by sub-packages such as postgres.
package repository

import (
	"context"
	"time"

	"github.com/42-v/vault42/internal/model"
)

// UserRepository manages user persistence.
type UserRepository interface {
	// Create inserts a new user record.
	Create(ctx context.Context, user *model.User) error
	// GetByID retrieves a user by their unique ID. Returns nil, nil if not found.
	GetByID(ctx context.Context, id string) (*model.User, error)
	// GetByEmail retrieves a user by email address. Returns nil, nil if not found.
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	// Update persists changes to a user's profile fields.
	Update(ctx context.Context, user *model.User) error
	// UpdatePassword replaces the user's password hash.
	UpdatePassword(ctx context.Context, id, passwordHash string) error
	// IncrementFailedLogin increments the failed login attempt counter for a user.
	IncrementFailedLogin(ctx context.Context, id string) error
	// ResetFailedLogin resets the failed login attempt counter to zero.
	ResetFailedLogin(ctx context.Context, id string) error
	// LockUntil locks the user account until the specified time.
	LockUntil(ctx context.Context, id string, until time.Time) error
	// Unlock removes the account lock and resets the failed login counter.
	Unlock(ctx context.Context, id string) error
	// VerifyEmail marks the user's email address as verified.
	VerifyEmail(ctx context.Context, id string) error
}

// RefreshTokenRepository manages refresh token persistence.
type RefreshTokenRepository interface {
	// Create inserts a new refresh token record.
	Create(ctx context.Context, token *model.RefreshToken) error
	// GetByTokenHash retrieves a refresh token by its SHA-256 hash. Returns nil, nil if not found.
	GetByTokenHash(ctx context.Context, hash string) (*model.RefreshToken, error)
	// MarkUsed atomically marks a token as used. Returns true if the token was unused and is now marked.
	MarkUsed(ctx context.Context, id string) (bool, error)
	// RevokeByID revokes a single refresh token by its ID.
	RevokeByID(ctx context.Context, id string) error
	// RevokeByDeviceID revokes all active refresh tokens for a given device.
	RevokeByDeviceID(ctx context.Context, deviceID string) error
	// RevokeFamily revokes all tokens in a rotation family (replay detection).
	RevokeFamily(ctx context.Context, familyID string) error
	// RevokeAllForUser revokes all active refresh tokens for a user.
	RevokeAllForUser(ctx context.Context, userID string) error
	// RevokeAll revokes all active refresh tokens system-wide.
	RevokeAll(ctx context.Context) error
	// CountActiveFamilies returns the number of distinct active (non-revoked, non-expired) token families for a user.
	CountActiveFamilies(ctx context.Context, userID string) (int, error)
	// DeleteExpired removes expired tokens that have already been used or revoked.
	DeleteExpired(ctx context.Context) (int64, error)
}

// DeviceRepository manages device fingerprint persistence.
type DeviceRepository interface {
	// Create inserts a new device record.
	Create(ctx context.Context, device *model.Device) error
	// GetByID retrieves a device by its unique ID. Returns nil, nil if not found.
	GetByID(ctx context.Context, id string) (*model.Device, error)
	// GetByFingerprint retrieves a device by user ID and fingerprint hash. Returns nil, nil if not found.
	GetByFingerprint(ctx context.Context, userID, fingerprintHash string) (*model.Device, error)
	// ListByUser returns all devices for a user, ordered by most recently seen.
	ListByUser(ctx context.Context, userID string) ([]*model.Device, error)
	// UpdateLastSeen updates the last-seen timestamp and IP address for a device.
	UpdateLastSeen(ctx context.Context, id string, ip string) error
	// UpdateFriendlyName sets a human-readable name for a device.
	UpdateFriendlyName(ctx context.Context, id string, name string) error
	// Trust marks a device as trusted until the specified time.
	Trust(ctx context.Context, id string, until time.Time) error
	// Delete removes a single device record. The userID parameter provides
	// defense-in-depth ownership verification at the SQL level.
	Delete(ctx context.Context, id, userID string) error
	// DeleteAllForUser removes all device records for a user.
	DeleteAllForUser(ctx context.Context, userID string) error
}

// ClientRepository manages service client persistence.
type ClientRepository interface {
	// Create inserts a new service client record.
	Create(ctx context.Context, client *model.Client) error
	// GetByID retrieves a client by its unique ID. Returns nil, nil if not found.
	GetByID(ctx context.Context, id string) (*model.Client, error)
	// GetByName retrieves a client by its unique name. Returns nil, nil if not found.
	GetByName(ctx context.Context, name string) (*model.Client, error)
	// List returns all registered service clients, ordered by name.
	List(ctx context.Context) ([]*model.Client, error)
	// Update persists changes to a client's fields.
	Update(ctx context.Context, client *model.Client) error
	// Deactivate marks a client as inactive.
	Deactivate(ctx context.Context, id string) error
}

// TOTPRepository manages TOTP secret persistence.
type TOTPRepository interface {
	// Create inserts a new TOTP secret record.
	Create(ctx context.Context, secret *model.TOTPSecret) error
	// GetByUserID retrieves the TOTP secret for a user. Returns an error if not found.
	GetByUserID(ctx context.Context, userID string) (*model.TOTPSecret, error)
	// MarkVerified marks a TOTP secret as verified after the user confirms setup.
	MarkVerified(ctx context.Context, id string) error
	// DeleteByUserID removes the TOTP secret for a user (disables TOTP).
	DeleteByUserID(ctx context.Context, userID string) error
}

// WebAuthnRepository manages WebAuthn credential persistence.
type WebAuthnRepository interface {
	// Create inserts a new WebAuthn credential record.
	Create(ctx context.Context, cred *model.WebAuthnCredential) error
	// GetByCredentialID retrieves a credential by its raw credential ID. Returns an error if not found.
	GetByCredentialID(ctx context.Context, credID []byte) (*model.WebAuthnCredential, error)
	// ListByUser returns all WebAuthn credentials for a user, ordered by creation time.
	ListByUser(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error)
	// UpdateSignCount updates the signature counter for clone detection.
	UpdateSignCount(ctx context.Context, id string, count int) error
	// Delete removes a single WebAuthn credential. The userID parameter provides
	// defense-in-depth ownership verification at the SQL level.
	Delete(ctx context.Context, id, userID string) error
}

// BackupCodeRepository manages backup code persistence.
type BackupCodeRepository interface {
	// CreateBatch inserts a set of backup codes for a user.
	CreateBatch(ctx context.Context, codes []*model.BackupCode) error
	// ListUnusedByUser returns all unused backup codes for a user.
	ListUnusedByUser(ctx context.Context, userID string) ([]*model.BackupCode, error)
	// MarkUsed atomically marks a single backup code as consumed. Returns true if the code was unused and is now marked.
	MarkUsed(ctx context.Context, id string) (bool, error)
	// DeleteAllForUser invalidates all backup codes for a user.
	DeleteAllForUser(ctx context.Context, userID string) error
}

// AuditRepository manages audit log persistence.
type AuditRepository interface {
	// Insert writes a single audit log entry to the append-only audit log.
	Insert(ctx context.Context, entry *model.AuditEntry) error
	// InsertBatch writes multiple audit log entries.
	InsertBatch(ctx context.Context, entries []*model.AuditEntry) error
	// Query retrieves audit log entries matching the given filter criteria.
	Query(ctx context.Context, filter AuditFilter) ([]*model.AuditEntry, error)
	// Cleanup removes audit entries older than the given time using the
	// SECURITY DEFINER function that temporarily disables append-only triggers.
	Cleanup(ctx context.Context, olderThan time.Time) (int64, error)
}

// AuditFilter specifies criteria for querying audit log entries.
type AuditFilter struct {
	UserID    string
	EventType string
	Since     *time.Time
	Until     *time.Time
	Limit     int
	Offset    int
}

// SocialAccountRepository manages social login persistence.
type SocialAccountRepository interface {
	// Create inserts a new social account link.
	Create(ctx context.Context, account *model.SocialAccount) error
	// GetByProviderAndID retrieves a social account by provider name and provider-side user ID.
	GetByProviderAndID(ctx context.Context, provider, providerUserID string) (*model.SocialAccount, error)
	// ListByUser returns all linked social accounts for a user.
	ListByUser(ctx context.Context, userID string) ([]*model.SocialAccount, error)
	// Delete removes a social account link. The userID parameter provides
	// defense-in-depth ownership verification at the SQL level.
	Delete(ctx context.Context, id, userID string) error
}

// PasswordHistoryRepository manages password history persistence.
type PasswordHistoryRepository interface {
	// Create inserts a password hash into the user's password history.
	Create(ctx context.Context, entry *model.PasswordHistory) error
	// GetRecentByUser returns the most recent password hashes for reuse prevention.
	GetRecentByUser(ctx context.Context, userID string, limit int) ([]*model.PasswordHistory, error)
}

// RateLimitRepository manages rate limit counter persistence (PostgreSQL fallback).
type RateLimitRepository interface {
	// Increment atomically increments the counter for a key in the given time window and returns the new count.
	Increment(ctx context.Context, key string, window time.Time) (int, error)
	// Get returns the current counter value for a key in the given time window.
	Get(ctx context.Context, key string, window time.Time) (int, error)
	// DeleteExpired removes rate limit entries with windows older than the given time.
	DeleteExpired(ctx context.Context, before time.Time) error
}

// AdminConfigRepository manages key-value admin configuration.
type AdminConfigRepository interface {
	// List returns all configuration key-value pairs.
	List(ctx context.Context) (map[string]string, error)
	// Get retrieves a configuration value by key. Returns empty string if not found.
	Get(ctx context.Context, key string) (string, error)
	// Set creates or updates a configuration key-value pair.
	Set(ctx context.Context, key, value string) error
	// Delete removes a configuration entry by key.
	Delete(ctx context.Context, key string) error
}

// IdentityRepository manages encrypted identity profile persistence.
type IdentityRepository interface {
	// Upsert creates or updates an identity profile by pseudonym ID.
	Upsert(ctx context.Context, profile *model.IdentityProfile) error
	// GetByPseudonym retrieves an identity profile. Returns nil, nil if not found.
	GetByPseudonym(ctx context.Context, pseudonymID string) (*model.IdentityProfile, error)
	// Delete removes an identity profile by pseudonym ID.
	Delete(ctx context.Context, pseudonymID string) error
}

// BlobRepository manages encrypted blob persistence.
type BlobRepository interface {
	// Create inserts a new blob record.
	Create(ctx context.Context, blob *model.Blob) error
	// GetByIDAndPseudonym retrieves a blob by ID, only if it belongs to the given pseudonym. Returns nil, nil if not found.
	GetByIDAndPseudonym(ctx context.Context, id, pseudonymID string) (*model.Blob, error)
	// GetByRefAndPseudonym retrieves a blob by ref_hash, only if it belongs to the given pseudonym. Returns nil, nil if not found.
	GetByRefAndPseudonym(ctx context.Context, refHash, pseudonymID string) (*model.Blob, error)
	// DeleteByRefAndPseudonym removes a blob by ref_hash, only if it belongs to the given pseudonym.
	DeleteByRefAndPseudonym(ctx context.Context, refHash, pseudonymID string) error
	// ListByPseudonym returns all blob metadata (without data_enc) for a pseudonym.
	ListByPseudonym(ctx context.Context, pseudonymID string) ([]*model.Blob, error)
	// GetQuota returns the blob count and total stored bytes for a pseudonym.
	GetQuota(ctx context.Context, pseudonymID string) (*model.BlobQuota, error)
	// Delete removes a blob by ID, only if it belongs to the given pseudonym.
	Delete(ctx context.Context, id, pseudonymID string) error
}

// AdminUserRepository manages admin gateway user persistence.
type AdminUserRepository interface {
	// Create inserts a new admin user.
	Create(ctx context.Context, user *model.AdminUser) error
	// GetByID retrieves an admin user by ID. Returns nil, nil if not found.
	GetByID(ctx context.Context, id string) (*model.AdminUser, error)
	// GetByUsername retrieves an admin user by username. Returns nil, nil if not found.
	GetByUsername(ctx context.Context, username string) (*model.AdminUser, error)
	// List returns all admin users.
	List(ctx context.Context) ([]*model.AdminUser, error)
	// Count returns the total number of admin users.
	Count(ctx context.Context) (int, error)
	// Update persists changes to an admin user's fields.
	Update(ctx context.Context, user *model.AdminUser) error
	// IncrementFailedLogin atomically increments the failed login counter and returns the new count.
	IncrementFailedLogin(ctx context.Context, id string) (int, error)
	// ResetFailedLogin resets the failed login counter to zero.
	ResetFailedLogin(ctx context.Context, id string) error
	// LockUntil locks the admin account until the specified time.
	LockUntil(ctx context.Context, id string, until time.Time) error
	// UpdateLastTOTPCounter records the accepted TOTP time-step for replay prevention.
	UpdateLastTOTPCounter(ctx context.Context, id string, counter int64) error
	// UpdateLastLogin sets the last login timestamp.
	UpdateLastLogin(ctx context.Context, id string) error
	// Revoke deletes an admin user and their sessions.
	Revoke(ctx context.Context, id string) error
}

// AdminSessionRepository manages admin gateway session persistence.
type AdminSessionRepository interface {
	// Create inserts a new admin session.
	Create(ctx context.Context, session *model.AdminSession) error
	// GetByTokenHash retrieves a session by its SHA-256 token hash. Returns nil, nil if not found.
	GetByTokenHash(ctx context.Context, hash string) (*model.AdminSession, error)
	// ListByAdmin returns all active sessions for an admin user.
	ListByAdmin(ctx context.Context, adminID string) ([]*model.AdminSession, error)
	// ListActive returns all active (non-revoked, non-expired) sessions.
	ListActive(ctx context.Context) ([]*model.AdminSession, error)
	// Revoke marks a session as revoked.
	Revoke(ctx context.Context, id string) error
	// RevokeAllForAdmin revokes all sessions for an admin user.
	RevokeAllForAdmin(ctx context.Context, adminID string) error
	// RevokeAll revokes all active sessions.
	RevokeAll(ctx context.Context) error
	// DeleteExpired removes expired sessions.
	DeleteExpired(ctx context.Context) (int64, error)
}
