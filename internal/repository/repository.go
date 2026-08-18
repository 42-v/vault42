// Package repository defines the persistence interfaces for all domain entities.
// Implementations are provided by sub-packages such as postgres.
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/42-v/vault42/internal/model"
)

// ErrRoleReserved is returned when attempting to delete a reserved catalog role.
var ErrRoleReserved = errors.New("role is reserved and cannot be deleted")

// AppRoleRepository manages the custom roles catalog (auth.app_roles).
type AppRoleRepository interface {
	// List returns all catalog roles ordered by name.
	List(ctx context.Context) ([]*model.AppRole, error)
	// ListNames returns just the role names (for the validation cache).
	ListNames(ctx context.Context) ([]string, error)
	// Get returns one role by name, or nil, nil if absent.
	Get(ctx context.Context, name string) (*model.AppRole, error)
	// Create inserts a new catalog role.
	Create(ctx context.Context, role *model.AppRole) error
	// Delete removes a non-reserved role by name. Returns ErrRoleReserved if the
	// role is reserved, or nil if the role does not exist (idempotent).
	Delete(ctx context.Context, name string) error
}

// EmailBrandingRepository manages per-app email branding (auth.email_branding).
type EmailBrandingRepository interface {
	// Get returns the branding for an app, or nil, nil if absent.
	Get(ctx context.Context, app string) (*model.EmailBranding, error)
	// List returns all per-app branding rows ordered by app.
	List(ctx context.Context) ([]*model.EmailBranding, error)
	// Upsert creates or replaces the branding for an app.
	Upsert(ctx context.Context, b *model.EmailBranding) error
	// Delete removes the branding for an app (idempotent).
	Delete(ctx context.Context, app string) error
}

// EmailTemplateRepository manages per-app email template overrides
// (auth.email_templates), keyed by (app, template_name).
type EmailTemplateRepository interface {
	// Get returns the override for (app, templateName), or nil, nil if absent.
	Get(ctx context.Context, app, templateName string) (*model.EmailTemplate, error)
	// ListByApp returns all template overrides for an app ordered by template_name.
	ListByApp(ctx context.Context, app string) ([]*model.EmailTemplate, error)
	// List returns every template override ordered by app, template_name.
	List(ctx context.Context) ([]*model.EmailTemplate, error)
	// Upsert creates or replaces the override for (app, template_name).
	Upsert(ctx context.Context, t *model.EmailTemplate) error
	// Delete removes the override for (app, templateName) (idempotent).
	Delete(ctx context.Context, app, templateName string) error
}

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
	// SetLastLogin stamps the user's last successful login time.
	SetLastLogin(ctx context.Context, id string) error
	// CreateImported inserts a passwordless imported user (import_pending=true),
	// idempotent on email.
	CreateImported(ctx context.Context, user *model.User) error
	// ClearImportPending marks an imported account as claimed after reset.
	ClearImportPending(ctx context.Context, id string) error
	// SoftDeleteScrub erases a user's PII in place: it sets a tombstone email,
	// clears display_name and avatar_url, and marks the row deleted=true with
	// deleted_at=now. The row is retained (not removed) to preserve referential
	// integrity; the account-state gate rejects deleted users at login/refresh.
	SoftDeleteScrub(ctx context.Context, id, tombstoneEmail string) error
}

// ErrFamilyRevoked is returned by RefreshTokenRepository.Create when the family
// the token belongs to may no longer be extended, and nothing was inserted.
//
// Two conditions produce it. The family has been revoked: reuse detection
// revokes the rows a family has at that instant, so a successor inserted
// afterwards is born outside the revocation and keeps the stolen session alive.
// Or the account has been erased: the cascade tombstones the user row and then
// removes every token row, so a rotation that was already in flight would put a
// fingerprint hash and a device reference back into a table the erasure reported
// it had cleared.
//
// Either way the caller must treat it as a replay: refuse the rotation and end
// the session.
var ErrFamilyRevoked = errors.New("refresh token family is revoked")

// ErrSessionLimitReached is returned by CreateWithinCap, which inserts nothing,
// when the user already holds the maximum number of concurrent token families.
// It is distinct from ErrFamilyRevoked so the caller can map it to the
// caller-facing "too many sessions" outcome rather than a replay.
var ErrSessionLimitReached = errors.New("concurrent session limit reached")

// RefreshTokenRepository manages refresh token persistence.
type RefreshTokenRepository interface {
	// Create inserts a new refresh token record. Returns ErrFamilyRevoked, and
	// inserts nothing, when the token's family already carries a revoked row or
	// the owning account has been erased.
	Create(ctx context.Context, token *model.RefreshToken) error
	// CreateWithinCap inserts the first token of a new family only while the
	// user holds fewer than maxFamilies active families, counting and inserting
	// under one per-user lock so racing logins cannot overshoot the cap. A
	// maxFamilies of zero or less disables the check and inserts unconditionally.
	// Returns ErrSessionLimitReached, and inserts nothing, when the cap is
	// already reached; ErrFamilyRevoked on the same conditions as Create.
	CreateWithinCap(ctx context.Context, token *model.RefreshToken, maxFamilies int) error
	// GetByTokenHash retrieves a refresh token by its SHA-256 hash. Returns nil, nil if not found.
	GetByTokenHash(ctx context.Context, hash string) (*model.RefreshToken, error)
	// MarkUsed atomically marks a token as used. Returns true if the token was
	// unused, not revoked, and is now marked.
	MarkUsed(ctx context.Context, id string) (bool, error)
	// RevokeByID revokes a single refresh token by its ID.
	RevokeByID(ctx context.Context, id string) error
	// RevokeByDeviceID revokes all active refresh tokens for a given device.
	RevokeByDeviceID(ctx context.Context, deviceID string) error
	// RevokeFamily revokes all tokens in a rotation family (replay detection).
	RevokeFamily(ctx context.Context, familyID string) error
	// RevokeAllForUser revokes all active refresh tokens for a user.
	RevokeAllForUser(ctx context.Context, userID string) error
	// DeleteAllForUser hard-deletes every refresh token row for a user (erasure).
	DeleteAllForUser(ctx context.Context, userID string) error
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

// LoginCountryRepository records the set of ISO alpha-2 countries a user has
// successfully logged in from, backing the new-location (AR-18) notice. It
// stores country granularity only — never an IP — and the table is
// user_id-cascaded so account erasure removes it automatically.
type LoginCountryRepository interface {
	// UpsertAndWasNew records that userID logged in from country cc and reports,
	// in one round trip evaluated against a single snapshot:
	//
	//   wasNew  — cc was not already recorded for this user (a genuinely new
	//             country for them);
	//   hadAny  — the user already had at least one recorded country BEFORE this
	//             call (so this is not their first-ever recorded login).
	//
	// The notice is sent only when wasNew && hadAny: a first-ever login seeds the
	// set silently. cc must be a two-character country code; the caller passes
	// the value from ipintel and never an empty string.
	UpsertAndWasNew(ctx context.Context, userID, cc string) (wasNew bool, hadAny bool, err error)
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
	// UpdateFlags stores the raw authenticator flags byte from the last verified
	// ceremony. A stale BackupEligible flag makes go-webauthn reject every
	// subsequent login for that credential.
	UpdateFlags(ctx context.Context, id string, flags int) error
	// Delete removes a single WebAuthn credential. The userID parameter provides
	// defense-in-depth ownership verification at the SQL level.
	Delete(ctx context.Context, id, userID string) error
	// DeleteAllForUser removes every WebAuthn credential for a user (account erasure).
	DeleteAllForUser(ctx context.Context, userID string) error
}

// BackupCodeRepository manages backup code persistence.
type BackupCodeRepository interface {
	// CreateBatch inserts a set of backup codes for a user.
	CreateBatch(ctx context.Context, codes []*model.BackupCode) error
	// ListUnusedByUser returns all unused backup codes for a user.
	ListUnusedByUser(ctx context.Context, userID string) ([]*model.BackupCode, error)
	// MarkUsed atomically marks a single backup code as consumed. Returns true if the code was unused and is now marked.
	MarkUsed(ctx context.Context, id string) (bool, error)
	// DeleteAllForUser invalidates all backup codes for a user (marks them used).
	// The rows, and their hashes, remain — use PurgeAllForUser for erasure.
	DeleteAllForUser(ctx context.Context, userID string) error
	// PurgeAllForUser hard-deletes every backup code row for a user (erasure).
	PurgeAllForUser(ctx context.Context, userID string) error
}

// AuditRepository manages audit log persistence.
type AuditRepository interface {
	// Insert writes a single audit log entry to the append-only audit log.
	Insert(ctx context.Context, entry *model.AuditEntry) error
	// InsertBatch writes multiple audit log entries.
	InsertBatch(ctx context.Context, entries []*model.AuditEntry) error
	// Query retrieves audit log entries matching the given filter criteria.
	Query(ctx context.Context, filter AuditFilter) ([]*model.AuditEntry, error)
	// CountByUser returns how many audit entries are held for a user. Query is
	// capped, so a caller that must report completeness (the Art. 15 export)
	// needs the unbounded total separately.
	CountByUser(ctx context.Context, userID string) (int, error)
	// Cleanup removes audit entries older than the given time using the
	// SECURITY DEFINER function that temporarily disables append-only triggers.
	Cleanup(ctx context.Context, olderThan time.Time) (int64, error)
	// CleanupLocked is Cleanup serialised across replicas by a Postgres advisory
	// lock. acquired=false means another replica is already sweeping and this one
	// must skip: the cleanup takes an ACCESS EXCLUSIVE lock on the audit table.
	//
	// It deletes at most AuditCleanupBatch rows per call, so a caller with a
	// backlog loops. A full batch means there is more; anything less means the
	// horizon is clear.
	CleanupLocked(ctx context.Context, olderThan time.Time) (deleted int64, acquired bool, err error)
}

// AuditCleanupBatch is how many rows one CleanupLocked call may delete, and
// therefore how long one call holds ACCESS EXCLUSIVE on the audit table.
//
// The purge has to disable the append-only trigger to delete anything, which is
// ALTER TABLE. Held over an unbounded DELETE that blocks every audit insert for
// the length of the whole purge — and a failed login is a critical event,
// written synchronously on the request path even when the buffer is full. Two
// thousand rows is the batch the postgres cache reaper already uses.
//
// It lives on the interface rather than in either implementation because both
// the implementation and the sweeper that loops over it have to agree on it,
// and internal/audit cannot import internal/repository/postgres.
const AuditCleanupBatch = 2000

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
	// DeleteAllForUser removes every social account link for a user (account erasure).
	DeleteAllForUser(ctx context.Context, userID string) error
}

// PasswordHistoryRepository manages password history persistence.
type PasswordHistoryRepository interface {
	// Create inserts a password hash into the user's password history.
	Create(ctx context.Context, entry *model.PasswordHistory) error
	// GetRecentByUser returns the most recent password hashes for reuse prevention.
	GetRecentByUser(ctx context.Context, userID string, limit int) ([]*model.PasswordHistory, error)
	// DeleteAllForUser removes a user's entire password history (account erasure).
	DeleteAllForUser(ctx context.Context, userID string) error
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
	// UpsertCAS writes only if the stored row still matches expectedUpdatedAt
	// (zero = expected absent). Returns false on a losing race, so a
	// read-modify-write of the encrypted blob cannot silently drop a concurrent
	// change. See the repo implementation for why a partial UPDATE is impossible.
	UpsertCAS(ctx context.Context, profile *model.IdentityProfile, expectedUpdatedAt time.Time) (bool, error)
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
	// DeleteAllForPseudonym removes every blob owned by a pseudonym (account erasure).
	DeleteAllForPseudonym(ctx context.Context, pseudonymID string) error
}

// ServiceDocumentVisibility controls which clients may read a service document.
//
// It is an integer enum rather than a boolean so a third tier (an explicit
// grantee allow-list) can be added by widening a CHECK constraint instead of
// changing a column's type, and so the wire representation stays a string enum
// rather than a field whose meaning inverts. The zero value is the closed one:
// a document whose visibility was never set is private.
type ServiceDocumentVisibility int16

const (
	// VisibilityPrivate documents are readable and writable only by the client
	// that owns them. This is the default for every write.
	VisibilityPrivate ServiceDocumentVisibility = 0
	// VisibilityShared documents are readable by any authenticated client
	// holding the read scope, and writable only by the owning client. There is
	// deliberately no shared-mutable tier: two services writing one document
	// with no locking loses data.
	VisibilityShared ServiceDocumentVisibility = 1
)

// ServiceDocument is one AES-GCM encrypted JSON document owned by a service
// client and scoped to a subject.
//
// The row type lives here rather than in model because the store has no
// plaintext-carrying representation worth sharing: DataEnc is the only payload
// field and it is opaque outside the service layer.
//
// SubjectHash is an HMAC pseudonym, never a raw user id, so a database reader
// cannot enumerate which users a service holds documents for. DocKey is stored
// in plaintext, unlike objects.blobs.ref_hash: blob reference names are chosen
// by users and may be personal data, whereas document keys are chosen by the
// writing service from a constrained charset and are configuration identifiers.
type ServiceDocument struct {
	ID          string
	ClientID    string
	SubjectHash string
	DocKey      string
	Visibility  ServiceDocumentVisibility
	DataEnc     []byte
	SizeBytes   int
	StoredBytes int
	Version     int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ServiceDocumentRepository manages encrypted, service-scoped JSON documents
// (objects.service_documents), keyed by (client_id, subject_hash, doc_key).
//
// Every read method that a request path can reach takes the caller's client id,
// so ownership is enforced in SQL rather than by a comparison the handler could
// forget. The two methods that span clients, ListSharedByKey and the erasure
// and export helpers, say so in their names.
type ServiceDocumentRepository interface {
	// Get returns one document owned by clientID, or nil, nil if absent.
	Get(ctx context.Context, clientID, subjectHash, docKey string) (*ServiceDocument, error)
	// ListSharedByKey returns every shared document at (subjectHash, docKey)
	// that is NOT owned by excludeClientID. More than one row can come back:
	// two services may each publish a shared document under the same key, and
	// the caller has to resolve that rather than the store guessing an owner.
	ListSharedByKey(ctx context.Context, subjectHash, docKey, excludeClientID string) ([]*ServiceDocument, error)
	// Upsert creates or fully replaces a document. created reports whether a new
	// row was inserted, so the handler can answer 201 versus 200.
	Upsert(ctx context.Context, doc *ServiceDocument) (created bool, err error)
	// Delete removes one document owned by clientID. Returns false when there
	// was nothing to remove.
	Delete(ctx context.Context, clientID, subjectHash, docKey string) (deleted bool, err error)
	// ListByOwner returns the caller's own documents for a subject, without
	// data_enc.
	ListByOwner(ctx context.Context, clientID, subjectHash string) ([]*ServiceDocument, error)
	// ListSharedForSubject returns shared documents for a subject owned by other
	// clients, without data_enc.
	ListSharedForSubject(ctx context.Context, subjectHash, excludeClientID string) ([]*ServiceDocument, error)
	// ListAllForSubject returns every document held for a subject across all
	// owning clients, WITH data_enc. It exists for the Art. 15 export, which
	// must return the document bodies a service wrote about the data subject.
	ListAllForSubject(ctx context.Context, subjectHash string) ([]*ServiceDocument, error)
	// CountForOwner returns how many documents clientID holds for a subject.
	CountForOwner(ctx context.Context, clientID, subjectHash string) (int, error)
	// SumBytesForSubjectAndClient returns the stored bytes one client holds for
	// a subject, for the per-(client, subject) byte quota. The budget is charged
	// against the caller's own footprint, so one service cannot fill a budget the
	// others then fail against, and one service's usage is never reported to
	// another.
	SumBytesForSubjectAndClient(ctx context.Context, subjectHash, clientID string) (int, error)
	// DeleteAllForSubject removes every document for a subject across all
	// owning clients (account erasure). It is idempotent: erasing a subject
	// that never had a document is not an error, so an interrupted cascade can
	// be re-run.
	DeleteAllForSubject(ctx context.Context, subjectHash string) error
}

// AccountRecoveryRepository manages the append-only account-recovery escrow log
// (auth.account_recovery). Records are written on account erasure and can only
// be decrypted with the offline recovery private key. The table is append-only:
// there is no update or delete method.
type AccountRecoveryRepository interface {
	// Append writes one encrypted recovery record.
	Append(ctx context.Context, rec *model.AccountRecovery) error
	// List returns recovery records ordered by deleted_at descending. Used by the
	// offline recovery tool to enumerate and decrypt escrowed accounts.
	List(ctx context.Context, limit, offset int) ([]model.AccountRecovery, error)
}

// AccountRecoveryPruner removes escrow records past their retention horizon.
//
// Deliberately separate from AccountRecoveryRepository: the escrow is
// append-only for everything that writes to it, and the erasure service, the
// admin gateway and the server wiring all hold the append-only interface. Only
// the retention sweeper and `vault cleanup-recovery` are handed a pruner, so a
// delete cannot be reached from a request path by accident.
type AccountRecoveryPruner interface {
	// Prune removes recovery records written before olderThan and returns how
	// many rows went.
	Prune(ctx context.Context, olderThan time.Time) (int64, error)
	// PruneLocked is Prune serialised across replicas by a Postgres advisory
	// lock. acquired=false means another replica is already sweeping and this one
	// must skip: the cleanup takes an ACCESS EXCLUSIVE lock on the escrow table.
	PruneLocked(ctx context.Context, olderThan time.Time) (deleted int64, acquired bool, err error)
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
