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
	// ID is the account's stable UUID. It is the JWT subject on every
	// self-authenticated user token and the foreign key every other user-scoped
	// row points at.
	ID string `json:"id"`
	// Email is the login identifier and the destination for verification,
	// password-reset, OTP and new-device mail. Unique among live accounts.
	Email string `json:"email"`
	// EmailVerified is true only after GET /auth/verify-email succeeds. An
	// unverified account is treated as unknown at login so the verify state
	// cannot be probed.
	EmailVerified bool `json:"email_verified"`
	// PasswordHash is the Argon2id PHC string of the account password. Tagged
	// json:"-" so a leaked row or accidental encode cannot put a password
	// verifier on the wire; only VerifyPassword reads it.
	PasswordHash string `json:"-"`
	// DisplayName is the human-facing name shown in profile and WebAuthn
	// ceremonies. Empty means the client should fall back to Email. PUT
	// /user/profile sanitizes and caps it at 100 runes; the column is 255.
	DisplayName string `json:"display_name"`
	// AvatarURL is an optional HTTPS image URL. Empty means no avatar is set.
	// PUT /user/profile stores "" for a non-HTTPS or over-long value rather
	// than returning 400, so a bad URL reads back as cleared.
	AvatarURL string `json:"avatar_url"`
	// Locale is the BCP 47 language tag used to pick email copy. Defaults to
	// "en" when the account is created without one.
	Locale string `json:"locale"`
	// MFARequired is the per-account flag stored on the row (legacy-platform
	// parity). It is not what GET /user/profile reports: that endpoint emits
	// the server-wide VAULT_MFA_REQUIRED setting. This column is what GET
	// /user/data-export copies into account.mfa_required.
	MFARequired bool `json:"mfa_required"`
	// LockedUntil is when a lockout from failed logins expires, RFC3339 UTC.
	// Nil means the account is not locked. A time in the past is treated as
	// unlocked; the login path clears it on the next success.
	LockedUntil *time.Time `json:"locked_until"`
	// FailedLoginCount is consecutive failed password attempts since the last
	// success. Reset to 0 on a successful login. Drives lockout thresholds.
	FailedLoginCount int `json:"failed_login_count"`
	// CreatedAt is when the account row was inserted, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when any persisted profile or state column last changed,
	// RFC3339 UTC.
	UpdatedAt time.Time `json:"updated_at"`
	// Roles is the application-role list copied into the JWT "roles" claim at
	// login. Empty is issued as ["user"]. Admin-tier names never appear here.
	Roles []string `json:"roles"`
	// Disabled is an operator-set flag that refuses login with a distinct
	// account_disabled error. Used for the legacy-platform Active=false
	// equivalent (migration 004). False means the account may authenticate.
	Disabled bool `json:"disabled"`
	// Banned is an operator-set flag that refuses login with a distinct
	// account_banned error. Stronger than Disabled: the account is sanctioned,
	// not merely switched off. False means not banned.
	Banned bool `json:"banned"`
	// BanReason is the operator-supplied explanation shown in the admin
	// console. Empty when Banned is false; the login path does not return it
	// to the caller, so it cannot be used as an oracle.
	BanReason string `json:"ban_reason"`
	// LastLoginAt is the most recent successful authentication, RFC3339 UTC.
	// Nil means the account has never completed a login (typical of a fresh
	// import or an unverified registration).
	LastLoginAt *time.Time `json:"last_login_at"`
	// Deleted is the soft-delete tombstone. True after DELETE /user/account;
	// login then answers as if the email were unknown so erasure cannot be
	// probed. Foreign keys stay intact until a later purge.
	Deleted bool `json:"deleted"`
	// DeletedAt is when the tombstone was written, RFC3339 UTC. Nil when
	// Deleted is false.
	DeletedAt *time.Time `json:"deleted_at"`
	// ImportPending is true until an imported account claims itself by
	// completing the first-login reset link (migration 006). While true there
	// is no password to verify; login is indistinguishable from a wrong
	// password so the import state cannot be enumerated.
	ImportPending bool `json:"import_pending"`
	// ImportedFrom is the source-system tag (for example "legacy"). Empty on
	// native registrations. Together with LegacyID it makes a re-run of an
	// import idempotent.
	ImportedFrom string `json:"imported_from"`
	// LegacyID is the source system's user id, stored so downstream services
	// that still join on the old identifier can find the vault42 account.
	// Empty on native registrations.
	LegacyID string `json:"legacy_id"`
}

// PasswordHistory tracks previous password hashes to prevent reuse.
type PasswordHistory struct {
	// ID is this history row's UUID.
	ID string `json:"id"`
	// UserID is the account that previously used PasswordHash.
	UserID string `json:"user_id"`
	// PasswordHash is an Argon2id verifier of a retired password. Tagged
	// json:"-" so a history dump cannot be used as a dictionary of old
	// verifiers; only the reuse check reads it.
	PasswordHash string `json:"-"`
	// CreatedAt is when this password became current (and the previous one
	// was archived), RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// SocialAccount links an OAuth provider to a user.
type SocialAccount struct {
	// ID is this link's UUID. DELETE /user/social/{id} addresses it.
	ID string `json:"id"`
	// UserID is the vault42 account this provider identity is bound to.
	UserID string `json:"user_id"`
	// Provider is the configured IdP name (for example "google" or "github").
	// Combined with ProviderUserID it is unique.
	Provider string `json:"provider"`
	// ProviderUserID is the subject the IdP asserted. It is how a later
	// callback is joined to this row rather than creating a second account.
	ProviderUserID string `json:"provider_user_id"`
	// Email is the address the IdP asserted at link time. Empty when the
	// provider did not release one. GET /user/social omits the key when empty.
	Email string `json:"email"`
	// AccessTokenEnc is the AES-GCM ciphertext of the provider access token.
	// Tagged json:"-" because it is a live credential; list and export views
	// drop it on purpose so a subject can see the link without holding the
	// provider session.
	AccessTokenEnc string `json:"-"`
	// RefreshTokenEnc is the AES-GCM ciphertext of the provider refresh
	// token. Tagged json:"-" for the same reason as AccessTokenEnc; unlinking
	// the row is the only way a user removes it.
	RefreshTokenEnc string `json:"-"`
	// CreatedAt is when the link was first stored, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// AccountRecovery is one append-only escrow record written when a user account
// is erased. Payload is a hybrid-asymmetric ciphertext (see crypto.EncryptRecovery)
// of the recoverable profile (email, created_at, roles, display_name). The
// server cannot decrypt it — only the holder of the offline recovery private
// key can, to restore the deleted user from backup. Pseudonym is an HMAC of the
// user id so a record can be correlated to a (soft-deleted) user without
// storing the plaintext identity here.
type AccountRecovery struct {
	// ID is this escrow row's UUID.
	ID string `json:"id"`
	// Pseudonym is HMAC-SHA256 of the erased user id. Tagged json:"-" so a
	// dump of this table cannot be joined back to a live identity without the
	// HMAC secret; cmd/recover is the only intended consumer.
	Pseudonym string `json:"-"`
	// Payload is the hybrid-asymmetric ciphertext of the recoverable profile.
	// Tagged json:"-" because the server holds only the public half and must
	// never put the blob on an API response; only the offline private key can
	// open it.
	Payload []byte `json:"-"`
	// DeletedAt is when the erasure wrote this row, RFC3339 UTC.
	DeletedAt time.Time `json:"deleted_at"`
	// DeletedBy records who initiated the erasure (the subject, or an
	// operator id). Empty when the actor was not recorded.
	DeletedBy string `json:"deleted_by"`
	// Reason is an optional operator note. Empty on self-service DELETE
	// /user/account, which supplies none.
	Reason string `json:"reason"`
}

// Client represents a registered service client.
type Client struct {
	// ID is the client's UUID. It is the JWT client_id claim on tokens issued
	// by POST /client/token and the owner axis of the service-document store.
	ID string `json:"id"`
	// Name is the registered display name used as the ?owner= selector on
	// GET /service/documents/{subject}/{key}.
	Name string `json:"name"`
	// SecretHash is the Argon2id verifier of the client secret. Tagged
	// json:"-" so a client listing or accidental encode cannot leak a
	// credential that is equivalent to the signing key's blast radius for
	// any scope the client holds.
	SecretHash string `json:"-"`
	// Role is the client's catalog role, distinct from a user's Roles claim.
	// It is an operator-assigned label, not a JWT role.
	Role string `json:"role"`
	// Scopes is the set POST /client/token may grant. A requested scope list
	// is intersected with this; an empty request grants the whole set.
	Scopes []string `json:"scopes"`
	// RedirectURIs is the allow-list for an authorization-code redirect.
	// Empty on a client that only uses the client-credentials grant.
	RedirectURIs []string `json:"redirect_uris"`
	// Active is false after an operator deactivates the client. POST
	// /client/token then returns 401 client_revoked rather than issuing.
	Active bool `json:"active"`
	// CreatedAt is when the client was registered, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when name, secret, scopes, URIs or Active last changed,
	// RFC3339 UTC.
	UpdatedAt time.Time `json:"updated_at"`
}

// RefreshToken represents a stored refresh token.
type RefreshToken struct {
	// ID is this token row's UUID.
	ID string `json:"id"`
	// UserID is the account the refresh family authenticates.
	UserID string `json:"user_id"`
	// ClientID is the service client that requested the session, when one
	// was named at login. Empty for a browser session with no client_id.
	ClientID string `json:"client_id"`
	// TokenHash is the HMAC of the opaque refresh token value. Tagged
	// json:"-" because possession of the hash plus the HMAC secret is
	// enough to mint a usable cookie; only the rotation path compares it.
	TokenHash string `json:"-"`
	// FamilyID groups the current token with its predecessors so a replay
	// of any generation revokes the whole family.
	FamilyID string `json:"family_id"`
	// DeviceID is the Device this session is bound to. Revoking the device
	// revokes every token that carries this id.
	DeviceID string `json:"device_id"`
	// FingerprintHash is the HMAC of the device fingerprint captured at
	// issuance. Tagged json:"-" because it correlates sessions across
	// accounts; a mismatch on POST /auth/refresh is reported as
	// invalid_token, not as a fingerprint leak.
	FingerprintHash string `json:"-"`
	// ExpiresAt is when this refresh token stops being accepted, RFC3339
	// UTC. A used or revoked token is rejected even before this instant.
	ExpiresAt time.Time `json:"expires_at"`
	// Used is true after a successful rotation. Presenting a used token is
	// replay_detected and burns the family, which is why rotation is
	// single-use.
	Used bool `json:"used"`
	// Revoked is true after logout, password change, reset, or an operator
	// revocation. A revoked token is rejected without treating it as replay.
	Revoked bool `json:"revoked"`
	// CreatedAt is when this generation was issued, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// Device represents a known device/fingerprint for a user.
type Device struct {
	// ID is this device row's UUID. GET /user/sessions and GET /user/devices
	// both expose it as id; DELETE /user/sessions/{id} and
	// DELETE /user/devices/{id} address it.
	ID string `json:"id"`
	// UserID is the account this device belongs to. Deletes are scoped by
	// this so one user cannot act on another's id.
	UserID string `json:"user_id"`
	// FingerprintHash is the HMAC of SHA256(IP + User-Agent +
	// Accept-Language + TLS-fingerprint). Tagged json:"-" because it is a
	// cross-account correlator. Device listings expose ID, not this hash;
	// ID is the identifier a client or operator may act on.
	FingerprintHash string `json:"-"`
	// FriendlyName is the user-chosen label from PATCH /user/devices/{id}.
	// Empty until the user names it; the server does not invent one.
	FriendlyName string `json:"friendly_name"`
	// Trusted is reserved for a remembered-device exemption. It is stored
	// and returned on session and device listings but no current login path
	// sets it, so callers must treat false as the only observed value until
	// a remember-device flow exists.
	Trusted bool `json:"trusted"`
	// TrustedUntil is when a remembered-device exemption would expire,
	// RFC3339 UTC. Nil while Trusted is false, which is the only state the
	// current issuance paths write.
	TrustedUntil *time.Time `json:"trusted_until"`
	// IP is the remote address recorded at last activity. Empty if the
	// request had none the middleware could trust.
	IP string `json:"ip"`
	// UserAgent is the User-Agent header recorded at last activity. Empty
	// if the client sent none.
	UserAgent string `json:"user_agent"`
	// LastSeenAt is the most recent request that refreshed this device,
	// RFC3339 UTC. Nil only on a row that has never been seen after insert,
	// which the login path does not produce.
	LastSeenAt *time.Time `json:"last_seen_at"`
	// FirstSeenAt is when this fingerprint was first bound to the account,
	// RFC3339 UTC.
	FirstSeenAt time.Time `json:"first_seen_at"`
	// CreatedAt is when the row was inserted, RFC3339 UTC. Equal to
	// FirstSeenAt on current issuance.
	CreatedAt time.Time `json:"created_at"`
}

// TOTPSecret holds an encrypted TOTP secret for a user.
type TOTPSecret struct {
	// ID is this TOTP enrollment's UUID.
	ID string `json:"id"`
	// UserID is the account this secret belongs to. One verified secret per
	// user; setup refuses a second.
	UserID string `json:"user_id"`
	// SecretEnc is the AES-GCM ciphertext of the base32 TOTP seed. Tagged
	// json:"-" so the seed that POST /auth/2fa/totp/setup returns once cannot
	// be read back later from any listing.
	SecretEnc string `json:"-"`
	// Verified is false between setup and the first successful code. An
	// unverified secret does not count as an enrolled factor and is replaced
	// by a later setup.
	Verified bool `json:"verified"`
	// CreatedAt is when the current secret was generated, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// WebAuthnCredential holds a WebAuthn credential for a user.
type WebAuthnCredential struct {
	// ID is this credential's vault42 UUID. GET /auth/2fa/webauthn/credentials
	// and DELETE /auth/2fa/webauthn/credentials/{id} address it, not the
	// authenticator's credential id.
	ID string `json:"id"`
	// UserID is the account this authenticator is bound to.
	UserID string `json:"user_id"`
	// CredentialID is the authenticator-generated credential id used in
	// allowCredentials. It is binary, not the vault42 UUID in ID.
	CredentialID []byte `json:"credential_id"`
	// PublicKey is the COSE public key used to verify assertions. It is
	// stored so a later ceremony can check the signature without a second
	// registration.
	PublicKey []byte `json:"public_key"`
	// SignCount is the authenticator's signature counter from the last
	// verified assertion. A lower count on a later assertion is a cloned-
	// authenticator signal and fails the ceremony.
	SignCount int `json:"sign_count"`
	// Flags is the raw authenticator flags byte (UP/UV/BE/BS) from the last
	// verified ceremony. go-webauthn rejects a login whose BackupEligible flag
	// disagrees with the stored one, so this has to survive round trips. Zero
	// means no flags were ever recorded: user presence is mandatory in every
	// ceremony, so a genuine value always has at least bit 0 set.
	Flags int `json:"flags"`
	// FriendlyName is an optional label for the authenticator. Empty when the
	// user never named it. The current list view does not emit it.
	FriendlyName string `json:"friendly_name"`
	// CreatedAt is when registration finished, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// BackupCode holds a hashed backup code for a user.
type BackupCode struct {
	// ID is this code row's UUID.
	ID string `json:"id"`
	// UserID is the account that may spend this code.
	UserID string `json:"user_id"`
	// CodeHash is the HMAC-SHA256 of the 16-hex plaintext code under the
	// server HMAC key. Tagged json:"-" because the plaintext is shown
	// once at generation and must not be recoverable from any later
	// response. HMAC rather than Argon2id so verify can check every
	// unused code without a memory-hard cost per guess.
	CodeHash string `json:"-"`
	// Used is true after POST /auth/2fa/backup-code/verify consumes the
	// code. Consumption is compare-and-swap so a concurrent spend cannot
	// succeed twice.
	Used bool `json:"used"`
	// UsedAt is when the code was consumed, RFC3339 UTC. Nil while Used is
	// false.
	UsedAt *time.Time `json:"used_at"`
	// CreatedAt is when this set was generated, RFC3339 UTC. Generating a
	// new set replaces every previous row.
	CreatedAt time.Time `json:"created_at"`
}

// RateLimit represents a rate limit counter entry.
type RateLimit struct {
	// Key is the limiter bucket (typically "ip:<addr>" or "user:<id>").
	// Combined with WindowStart it is the primary key.
	Key string `json:"key"`
	// WindowStart is the inclusive start of this counting window, RFC3339
	// UTC. A new window starts a new row rather than resetting Count.
	WindowStart time.Time `json:"window_start"`
	// Count is how many requests have been charged to this (Key, WindowStart).
	Count int `json:"count"`
}

// AuditEntry represents an audit log entry.
//
// FingerprintHash is an HMAC of a device fingerprint: it correlates events
// across accounts and is never part of a response. DeviceID is the identifier
// an operator can act on, and that is what the admin audit view carries.
type AuditEntry struct {
	// ID is this event's UUID. The table is append-only; this never changes.
	ID string `json:"id"`
	// Timestamp is when the event was recorded, RFC3339 UTC.
	Timestamp time.Time `json:"timestamp"`
	// EventType is the catalog name (login_success, token_minted, svcdoc_put,
	// and so on). New members may appear in a minor release.
	EventType string `json:"event_type"`
	// UserID is the affected account, when the event has one. Empty on
	// client-only events and on _global service-document writes, so those
	// rows do not appear in a subject's data export.
	UserID string `json:"user_id"`
	// ClientID is the service client that performed the action, when the
	// actor was a client. Empty on a user-initiated event.
	ClientID string `json:"client_id"`
	// IP is the remote address recorded with the event. Empty when none was
	// available.
	IP string `json:"ip"`
	// UserAgent is the User-Agent recorded with the event. Empty when the
	// client sent none.
	UserAgent string `json:"user_agent"`
	// FingerprintHash is the HMAC of the request fingerprint. Tagged
	// json:"-" because it correlates events across accounts; GET /admin/audit
	// and GET /user/data-export both withhold it and expose DeviceID instead.
	FingerprintHash string `json:"-"`
	// DeviceID is the device row the event is attributed to, when one was
	// known. Empty on events with no device binding.
	DeviceID string `json:"device_id"`
	// Metadata is event-specific structured detail (reason, kid, doc_key).
	// It must never contain credential material; scrubbers drop known
	// sensitive keys by event-type prefix.
	Metadata map[string]interface{} `json:"metadata"`
	// RiskScore is a hardcoded per-event-type severity tag, not a computed
	// measurement. It is excluded from the 1.x stability contract (spec.md
	// section 0.6.1); clients must not threshold or alert on it.
	RiskScore int `json:"risk_score"`
}

// AdminConfig represents a key-value configuration entry.
type AdminConfig struct {
	// Key is the runtime setting name addressed by PUT/DELETE
	// /admin/config/{key}. Environment variables remain the primary
	// configuration; this store is a small overlay.
	Key string `json:"key"`
	// Value is the stored string. Interpretation is key-specific and not
	// typed on the wire.
	Value string `json:"value"`
	// UpdatedAt is when Value was last written, RFC3339 UTC.
	UpdatedAt time.Time `json:"updated_at"`
}

// IdentityProfile holds encrypted PII for a user, keyed by pseudonym.
type IdentityProfile struct {
	// PseudonymID is HMAC-SHA256(userID + ":identity") and the table's
	// primary key. The plaintext user id is not stored on this row.
	PseudonymID string `json:"pseudonym_id"`
	// DataEnc is the AES-256-GCM ciphertext of the IdentityData JSON.
	// Tagged json:"-" so GET /user/identity can only return the decrypted
	// view the handler builds; the ciphertext never belongs on the wire.
	DataEnc []byte `json:"-"`
	// Version is the compare-and-set generation. PUT /user/identity and
	// POST /user/marketing/unsubscribe increment it so a concurrent write
	// cannot silently clobber a withdrawal.
	Version int `json:"version"`
	// UpdatedAt is when DataEnc was last rewritten, RFC3339 UTC. GET
	// /user/identity surfaces it as updated_at.
	UpdatedAt time.Time `json:"updated_at"`
	// CreatedAt is when the profile row was first inserted, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// Blob holds an encrypted user data blob, keyed by pseudonym.
type Blob struct {
	// ID is this blob's UUID. GET/DELETE /user/blobs/{id} address it.
	ID string `json:"id"`
	// PseudonymID is HMAC-SHA256(userID + ":objects"). The plaintext user
	// id is not stored on this row, so the table cannot enumerate which
	// users hold objects.
	PseudonymID string `json:"pseudonym_id"`
	// RefHash is HMAC of the reference name (empty for unnamed blobs).
	// Tagged json:"-" so the plaintext name never appears in a listing or
	// dump; named-blob lookup recomputes the hash from the path.
	RefHash string `json:"-"`
	// LabelEnc is the AES-GCM ciphertext of the user-supplied label.
	// Tagged json:"-" because the listing decrypts it into the view's
	// label field; the ciphertext is not a client concern.
	LabelEnc []byte `json:"-"`
	// DataEnc is the compressed-then-AES-GCM ciphertext of the payload.
	// Tagged json:"-" so GET /user/blobs returns metadata only; contents
	// leave only through the binary download routes.
	DataEnc []byte `json:"-"`
	// SizeBytes is the original plaintext length before compression.
	SizeBytes int `json:"size_bytes"`
	// StoredBytes is the ciphertext length, which is what the per-user
	// quota charges. It can be smaller or larger than SizeBytes depending
	// on compressibility and GCM overhead.
	StoredBytes int `json:"stored_bytes"`
	// Checksum is "sha256:" plus the hex digest of the original plaintext,
	// so a client can verify a download without trusting the transport.
	Checksum string `json:"checksum"`
	// CreatedAt is when the blob was written, RFC3339 UTC. Named-blob
	// replacement produces a new row and a new timestamp.
	CreatedAt time.Time `json:"created_at"`
}

// BlobQuota summarizes a user's blob storage usage.
type BlobQuota struct {
	// UsedBytes is the sum of StoredBytes across the user's blobs. The
	// GET /user/blobs quota object adds max_bytes from configuration; this
	// type is the persistence summary only.
	UsedBytes int `json:"used_bytes"`
	// UsedCount is how many blob rows the user holds, named and unnamed.
	UsedCount int `json:"used_count"`
}

// AdminRole represents a role from the auth.admin_roles reference table.
type AdminRole struct {
	// Role is the admin-tier name ("viewer", "operator", "admin",
	// "super_admin"). It is joined onto AdminUser and is never issued as a
	// user JWT role.
	Role string `json:"role"`
	// Description is the human-readable explanation shown in the admin
	// console. Empty when none was stored.
	Description string `json:"description"`
	// Rank is the privilege ordering used to prevent a lower-ranked admin
	// from creating or editing a higher-ranked one. Higher is more
	// privileged.
	Rank int `json:"rank"`
}

// AppRole is an entry in the custom roles catalog (auth.app_roles). User roles
// are validated against this catalog at JWT issuance. Reserved=true entries are
// catalog-protected and cannot be deleted via the admin API.
type AppRole struct {
	// Name is the role string stored on User.Roles and issued in the JWT.
	// GET /admin/roles lists it; DELETE /admin/roles/{name} addresses it.
	Name string `json:"name"`
	// Namespace groups roles by application (for example "forum"). Empty
	// means the role is global rather than app-scoped.
	Namespace string `json:"namespace"`
	// Description is the operator-facing explanation. Empty when none was
	// stored.
	Description string `json:"description"`
	// Reserved is true for catalog-protected entries. Those cannot be
	// deleted via DELETE /admin/roles/{name}; they exist so seed roles
	// survive an accidental wipe.
	Reserved bool `json:"reserved"`
	// CreatedAt is when the catalog entry was inserted, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// EmailBranding holds the per-app white-label overrides applied to auth emails.
// App is the tenant slug (e.g. "acme"). Any empty field falls back to the
// global default at render time. FromAddress is honoured only when its domain
// is on the configured From allowlist (see config.EmailFromAllowedDomains).
type EmailBranding struct {
	// App is the tenant slug matching ^[a-z0-9][a-z0-9_-]{0,63}$. It is
	// selected by the proxy-set X-Vault-App header, not by a query parameter.
	App string `json:"app"`
	// AppName replaces the product name in email copy. Empty falls back to
	// the global brand at render time.
	AppName string `json:"app_name"`
	// LogoURL is the image the template embeds. Empty falls back to the
	// global logo.
	LogoURL string `json:"logo_url"`
	// PrimaryColor is the accent colour, typically "#RRGGBB". Empty falls
	// back to the global accent.
	PrimaryColor string `json:"primary_color"`
	// FromName is the display name on the From header. Empty falls back to
	// the global From display name.
	FromName string `json:"from_name"`
	// FromAddress is the mailbox used as From. Empty falls back to the
	// global address. A non-empty value is honoured only when its domain is
	// on VAULT_EMAIL_FROM_ALLOWED_DOMAINS, so an admin cannot point mail at
	// a domain the deployment does not control.
	FromAddress string `json:"from_address"`
	// CreatedAt is when the branding row was first written, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when any branding column last changed, RFC3339 UTC.
	UpdatedAt time.Time `json:"updated_at"`
	// UpdatedBy is the admin username that last wrote the row. Empty on a
	// row inserted by a seed or migration.
	UpdatedBy string `json:"updated_by"`
}

// EmailTemplate is a per-app, per-type full override of an auth email body.
// TemplateName is one of the email.Template* constants. When absent or
// disabled, the global template is rendered with the app's branding instead.
type EmailTemplate struct {
	// ID is this override row's UUID.
	ID string `json:"id"`
	// App is the tenant slug this override applies to, same charset as
	// EmailBranding.App.
	App string `json:"app"`
	// TemplateName is one of verification, password_reset, new_device,
	// account_locked, 2fa_setup, suspicious_activity, email_otp.
	TemplateName string `json:"template_name"`
	// Subject is the override Subject header. Required on a stored row.
	Subject string `json:"subject"`
	// HTMLContent is the full HTML body. Required on a stored row; there is
	// no merge with the global HTML.
	HTMLContent string `json:"html_content"`
	// TextContent is the plain-text alternative. Empty means the mailer
	// sends HTML only.
	TextContent string `json:"text_content"`
	// Enabled is false when the override is stored but should not be used.
	// The send path then falls back to the global template with this app's
	// branding.
	Enabled bool `json:"enabled"`
	// CreatedAt is when the override was first written, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
	// CreatedBy is the admin username that inserted the row. Empty on a
	// seeded row.
	CreatedBy string `json:"created_by"`
	// UpdatedAt is when subject or body last changed, RFC3339 UTC.
	UpdatedAt time.Time `json:"updated_at"`
	// UpdatedBy is the admin username that last wrote the row. Empty on a
	// seeded row.
	UpdatedBy string `json:"updated_by"`
}

// AdminUser represents an admin gateway operator account.
// Admin accounts are stored in auth.admin_users, fully decoupled from auth.users.
// The Role field is populated from the auth.admin_roles reference table via JOIN.
type AdminUser struct {
	// ID is this operator account's UUID. Admin sessions and audit rows
	// point at it, never at a User.ID.
	ID string `json:"id"`
	// Username is the admin-gateway login identifier. It is not an email
	// and lives in a different table from User.Email.
	Username string `json:"username"`
	// PasswordHash is the Argon2id verifier of the admin password. Tagged
	// json:"-" so GET /admin/status and admin listings cannot leak it.
	PasswordHash string `json:"-"`
	// Role is the admin-tier name joined from auth.admin_roles. It selects
	// the RBAC permission set; it is never copied onto a user JWT.
	Role string `json:"role"`
	// TOTPSecretEnc is the AES-GCM ciphertext of the admin TOTP seed.
	// Tagged json:"-" so the seed returned at setup cannot be read back
	// from a later status call.
	TOTPSecretEnc string `json:"-"`
	// TOTPVerified is true after the admin completes TOTP enrollment.
	// False means TOTP is not yet a required second factor for this
	// operator.
	TOTPVerified bool `json:"totp_verified"`
	// LockedUntil is when an admin lockout expires, RFC3339 UTC. Nil means
	// the operator is not locked.
	LockedUntil *time.Time `json:"locked_until"`
	// FailedLoginCount is consecutive failed admin logins since the last
	// success. Reset to 0 on a successful login.
	FailedLoginCount int `json:"failed_login_count"`
	// LastTOTPCounter is the last accepted TOTP time-step, stored so the
	// same 30-second code cannot be replayed. Tagged json:"-" because it is
	// an anti-replay secret, not a status field.
	LastTOTPCounter int64 `json:"-"`
	// LastLoginAt is the most recent successful admin login, RFC3339 UTC.
	// Nil means the operator has never completed one.
	LastLoginAt *time.Time `json:"last_login_at"`
	// CreatedAt is when the operator account was created, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when any admin-account column last changed, RFC3339 UTC.
	UpdatedAt time.Time `json:"updated_at"`
	// CreatedBy is the username of the operator who created this account.
	// Empty on the bootstrap first-admin row.
	CreatedBy string `json:"created_by"`
}

// AdminSession represents an active admin gateway session.
type AdminSession struct {
	// ID is this session row's UUID.
	ID string `json:"id"`
	// AdminID is the AdminUser this session authenticates.
	AdminID string `json:"admin_id"`
	// TokenHash is the HMAC of the session cookie value. Tagged json:"-"
	// so a session listing cannot be turned into a stolen cookie.
	TokenHash string `json:"-"`
	// IP is the remote address recorded at session creation.
	IP string `json:"ip"`
	// UserAgent is the User-Agent recorded at session creation. Empty if
	// the client sent none.
	UserAgent string `json:"user_agent"`
	// CreatedAt is when the session was issued, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is when the session cookie stops being accepted, RFC3339
	// UTC. Logout revokes the row before this instant.
	ExpiresAt time.Time `json:"expires_at"`
	// Revoked is true after POST /admin/auth/logout or an operator
	// revocation. A revoked session is rejected even before ExpiresAt.
	Revoked bool `json:"revoked"`
}
