package handler

import (
	"encoding/json"
	"time"

	"github.com/42-v/vault42/internal/service"
)

// StatusResponse is returned by endpoints that indicate success/failure with a single status field.
type StatusResponse struct {
	// Status is a lowercase snake_case outcome token such as "ok", "deleted",
	// "logged_out", or "password_changed". It is not a free-form sentence;
	// callers should switch on the token, not parse English.
	Status string `json:"status"`
}

// StatusMessageResponse is returned by endpoints that include both status and message.
type StatusMessageResponse struct {
	// Status is a lowercase snake_case outcome token. On POST /auth/register
	// for an already-registered email it is "verification_email_sent" so that
	// response is indistinguishable from a new signup's anti-enumeration path.
	Status string `json:"status"`
	// Message is human-readable prose shown to the end user. It is not in
	// the stability contract (spec.md section 0.6); Status is.
	Message string `json:"message"`
}

// ConfirmPasswordResponse is returned after password confirmation.
type ConfirmPasswordResponse struct {
	// Confirmed is always true on a 200 from POST /auth/confirm. A failed
	// confirmation is an error body, not confirmed=false.
	Confirmed bool `json:"confirmed"`
	// ExpiresIn is how many seconds the elevated-access window lasts from
	// this response. Currently 300; TOTP setup, WebAuthn register/delete and
	// backup-code generation require the window to still be open.
	ExpiresIn int `json:"expires_in"`
}

// VerifiedResponse is returned by 2FA verification endpoints.
type VerifiedResponse struct {
	// Verified is always true on a 200 from a setup-mode 2FA verify. Login
	// completion returns tokens instead of this type. A failed verify is an
	// error body, not verified=false.
	Verified bool `json:"verified"`
}

// ProfileResponse is returned by GET /user/profile and PUT /user/profile.
//
// AvatarURL closes the write-only gap: PUT accepts avatar_url and the data
// export returns it, so a client that set it had no way to read it back short
// of an Art. 15 export.
//
// MFAMethods is always an array, never null.
type ProfileResponse struct {
	// ID is the account UUID, equal to the access token's subject.
	ID string `json:"id"`
	// Email is the login address. It cannot be changed through PUT
	// /user/profile.
	Email string `json:"email"`
	// EmailVerified is true after GET /auth/verify-email. An unverified
	// account cannot obtain this response because it cannot log in.
	EmailVerified bool `json:"email_verified"`
	// DisplayName is the human-facing name. Empty means the client should
	// fall back to Email.
	DisplayName string `json:"display_name"`
	// AvatarURL is the HTTPS image URL last written by PUT /user/profile.
	// Empty means none is set. Always present so a client can read back
	// what it wrote without an Art. 15 export.
	AvatarURL string `json:"avatar_url"`
	// Locale is the BCP 47 tag used to pick email copy. Defaults to "en"
	// when the account was created without one.
	Locale string `json:"locale"`
	// MFARequired is the server-wide VAULT_MFA_REQUIRED flag, not the
	// per-account column on model.User. True means every login must complete
	// a second factor (email OTP is the fallback when the user enrolled
	// none). GET /user/data-export.account.mfa_required is the per-account
	// column and can disagree with this field.
	MFARequired bool `json:"mfa_required"`
	// MFAEnabled is true when the user has a verified TOTP secret or at
	// least one WebAuthn credential. Backup codes and email OTP alone do
	// not set it.
	MFAEnabled bool `json:"mfa_enabled"`
	// MFAMethods is the enrolled-factor list copied from
	// MFAService.GetStatus: "totp" when a verified TOTP secret exists,
	// "webauthn" when at least one credential exists, "backup_code" when
	// at least one unused backup code remains. Always an array; a user
	// with none of those gets [], never null. GetStatus never appends
	// "email_otp": that name is only on POST /auth/login
	// available_methods, and only when VAULT_MFA_REQUIRED is set and the
	// user has no enrolled factor.
	MFAMethods []string `json:"mfa_methods"`
	// CreatedAt is when the account was created, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// UpdateProfileInput is the request body for PUT /user/profile.
// Pointer fields distinguish "not sent" from "set to empty string".
type UpdateProfileInput struct {
	// DisplayName, when present, replaces the stored display name. Null or
	// omitted leaves the current value. A present empty string clears it
	// after sanitization; max 100 runes.
	DisplayName *string `json:"display_name"`
	// AvatarURL, when present, replaces the stored avatar. A value that is
	// not an https:// URL, or is longer than 2048 bytes, is stored as empty
	// (cleared), not rejected. Omitted leaves the current value.
	AvatarURL *string `json:"avatar_url"`
	// Locale, when present, replaces the stored BCP 47 tag. Empty or
	// invalid input is stored as "en", not rejected. Omitted leaves the
	// current value.
	Locale *string `json:"locale"`
}

// SessionInfo represents a single session in the sessions list.
type SessionInfo struct {
	// ID is the device UUID this session is bound to. DELETE
	// /user/sessions/{id} addresses it.
	ID string `json:"id"`
	// FriendlyName is the stored device label. Login invents one from the
	// User-Agent (for example "Chrome on Windows"; "Unknown Device" if the
	// header is empty or unrecognized). PATCH /user/devices/{id} replaces
	// it. Empty only on a row that skipped the current login path and was
	// never renamed.
	FriendlyName string `json:"friendly_name"`
	// IP is the remote address last recorded on the device.
	IP string `json:"ip"`
	// UserAgent is the User-Agent last recorded on the device. Empty if
	// the client sent none.
	UserAgent string `json:"user_agent"`
	// Trusted is the remembered-device flag. Current issuance never sets it,
	// so callers should treat false as the only observed value.
	Trusted bool `json:"trusted"`
	// LastSeenAt is the most recent activity on this session, RFC3339 UTC.
	// Nil only if the device row has never been refreshed, which login
	// does not produce.
	LastSeenAt *time.Time `json:"last_seen_at"`
	// FirstSeenAt is when this device was first bound to the account,
	// RFC3339 UTC.
	FirstSeenAt time.Time `json:"first_seen_at"`
}

// SessionsResponse is returned by GET /user/sessions.
//
// Total carries the standard list-envelope count. The endpoint is unpaged
// today, so it equals the length of Sessions; carrying the key now means limit
// and offset can be added later without changing the response shape.
type SessionsResponse struct {
	// Sessions is every device currently bound to the caller. Always an
	// array; [] when the user has no devices.
	Sessions []SessionInfo `json:"sessions"`
	// Total is len(Sessions). Always present, including on an empty list,
	// so a later paged shape can reuse the key.
	Total int `json:"total"`
}

// DeviceInfo represents a single device in the devices list.
type DeviceInfo struct {
	// ID is the device UUID. PATCH and DELETE /user/devices/{id} address it.
	ID string `json:"id"`
	// FriendlyName is the stored device label. Login invents one from the
	// User-Agent (for example "Chrome on Windows"; "Unknown Device" if the
	// header is empty or unrecognized). PATCH /user/devices/{id} replaces
	// it. Empty only on a row that skipped the current login path and was
	// never renamed.
	FriendlyName string `json:"friendly_name"`
	// Trusted is the remembered-device flag. Current issuance never sets it.
	Trusted bool `json:"trusted"`
	// IP is the remote address last recorded on the device.
	IP string `json:"ip"`
	// UserAgent is the User-Agent last recorded on the device. Empty if
	// the client sent none.
	UserAgent string `json:"user_agent"`
	// LastSeenAt is the most recent activity, RFC3339 UTC. Nil only on a
	// row that has never been refreshed.
	LastSeenAt *time.Time `json:"last_seen_at"`
}

// DevicesResponse is returned by GET /user/devices.
type DevicesResponse struct {
	// Devices is every registered device for the caller. Always an array;
	// [] when none exist. The fingerprint hash is withheld; ID is the
	// identifier a client may act on.
	Devices []DeviceInfo `json:"devices"`
	// Total is len(Devices). Always present, including on an empty list.
	Total int `json:"total"`
}

// RenameResponse is returned after renaming a device.
type RenameResponse struct {
	// Status is "updated" on a successful PATCH /user/devices/{id}.
	Status string `json:"status"`
	// FriendlyName is the sanitized name that was stored, so the client
	// can display what the server actually accepted.
	FriendlyName string `json:"friendly_name"`
}

// BlobUploadResponse is returned after uploading a blob.
type BlobUploadResponse struct {
	// ID is the new blob UUID. GET/DELETE /user/blobs/{id} address it.
	ID string `json:"id"`
	// Label is the sanitized label from X-Blob-Label or the multipart
	// "label" field. For a named-blob PUT it is the path name. Empty when
	// the client supplied none.
	Label string `json:"label"`
	// SizeBytes is the original plaintext length before compression.
	SizeBytes int `json:"size_bytes"`
	// StoredBytes is the ciphertext length charged against the quota.
	StoredBytes int `json:"stored_bytes"`
	// Checksum is "sha256:" plus the hex digest of the original plaintext.
	Checksum string `json:"checksum"`
	// CreatedAt is when the blob was written, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// BlobListResponse is returned by GET /user/blobs. Its wire shape is defined by
// blobListWire below, which MarshalJSON produces; the tags here describe the
// same fields for readers.
type BlobListResponse struct {
	// Blobs is the metadata list (id, label, named, sizes, checksum,
	// created_at). Always an array; contents are never included.
	Blobs any `json:"blobs"`
	// Count is the element count. The json tag is "total" for the struct
	// field, but MarshalJSON emits the same number as both total (the
	// canonical list-envelope key) and count (the pre-1.0.0 Vue SDK name).
	Count int `json:"total"`
	// Quota is used_bytes, max_bytes, used_count and max_count for this
	// user. max_* come from VAULT_BLOB_QUOTA_BYTES and VAULT_BLOB_MAX_PER_USER.
	Quota any `json:"quota"`
}

// blobListWire is the serialized form of BlobListResponse. The element count is
// emitted twice: total is the name every list endpoint uses, and count is the
// pre-1.0.0 name that the published Vue SDK reads (BlobListResult.count in
// packages/vue/src/types.ts). Remove count at the next major version.
type blobListWire struct {
	// Blobs is the same metadata list as BlobListResponse.Blobs.
	Blobs any `json:"blobs"`
	// Total is the canonical list-envelope count, equal to len(Blobs).
	Total int `json:"total"`
	// Count is the deprecated alias of Total, kept so the published Vue
	// SDK keeps working until 2.0.0.
	Count int `json:"count"`
	// Quota is the same quota object as BlobListResponse.Quota.
	Quota any `json:"quota"`
}

// MarshalJSON publishes the element count under both names.
func (r BlobListResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(blobListWire{
		Blobs: r.Blobs,
		Total: r.Count,
		Count: r.Count,
		Quota: r.Quota,
	})
}

// ClientTokenResponse is returned by POST /client/token.
type ClientTokenResponse struct {
	// AccessToken is the RS256 JWT the client presents as
	// Authorization: Bearer. It is not stored server-side.
	AccessToken string `json:"access_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
	// TokenType is the HTTP presentation scheme. Always "Bearer".
	TokenType string `json:"token_type"`
	// ExpiresIn is the access-token lifetime in seconds, typically 900.
	ExpiresIn int `json:"expires_in"`
	// Scope is the space-separated grant, the intersection of the request
	// and the client's allow-list. If the client requested nothing, it is
	// the full allow-list.
	Scope string `json:"scope"`
}

// KMSUnwrapRequest is the POST /kms/unwrap request body. Ciphertext is the
// base64 (std) wrapped-key envelope (nonce || AES-256-GCM ciphertext); Kid names
// the KEK it was wrapped under.
type KMSUnwrapRequest struct {
	// Kid names the KEK the envelope was wrapped under. Required. An empty
	// or unknown value collapses to the same 400 unwrap_failed as a bad
	// ciphertext so the endpoint is not a key-existence oracle.
	Kid string `json:"kid"`
	// Ciphertext is standard-base64 of nonce || AES-256-GCM ciphertext,
	// with kid bound as AAD. Required. Produce it with `vault kms wrap`.
	Ciphertext string `json:"ciphertext"`
}

// KMSUnwrapResponse is returned by POST /kms/unwrap. Plaintext is the base64
// (std) unwrapped key, released only over the authenticated response.
type KMSUnwrapResponse struct {
	// Plaintext is standard-base64 of the unwrapped key. It is returned
	// only to a caller holding kms:unwrap, and only over the response
	// body; it is never logged.
	Plaintext string `json:"plaintext"` // #nosec G117 -- base64 key material, returned only to the authorized caller over the response body
}

// OAuthExchangeData is the token data stored in cache and returned by POST /auth/oauth2/exchange.
type OAuthExchangeData struct {
	// AccessToken is the RS256 user JWT issued after a successful social
	// callback. The one-time exchange code that retrieves it lives 60
	// seconds and is deleted atomically.
	AccessToken string `json:"access_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
	// TokenType is the HTTP presentation scheme. Always "Bearer".
	TokenType string `json:"token_type"`
	// ExpiresIn is the access-token lifetime in seconds.
	ExpiresIn int `json:"expires_in"`
}

// TOTPSetupResponse is returned by POST /auth/2fa/totp/setup.
type TOTPSetupResponse struct {
	// Secret is the base32 TOTP seed. Shown once; the stored copy is
	// encrypted and never returned again. The client must persist it or
	// the otpauth URL before leaving the page.
	Secret string `json:"secret"`
	// OTPURL is the otpauth:// URL for QR rendering (issuer, account,
	// SHA1, 6 digits, 30-second period). Equivalent to Secret; either is
	// enough to enroll an authenticator.
	OTPURL string `json:"otp_url"`
}

// BackupCodesResponse is returned by POST /auth/2fa/backup-codes.
type BackupCodesResponse struct {
	// Codes is the new set of 10 single-use 16-hex codes (RandomHex(8),
	// 64-bit entropy). Any previous set is replaced. Each code is stored
	// as HMAC-SHA256 of the plaintext under the server HMAC key, not as
	// Argon2id; verification compares the guess against every unused hash
	// in constant time, which Argon2id would make too expensive. The
	// plaintext is shown only in this response.
	Codes []string `json:"codes"`
	// Warning is a fixed reminder that the codes will not be shown again.
	// Prose is not in the stability contract; the codes array is.
	Warning string `json:"warning"`
}

// CredentialInfo represents a single WebAuthn credential.
type CredentialInfo struct {
	// ID is the vault42 credential UUID, not the authenticator credential
	// id. DELETE /auth/2fa/webauthn/credentials/{id} addresses it.
	ID string `json:"id"`
	// SignCount is the authenticator signature counter from the last
	// verified assertion. A later assertion with a lower count fails as a
	// cloned-authenticator signal.
	SignCount int `json:"sign_count"`
	// CreatedAt is when registration finished, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// CredentialListResponse is returned by GET /auth/2fa/webauthn/credentials.
type CredentialListResponse struct {
	// Credentials is every authenticator registered to the caller. Always
	// an array; [] when none exist.
	Credentials []CredentialInfo `json:"credentials"`
}

// DataExportAccount holds account metadata in a data export.
type DataExportAccount struct {
	// ID is the account UUID.
	ID string `json:"id"`
	// Email is the login address currently stored on the account.
	Email string `json:"email"`
	// EmailVerified is the current verify flag.
	EmailVerified bool `json:"email_verified"`
	// DisplayName is the stored display name. Empty if none was set.
	DisplayName string `json:"display_name"`
	// AvatarURL is the stored HTTPS avatar URL. Empty if none was set.
	AvatarURL string `json:"avatar_url"`
	// Locale is the stored BCP 47 tag.
	Locale string `json:"locale"`
	// Roles is the application-role list that would be issued at login.
	// Always an array.
	Roles []string `json:"roles"`
	// MFARequired is the per-account column on model.User, not the
	// server-wide VAULT_MFA_REQUIRED flag that GET /user/profile reports.
	// The two can disagree.
	MFARequired bool `json:"mfa_required"`
	// Disabled is the operator-set flag that refuses login.
	Disabled bool `json:"disabled"`
	// Banned is the operator-set sanction flag that refuses login.
	Banned bool `json:"banned"`
	// CreatedAt is when the account was created, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when any persisted account column last changed,
	// RFC3339 UTC.
	UpdatedAt time.Time `json:"updated_at"`
	// LastLoginAt is the most recent successful login, RFC3339 UTC. Null
	// when the account has never completed one.
	LastLoginAt *time.Time `json:"last_login_at"`
}

// DataExportDevice holds a single device in a data export.
type DataExportDevice struct {
	// ID is the device UUID.
	ID string `json:"id"`
	// FriendlyName is the stored device label. Login invents one from the
	// User-Agent (for example "Chrome on Windows"; "Unknown Device" if the
	// header is empty or unrecognized). PATCH /user/devices/{id} replaces
	// it. Empty only on a row that skipped the current login path and was
	// never renamed.
	FriendlyName string `json:"friendly_name"`
	// Trusted is the remembered-device flag. Current issuance never sets it.
	Trusted bool `json:"trusted"`
	// IP is the remote address last recorded on the device.
	IP string `json:"ip"`
	// UserAgent is the User-Agent last recorded on the device.
	UserAgent string `json:"user_agent"`
	// FirstSeenAt is when this device was first bound, RFC3339 UTC.
	FirstSeenAt time.Time `json:"first_seen_at"`
	// LastSeenAt is the most recent activity, RFC3339 UTC. Null only if
	// the row was never refreshed.
	LastSeenAt *time.Time `json:"last_seen_at"`
}

// DataExportBlob holds blob metadata (no contents) in a data export.
type DataExportBlob struct {
	// ID is the blob UUID.
	ID string `json:"id"`
	// Label is the decrypted user-supplied name. Omitted when the blob
	// has none, so an unnamed blob is not sent as an empty string.
	Label string `json:"label,omitempty"`
	// Named is true when the blob is addressed by a reference name
	// (PUT /user/blobs/named/{name}) rather than only by UUID.
	Named bool `json:"named"`
	// SizeBytes is the original plaintext length. Contents are never
	// included; the user already holds the file they uploaded.
	SizeBytes int `json:"size_bytes"`
	// Checksum is "sha256:" plus the hex digest of the original plaintext.
	Checksum string `json:"checksum"`
	// CreatedAt is when the blob was written, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// DataExportSocialAccount holds a linked social account in a data export.
// Provider tokens are intentionally excluded.
type DataExportSocialAccount struct {
	// Provider is the IdP name (google, github, ...).
	Provider string `json:"provider"`
	// ProviderUserID is the subject the IdP asserted.
	ProviderUserID string `json:"provider_user_id"`
	// Email is the address the IdP asserted at link time. Omitted when
	// the provider released none.
	Email string `json:"email,omitempty"`
	// CreatedAt is when the link was stored, RFC3339 UTC.
	CreatedAt time.Time `json:"created_at"`
}

// DataExportAuditEvent holds a single user-scoped audit event in a data export.
type DataExportAuditEvent struct {
	// Timestamp is when the event was recorded, RFC3339 UTC.
	Timestamp time.Time `json:"timestamp"`
	// EventType is the catalog name (login_success, identity_write, ...).
	EventType string `json:"event_type"`
	// IP is the remote address recorded with the event. Omitted when none
	// was stored.
	IP string `json:"ip,omitempty"`
	// UserAgent is the User-Agent recorded with the event. Omitted when
	// none was stored.
	UserAgent string `json:"user_agent,omitempty"`
	// Metadata is event-specific structured detail. Omitted when empty.
	// Fingerprint hashes and credential material are not included.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// DataExportResponse is the aggregate returned by GET /user/data-export. It
// fulfils the data subject's right of access and right to data portability
// (GDPR Articles 15 and 20) by returning every category of personal data the
// service holds for the requesting user in a structured, machine-readable form.
type DataExportResponse struct {
	// GeneratedAt is when this document was assembled, RFC3339 UTC. The
	// endpoint stores nothing, so two calls can differ if data changed.
	GeneratedAt time.Time `json:"generated_at"`
	// Account is the live user-row projection (no password hash).
	Account DataExportAccount `json:"account"`
	// Identity is the decrypted PII profile. Null when the identity store
	// is disabled or the user has never written one, so a missing profile
	// is distinct from an empty one.
	Identity *IdentityResponse `json:"identity"`
	// Devices is every device bound to the account. Always an array.
	Devices []DataExportDevice `json:"devices"`
	// Blobs is blob metadata only, never contents. Always an array; []
	// when blob storage is disabled or the user holds none.
	Blobs []DataExportBlob `json:"blobs"`
	// SocialAccounts is every linked IdP, without provider tokens. Always
	// an array.
	SocialAccounts []DataExportSocialAccount `json:"social_accounts"`
	// AuditEvents is the most recent user-scoped events, capped at
	// AuditEventsLimit. Always an array. Use AuditEventsTruncated to tell
	// a partial list from a complete one.
	AuditEvents []DataExportAuditEvent `json:"audit_events"`

	// ServiceDocuments carries the decrypted service-scoped documents held about
	// this subject, including ones marked private. A service's privacy from other
	// services is not privacy from the data subject: Art. 15 entitles them to the
	// personal data, not to the subset the authoring service chose to publish.
	ServiceDocuments []*service.ServiceDocumentExport `json:"service_documents"`

	// AuditEventsTotal is how many user-scoped audit events are held. It can
	// exceed len(AuditEvents) when the export cap was reached.
	AuditEventsTotal int `json:"audit_events_total"`
	// AuditEventsLimit is the cap applied to AuditEvents (currently 1000,
	// most recent first). It is repeated in the body so a client does not
	// have to hard-code it.
	AuditEventsLimit int `json:"audit_events_limit"`
	// AuditEventsTruncated is true when AuditEventsTotal > len(AuditEvents),
	// so a subject can tell a partial export from a complete one and ask the
	// operator for the remainder instead of assuming this is everything.
	AuditEventsTruncated bool `json:"audit_events_truncated"`
}

// IdentityResponse is returned by GET /user/identity.
type IdentityResponse struct {
	// GivenName is the stored given name. Empty when never set. Always
	// present on GET so a client can tell "cleared" from a decode miss.
	GivenName string `json:"given_name"`
	// FamilyName is the stored family name. Empty when never set.
	FamilyName string `json:"family_name"`
	// Username is an optional handle, 3-32 runes when set. Omitted when
	// empty so a profile without one does not send a blank string.
	Username string `json:"username,omitempty"`
	// Country is an ISO 3166-1 alpha-2 code (handler: two uppercase
	// letters). Empty when never set; still present so a client can clear
	// and read back.
	Country string `json:"country"`
	// State is an optional region code, at most 3 runes. Omitted when empty.
	State string `json:"state,omitempty"`
	// DateOfBirth is YYYY-MM-DD. Empty when never set. A future date is
	// rejected on PUT.
	DateOfBirth string `json:"date_of_birth"`
	// Sex is "male", "female", or empty. Other values are rejected on PUT
	// as invalid_profile even though the handler truncates to 50 runes.
	Sex string `json:"sex"`
	// MarketingEmails is the current preference. Omitted when no value
	// has been stored. True alone does not authorise sending; read
	// MarketingConsent.Affirmative.
	MarketingEmails *bool `json:"marketing_emails,omitempty"`
	// UpdatedAt is when the encrypted profile was last rewritten, RFC3339
	// UTC.
	UpdatedAt string `json:"updated_at"`
	// Billing is the stored billing address. Omitted when the user never
	// wrote one.
	Billing any `json:"billing,omitempty"`
	// Dynamic is namespaced opaque JSON (keys like "legacy.forum"), max
	// 64 KiB encoded. Omitted when empty. vault42 validates size and shape
	// only; it does not interpret the values.
	Dynamic map[string]json.RawMessage `json:"dynamic,omitempty"`

	// MarketingConsent exposes the provenance behind MarketingEmails, read-only.
	// Without it a client cannot tell an affirmative opt-in from an imported or
	// legacy value that merely looks like one, and so cannot know to ask the user
	// to confirm. It is never read back off a PUT.
	MarketingConsent *MarketingConsentView `json:"marketing_consent,omitempty"`
}

// MarketingConsentView is the read-only projection of a consent record.
type MarketingConsentView struct {
	// Granted is the stored preference. It is not enough to send mail;
	// Affirmative must also be true.
	Granted bool `json:"granted"`
	// Source is how the preference was recorded: registration, profile,
	// unsubscribe, import, or legacy.
	Source string `json:"source"`
	// At is when the preference was stamped, RFC3339 UTC. Omitted when
	// the stored timestamp is zero (a legacy row with no clock).
	At string `json:"at,omitempty"`
	// Affirmative is false for imported and legacy values: the preference is
	// known, but it is not consent that could be demonstrated under Art. 7, and
	// nothing may be sent on the strength of it.
	Affirmative bool `json:"affirmative"`
}
