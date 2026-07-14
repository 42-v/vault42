package handler

import (
	"encoding/json"
	"time"
)

// StatusResponse is returned by endpoints that indicate success/failure with a single status field.
type StatusResponse struct {
	Status string `json:"status"`
}

// StatusMessageResponse is returned by endpoints that include both status and message.
type StatusMessageResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// ConfirmPasswordResponse is returned after password confirmation.
type ConfirmPasswordResponse struct {
	Confirmed bool `json:"confirmed"`
	ExpiresIn int  `json:"expires_in"`
}

// VerifiedResponse is returned by 2FA verification endpoints.
type VerifiedResponse struct {
	Verified bool `json:"verified"`
}

// ProfileResponse is returned by GET /user/profile.
type ProfileResponse struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	DisplayName   string    `json:"display_name"`
	Locale        string    `json:"locale"`
	MFARequired   bool      `json:"mfa_required"`
	MFAEnabled    bool      `json:"mfa_enabled"`
	MFAMethods    []string  `json:"mfa_methods"`
	CreatedAt     time.Time `json:"created_at"`
}

// UpdateProfileInput is the request body for PUT /user/profile.
// Pointer fields distinguish "not sent" from "set to empty string".
type UpdateProfileInput struct {
	DisplayName *string `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
	Locale      *string `json:"locale"`
}

// SessionInfo represents a single session in the sessions list.
type SessionInfo struct {
	ID           string     `json:"id"`
	FriendlyName string     `json:"friendly_name"`
	IP           string     `json:"ip"`
	UserAgent    string     `json:"user_agent"`
	Trusted      bool       `json:"trusted"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	FirstSeenAt  time.Time  `json:"first_seen_at"`
}

// SessionsResponse is returned by GET /user/sessions.
type SessionsResponse struct {
	Sessions []SessionInfo `json:"sessions"`
}

// DeviceInfo represents a single device in the devices list.
type DeviceInfo struct {
	ID           string     `json:"id"`
	FriendlyName string     `json:"friendly_name"`
	Trusted      bool       `json:"trusted"`
	IP           string     `json:"ip"`
	UserAgent    string     `json:"user_agent"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
}

// DevicesResponse is returned by GET /user/devices.
type DevicesResponse struct {
	Devices []DeviceInfo `json:"devices"`
}

// RenameResponse is returned after renaming a device.
type RenameResponse struct {
	Status       string `json:"status"`
	FriendlyName string `json:"friendly_name"`
}

// BlobUploadResponse is returned after uploading a blob.
type BlobUploadResponse struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	SizeBytes   int       `json:"size_bytes"`
	StoredBytes int       `json:"stored_bytes"`
	Checksum    string    `json:"checksum"`
	CreatedAt   time.Time `json:"created_at"`
}

// BlobListResponse is returned by GET /user/blobs.
type BlobListResponse struct {
	Blobs any `json:"blobs"`
	Count int `json:"count"`
	Quota any `json:"quota"`
}

// ClientTokenResponse is returned by POST /client/token.
type ClientTokenResponse struct {
	AccessToken string `json:"access_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// KMSUnwrapRequest is the POST /kms/unwrap request body. Ciphertext is the
// base64 (std) wrapped-key envelope (nonce || AES-256-GCM ciphertext); Kid names
// the KEK it was wrapped under.
type KMSUnwrapRequest struct {
	Kid        string `json:"kid"`
	Ciphertext string `json:"ciphertext"`
}

// KMSUnwrapResponse is returned by POST /kms/unwrap. Plaintext is the base64
// (std) unwrapped key, released only over the authenticated response.
type KMSUnwrapResponse struct {
	Plaintext string `json:"plaintext"` // #nosec G117 -- base64 key material, returned only to the authorized caller over the response body
}

// OAuthExchangeData is the token data stored in cache and returned by POST /auth/oauth2/exchange.
type OAuthExchangeData struct {
	AccessToken string `json:"access_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// TOTPSetupResponse is returned by POST /auth/2fa/totp/setup.
type TOTPSetupResponse struct {
	Secret string `json:"secret"`
	OTPURL string `json:"otp_url"`
}

// BackupCodesResponse is returned by POST /auth/2fa/backup-codes.
type BackupCodesResponse struct {
	Codes   []string `json:"codes"`
	Warning string   `json:"warning"`
}

// CredentialInfo represents a single WebAuthn credential.
type CredentialInfo struct {
	ID        string    `json:"id"`
	SignCount int       `json:"sign_count"`
	CreatedAt time.Time `json:"created_at"`
}

// CredentialListResponse is returned by GET /auth/2fa/webauthn/credentials.
type CredentialListResponse struct {
	Credentials []CredentialInfo `json:"credentials"`
}

// DataExportAccount holds account metadata in a data export.
type DataExportAccount struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	DisplayName   string     `json:"display_name"`
	AvatarURL     string     `json:"avatar_url"`
	Locale        string     `json:"locale"`
	Roles         []string   `json:"roles"`
	MFARequired   bool       `json:"mfa_required"`
	Disabled      bool       `json:"disabled"`
	Banned        bool       `json:"banned"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastLoginAt   *time.Time `json:"last_login_at"`
}

// DataExportDevice holds a single device in a data export.
type DataExportDevice struct {
	ID           string     `json:"id"`
	FriendlyName string     `json:"friendly_name"`
	Trusted      bool       `json:"trusted"`
	IP           string     `json:"ip"`
	UserAgent    string     `json:"user_agent"`
	FirstSeenAt  time.Time  `json:"first_seen_at"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
}

// DataExportBlob holds blob metadata (no contents) in a data export.
type DataExportBlob struct {
	ID        string    `json:"id"`
	Label     string    `json:"label,omitempty"`
	Named     bool      `json:"named"`
	SizeBytes int       `json:"size_bytes"`
	Checksum  string    `json:"checksum"`
	CreatedAt time.Time `json:"created_at"`
}

// DataExportSocialAccount holds a linked social account in a data export.
// Provider tokens are intentionally excluded.
type DataExportSocialAccount struct {
	Provider       string    `json:"provider"`
	ProviderUserID string    `json:"provider_user_id"`
	Email          string    `json:"email,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// DataExportAuditEvent holds a single user-scoped audit event in a data export.
type DataExportAuditEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	IP        string                 `json:"ip,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// DataExportResponse is the aggregate returned by GET /user/data-export. It
// fulfils the data subject's right of access and right to data portability
// (GDPR Articles 15 and 20) by returning every category of personal data the
// service holds for the requesting user in a structured, machine-readable form.
type DataExportResponse struct {
	GeneratedAt    time.Time                 `json:"generated_at"`
	Account        DataExportAccount         `json:"account"`
	Identity       *IdentityResponse         `json:"identity"`
	Devices        []DataExportDevice        `json:"devices"`
	Blobs          []DataExportBlob          `json:"blobs"`
	SocialAccounts []DataExportSocialAccount `json:"social_accounts"`
	AuditEvents    []DataExportAuditEvent    `json:"audit_events"`
}

// IdentityResponse is returned by GET /user/identity.
type IdentityResponse struct {
	GivenName       string                     `json:"given_name"`
	FamilyName      string                     `json:"family_name"`
	Username        string                     `json:"username,omitempty"`
	Country         string                     `json:"country"`
	State           string                     `json:"state,omitempty"`
	DateOfBirth     string                     `json:"date_of_birth"`
	Sex             string                     `json:"sex"`
	MarketingEmails *bool                      `json:"marketing_emails,omitempty"`
	UpdatedAt       string                     `json:"updated_at"`
	Billing         any                        `json:"billing,omitempty"`
	Dynamic         map[string]json.RawMessage `json:"dynamic,omitempty"`

	// MarketingConsent exposes the provenance behind MarketingEmails, read-only.
	// Without it a client cannot tell an affirmative opt-in from an imported or
	// legacy value that merely looks like one, and so cannot know to ask the user
	// to confirm. It is never read back off a PUT.
	MarketingConsent *MarketingConsentView `json:"marketing_consent,omitempty"`
}

// MarketingConsentView is the read-only projection of a consent record.
type MarketingConsentView struct {
	Granted bool   `json:"granted"`
	Source  string `json:"source"`
	At      string `json:"at,omitempty"`
	// Affirmative is false for imported and legacy values: the preference is
	// known, but it is not consent that could be demonstrated under Art. 7, and
	// nothing may be sent on the strength of it.
	Affirmative bool `json:"affirmative"`
}
