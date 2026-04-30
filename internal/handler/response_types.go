package handler

import "time"

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

// IdentityResponse is returned by GET /user/identity.
type IdentityResponse struct {
	GivenName   string `json:"given_name"`
	FamilyName  string `json:"family_name"`
	Country     string `json:"country"`
	DateOfBirth string `json:"date_of_birth"`
	Sex         string `json:"sex"`
	UpdatedAt   string `json:"updated_at"`
	Billing     any    `json:"billing,omitempty"`
}
