package model

import "github.com/go-webauthn/webauthn/webauthn"

// WebAuthnUser implements the webauthn.User interface for use with go-webauthn.
type WebAuthnUser struct {
	User        *User
	Credentials []webauthn.Credential
}

// WebAuthnID returns the user's unique ID as a byte slice.
func (u *WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.User.ID)
}

// WebAuthnName returns the user's email as the WebAuthn account name.
func (u *WebAuthnUser) WebAuthnName() string {
	return u.User.Email
}

// WebAuthnDisplayName returns the user's display name, falling back to email.
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.User.DisplayName != "" {
		return u.User.DisplayName
	}
	return u.User.Email
}

// WebAuthnCredentials returns the user's registered WebAuthn credentials.
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}
