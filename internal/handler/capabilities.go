package handler

import "net/http"

// capabilitiesResponse is the pre-built JSON response for GET /auth/capabilities.
type capabilitiesResponse struct {
	// RegistrationEnabled is true when POST /auth/register will accept a
	// new account. False means that route answers 403 registration_disabled.
	// Clients must read this rather than probe with a trial request.
	RegistrationEnabled bool `json:"registration_enabled"`
	// MFARequired is the server-wide VAULT_MFA_REQUIRED flag. True means
	// every login must complete a second factor. This is the same value
	// GET /user/profile reports, not the per-account column.
	MFARequired bool `json:"mfa_required"`
	// OAuthProviders is the configured IdP names (google, github, ...).
	// Always an array; [] when no provider is configured, in which case
	// the OAuth2 routes are not mounted.
	OAuthProviders []string `json:"oauth_providers"`
}

// Capabilities returns a handler that responds with server capability flags.
// The response is built once at startup (zero allocation per request).
func Capabilities(registrationEnabled, mfaRequired bool, oauthProviders []string) http.HandlerFunc {
	if oauthProviders == nil {
		oauthProviders = []string{}
	}
	resp := capabilitiesResponse{
		RegistrationEnabled: registrationEnabled,
		MFARequired:         mfaRequired,
		OAuthProviders:      oauthProviders,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, resp)
	}
}
