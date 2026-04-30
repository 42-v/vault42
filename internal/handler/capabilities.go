package handler

import "net/http"

// capabilitiesResponse is the pre-built JSON response for GET /auth/capabilities.
type capabilitiesResponse struct {
	RegistrationEnabled bool     `json:"registration_enabled"`
	MFARequired         bool     `json:"mfa_required"`
	OAuthProviders      []string `json:"oauth_providers"`
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
