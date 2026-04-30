package handler

import (
	"crypto/rsa"
	"net/http"
	"sync"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// WellKnownHandler handles /.well-known/* endpoints.
type WellKnownHandler struct {
	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	keyProvider func() map[string]*rsa.PublicKey // dynamic provider (keystore mode)
	issuer      string
}

// NewWellKnownHandler creates a new well-known handler with a static key set.
func NewWellKnownHandler(keys map[string]*rsa.PublicKey, issuer string) *WellKnownHandler {
	return &WellKnownHandler{keys: keys, issuer: issuer}
}

// NewDynamicWellKnownHandler creates a well-known handler that fetches keys
// from a dynamic provider function (e.g., keystore.AllPublicKeys).
func NewDynamicWellKnownHandler(keyProvider func() map[string]*rsa.PublicKey, issuer string) *WellKnownHandler {
	return &WellKnownHandler{keyProvider: keyProvider, issuer: issuer}
}

// JWKS handles GET /.well-known/jwks.json.
func (h *WellKnownHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	var keys map[string]*rsa.PublicKey
	if h.keyProvider != nil {
		keys = h.keyProvider()
	} else {
		h.mu.RLock()
		keys = h.keys
		h.mu.RUnlock()
	}

	jwksJSON, err := vaultcrypto.SerializeJWKSJSON(keys)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	w.Write(jwksJSON) // #nosec G104 -- ResponseWriter.Write errors are unactionable (client disconnected)
}

// OpenIDConfig handles GET /.well-known/openid-configuration.
func (h *WellKnownHandler) OpenIDConfig(w http.ResponseWriter, r *http.Request) {
	issuer := h.issuer

	discovery := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/auth/oauth2/authorize",
		"token_endpoint":                        issuer + "/auth/login",
		"userinfo_endpoint":                     issuer + "/user/profile",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"registration_endpoint":                 issuer + "/auth/register",
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"dpop_signing_alg_values_supported":     []string{"RS256", "ES256"},
	}

	WriteJSON(w, http.StatusOK, discovery)
}

// UpdateKeys replaces the JWKS key set (called during rotation).
func (h *WellKnownHandler) UpdateKeys(keys map[string]*rsa.PublicKey) {
	h.mu.Lock()
	h.keys = keys
	h.mu.Unlock()
}
