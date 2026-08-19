package handler

import (
	"crypto/rsa"
	"net/http"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// WellKnownHandler handles /.well-known/* endpoints.
type WellKnownHandler struct {
	// keys is the static key set, written once by NewWellKnownHandler and never
	// again. It carried a sync.RWMutex for as long as UpdateKeys existed to write
	// it during rotation; UpdateKeys had no caller, because rotation reaches this
	// handler through keyProvider instead -- cmd/vault's SetOnKeyChange callback
	// says so in as many words. A lock over a field with no writer reads as
	// evidence of concurrent mutation that does not happen.
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
		keys = h.keys
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
//
// vault42 is not an OpenID Connect provider. It has no authorization-code
// token endpoint, it issues no ID token to a relying party, its user profile
// is not a UserInfo response, and /auth/register is end-user signup rather
// than RFC 7591 dynamic client registration. The document therefore states
// only what is true of this server: the issuer stamped into every token it
// signs, where the verification keys for those tokens live, and the signature
// algorithm those tokens use.
//
// The algorithm is also published per key in the JWKS, which stays correct if
// a key of another algorithm is ever added; the summary key here exists so a
// consumer can pin an expected algorithm before it fetches the key set. It is
// deliberately not named id_token_signing_alg_values_supported, because no ID
// token is ever issued.
//
// Keys are omitted rather than faked. Once POST /client/token reads
// grant_type and reports RFC 6749 error codes, token_endpoint,
// grant_types_supported and token_endpoint_auth_methods_supported can be added
// back, which is an additive change.
func (h *WellKnownHandler) OpenIDConfig(w http.ResponseWriter, r *http.Request) {
	issuer := h.issuer

	discovery := map[string]interface{}{
		"issuer":   issuer,
		"jwks_uri": issuer + "/.well-known/jwks.json",
		"access_token_signing_alg_values_supported": []string{"RS256"},
	}

	WriteJSON(w, http.StatusOK, discovery)
}
