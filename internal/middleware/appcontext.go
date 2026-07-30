package middleware

import (
	"net/http"

	"github.com/42-v/vault42/internal/email"
)

// AppContext extracts the white-label tenant slug from the X-Vault-App request
// header and stores it in the request context for the email layer to pick up.
//
// The slug decides whose name, logo and colours a genuine auth email wears, and
// none of the endpoints that send one are authenticated. It is therefore only
// honoured when the request reached vault42 through a trusted proxy
// (TRUSTED_PROXIES): the gateway or BFF in front of vault42 sets the header per
// tenant and overwrites whatever the client sent. A request arriving directly,
// or through a peer outside the trusted set, selects no tenant, so an outside
// caller cannot make a real password-reset or verification email arrive wearing
// another tenant's branding. The former ?app= query fallback is gone for the
// same reason: a proxy forwards the client's query string verbatim, so it can
// never be an operator-controlled channel.
//
// An absent, malformed or untrusted slug is ignored, leaving the global
// branding in effect.
func AppContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app := r.Header.Get("X-Vault-App")
		if email.ValidApp(app) && isTrustedProxy(stripPort(r.RemoteAddr)) {
			r = r.WithContext(email.WithApp(r.Context(), app))
		}
		next.ServeHTTP(w, r)
	})
}
