package middleware

import (
	"net/http"

	"github.com/42-v/vault42/internal/email"
)

// AppContext extracts the white-label tenant slug from the request and stores it
// in the request context for the email layer to pick up. Resolution order: the
// X-Vault-App header, then the ?app= query parameter. An invalid or absent slug
// is ignored, leaving the global branding in effect.
//
// A gateway or BFF in front of vault42 (e.g. a tenant's auth proxy) sets the
// header so its users receive auth emails branded as that tenant.
func AppContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app := r.Header.Get("X-Vault-App")
		if app == "" {
			app = r.URL.Query().Get("app")
		}
		if email.ValidApp(app) {
			r = r.WithContext(email.WithApp(r.Context(), app))
		}
		next.ServeHTTP(w, r)
	})
}
