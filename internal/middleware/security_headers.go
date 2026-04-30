package middleware

import (
	"net/http"
	"strings"
)

// SecurityHeaders adds security headers to every response.
// When serveFrontend is true, a permissive CSP is used for frontend routes
// so the embedded Vue SPA can load its assets.
func SecurityHeaders(serveFrontend bool) func(http.Handler) http.Handler {
	apiCSP := "default-src 'none'; frame-ancestors 'none'"
	frontendCSP := "default-src 'self'; frame-ancestors 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data: https:; font-src 'self'"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "0")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
			w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
			w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

			// Use relaxed CSP for frontend routes, strict API CSP for all API endpoints
			isAPI := strings.HasPrefix(r.URL.Path, "/auth/") ||
				strings.HasPrefix(r.URL.Path, "/client/") ||
				strings.HasPrefix(r.URL.Path, "/user/") ||
				strings.HasPrefix(r.URL.Path, "/admin/") ||
				strings.HasPrefix(r.URL.Path, "/.well-known/") ||
				r.URL.Path == "/healthz" ||
				r.URL.Path == "/readyz"
			if serveFrontend && !isAPI {
				w.Header().Set("Content-Security-Policy", frontendCSP)
			} else {
				w.Header().Set("Content-Security-Policy", apiCSP)
			}

			next.ServeHTTP(w, r)
		})
	}
}
