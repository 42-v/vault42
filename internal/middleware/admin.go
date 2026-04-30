package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/42-v/vault42/internal/httputil"
)

// AdminAuth middleware validates admin Bearer tokens against a known hash.
// The verifyFunc should perform constant-time comparison (e.g., Argon2id verify).
func AdminAuth(verifyFunc func(token string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				httputil.WriteError(w, http.StatusUnauthorized, "missing_authorization")
				return
			}

			parts := strings.SplitN(auth, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				httputil.WriteError(w, http.StatusUnauthorized, "invalid_authorization")
				return
			}

			token := parts[1]
			if len(token) == 0 || len(token) > 256 {
				httputil.WriteError(w, http.StatusUnauthorized, "invalid_token")
				return
			}

			if !verifyFunc(token) {
				httputil.WriteError(w, http.StatusForbidden, "forbidden")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// StaticTokenAuth creates a simple admin auth middleware that compares
// the Bearer token against a static token using constant-time comparison.
// Used for admin endpoints when Argon2id verification is too expensive.
func StaticTokenAuth(expectedToken string) func(http.Handler) http.Handler {
	expected := []byte(expectedToken)
	return AdminAuth(func(token string) bool {
		return subtle.ConstantTimeCompare(expected, []byte(token)) == 1
	})
}
