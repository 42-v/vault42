package middleware

import (
	"log"
	"net/http"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
)

// Fingerprint middleware recomputes the device fingerprint on every
// authenticated request and compares it to the JWT claim.
// In soft mode (mobile), mismatch is logged but not rejected.
func Fingerprint(softMode bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				// Not authenticated — skip fingerprint check
				next.ServeHTTP(w, r)
				return
			}

			if claims.Fingerprint == "" {
				// No fingerprint in token — skip
				next.ServeHTTP(w, r)
				return
			}

			fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
				IP:             ClientIP(r),
				UserAgent:      r.Header.Get("User-Agent"),
				AcceptLanguage: r.Header.Get("Accept-Language"),
				TLSFingerprint: TLSFingerprint(r),
			})

			if !vaultcrypto.CompareFingerprints(fp, claims.Fingerprint) {
				if softMode {
					log.Printf("fingerprint check: mismatch user=%s ip=%s", httputil.SafeLogValue(claims.Subject), httputil.SafeLogValue(ClientIP(r))) // #nosec G706 -- sanitized via SafeLogValue
					next.ServeHTTP(w, r)
					return
				}
				httputil.WriteError(w, http.StatusUnauthorized, "invalid_token")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
