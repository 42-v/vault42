package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
)

// DPoP validates DPoP proof-of-possession when a DPoP header is present.
// The cache parameter is used for JTI replay prevention (RFC 9449 §11.1).
//
//nolint:gocognit // RFC 9449 mandates a sequence of checks (typ, alg, jwk, htm, htu, iat, jti, ath); splitting them obscures the spec mapping
func DPoP(c cache.Cache, origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			dpopProof := r.Header.Get("DPoP")
			if dpopProof == "" {
				// No DPoP proof — allow if token doesn't require DPoP
				claims := GetClaims(r.Context())
				if claims != nil && claims.Confirmation != nil && claims.Confirmation.JKT != "" {
					// Token has DPoP binding but no proof provided
					httputil.WriteError(w, http.StatusUnauthorized, "dpop_proof_required")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Validate DPoP proof
			claims := GetClaims(r.Context())
			httpMethod := r.Method
			httpURI := origin + r.URL.Path

			// Compute access token hash (ath) for DPoP binding validation
			var ath string
			if authHeader := r.Header.Get("Authorization"); authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 {
					ath = vaultcrypto.SHA256Base64URL(parts[1])
				}
			}

			thumbprint, jti, err := vaultcrypto.ValidateDPoPProof(dpopProof, httpMethod, httpURI, ath)
			if err != nil {
				log.Printf("DPoP: validation failed")
				httputil.WriteError(w, http.StatusUnauthorized, "invalid_dpop_proof")
				return
			}

			// JTI replay prevention: each DPoP proof can only be used once.
			// When the token has cnf.jkt (DPoP binding), fail closed on cache errors
			// to prevent replay attacks against DPoP-bound tokens.
			tokenRequiresDPoP := claims != nil && claims.Confirmation != nil && claims.Confirmation.JKT != ""
			if jti != "" {
				if c == nil {
					if tokenRequiresDPoP {
						log.Printf("DPoP: JTI replay prevention unavailable (cache nil), failing closed")
						httputil.WriteError(w, http.StatusServiceUnavailable, "dpop_replay_check_unavailable")
						return
					}
				} else {
					key := "dpop_jti:" + jti
					isNew, err := c.SetIfNotExists(r.Context(), key, "1", vaultcrypto.DPoPMaxAge+30*time.Second)
					if err != nil {
						if tokenRequiresDPoP {
							log.Printf("DPoP: JTI cache error, failing closed")
							httputil.WriteError(w, http.StatusServiceUnavailable, "dpop_replay_check_unavailable")
							return
						}
						log.Printf("DPoP: JTI cache error (allowing — token not DPoP-bound)")
					} else if !isNew {
						httputil.WriteError(w, http.StatusUnauthorized, "dpop_proof_reused")
						return
					}
				}
			}

			// If token has cnf.jkt, verify thumbprint matches
			if claims != nil && claims.Confirmation != nil && claims.Confirmation.JKT != "" {
				if !vaultcrypto.SecureCompare(claims.Confirmation.JKT, thumbprint) {
					httputil.WriteError(w, http.StatusUnauthorized, "dpop_thumbprint_mismatch")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
