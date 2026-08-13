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
// It binds nothing today. Binding requires the access token to carry a
// "cnf.jkt" confirmation claim (RFC 9449 §6.1), and no vault42 code path sets
// one, so every request takes the unbound path: a request without a proof
// passes through, and a request with a proof has that proof checked against the
// method, URI and access-token hash but never compared against a thumbprint the
// token committed to. VAULT_DPOP_ENABLED is therefore experimental and
// unsupported until token issuance populates cnf.jkt.
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
					key := dpopReplayKey(jti)
					isNew, err := c.SetIfNotExists(r.Context(), key, "1", dpopReplayTTL)
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

// dpopReplayTTL is how long a spent DPoP jti is remembered.
//
// ValidateDPoPProof measures a proof's age against DPoPMaxAge in both
// directions, so the span in which one proof stays acceptable runs from
// DPoPMaxAge before its iat to DPoPMaxAge after it: twice DPoPMaxAge, not once.
// A caller picks where inside that span the first request lands by choosing the
// iat, and post-dating it by DPoPMaxAge puts the whole remaining span after the
// first use.
//
// Sized to DPoPMaxAge alone the entry expired while the proof was still valid,
// so a captured proof presented a second time was recorded as fresh and passed.
// The 30 seconds on top absorb clock drift between the pod that writes the entry
// and the one that reads it.
const dpopReplayTTL = 2*vaultcrypto.DPoPMaxAge + 30*time.Second

// dpopReplayKey builds the cache key that holds a spent DPoP jti.
//
// The jti is hashed rather than concatenated. It arrives inside a self-signed
// proof, so it is the one cache key suffix in this service that an attacker
// chooses freely, at whatever length the 4 KB proof cap allows. Raw, it lands in
// a TEXT PRIMARY KEY on the Postgres backend, where a value past roughly 2704
// bytes exceeds the btree index limit: the replay check then errors instead of
// answering, and for a token that is not DPoP-bound that path logs and allows.
//
// Hashing also makes the key a fixed width regardless of input, so one caller
// cannot decide how much of the keyspace a single entry occupies.
func dpopReplayKey(jti string) string {
	return "dpop_jti:" + vaultcrypto.SHA256Hex(jti)
}
