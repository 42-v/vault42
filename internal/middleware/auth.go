// Package middleware provides HTTP middleware for the Vault auth service,
// including JWT authentication, CORS, DPoP proof validation, device
// fingerprinting, rate limiting, request logging, security headers, and
// panic recovery.
package middleware

import (
	"context"
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

const (
	// ClaimsKey is the context key used to store authenticated VaultClaims.
	ClaimsKey ctxKey = "claims"
)

// AuthOption configures an authentication middleware constructor.
type AuthOption func(*authOptions)

type authOptions struct {
	acceptDPoPScheme bool
}

// WithDPoPScheme controls whether the "DPoP" HTTP authentication scheme
// (RFC 9449 §7.1) is accepted on the Authorization header. It is off by
// default, so only "Bearer" is accepted.
//
// RFC 9449 reserves the scheme for sender-constrained tokens. vault42 issues
// no such token: nothing populates the "cnf.jkt" confirmation claim, so a
// token presented under the DPoP scheme is bearer-equivalent, which is the
// confusion the separate scheme exists to prevent. Enable this only when
// VAULT_DPOP_ENABLED is set, and only while DPoP is understood to be
// experimental and unsupported.
func WithDPoPScheme(enabled bool) AuthOption {
	return func(o *authOptions) { o.acceptDPoPScheme = enabled }
}

func (o authOptions) schemeAllowed(scheme string) bool {
	return scheme == "Bearer" || (o.acceptDPoPScheme && scheme == "DPoP")
}

// Auth validates JWT bearer tokens from the Authorization header.
//
// Only the "Bearer" scheme is accepted unless WithDPoPScheme(true) is passed.
// Even then, this middleware validates the JWT alone and performs no
// proof-of-possession check, so a DPoP-scheme token is bearer-equivalent here.
// Sender-constraint enforcement lives in DPoP, which must be chained after
// this middleware, and which can only bind a token carrying "cnf.jkt", a claim
// vault42 does not currently issue.
func Auth(keys map[string]*rsa.PublicKey, issuer, audience string, opts ...AuthOption) func(http.Handler) http.Handler {
	return authWithTypes(func() map[string]*rsa.PublicKey { return keys }, issuer, audience, opts, "Bearer")
}

// AuthChallenge validates JWT tokens allowing both Bearer and 2fa_challenge types.
// Use this for 2FA verify endpoints that accept challenge tokens.
// See Auth for which authentication schemes are accepted.
func AuthChallenge(keys map[string]*rsa.PublicKey, issuer, audience string, opts ...AuthOption) func(http.Handler) http.Handler {
	return authWithTypes(func() map[string]*rsa.PublicKey { return keys }, issuer, audience, opts, "Bearer", "2fa_challenge")
}

// AuthDynamic validates JWT bearer tokens using a dynamic key provider.
// Used when keys are managed by a KeyStore that rotates keys at runtime.
// See Auth for which authentication schemes are accepted.
func AuthDynamic(keyProvider func() map[string]*rsa.PublicKey, issuer, audience string, opts ...AuthOption) func(http.Handler) http.Handler {
	return authWithTypes(keyProvider, issuer, audience, opts, "Bearer")
}

// AuthChallengeDynamic validates JWT tokens (Bearer + 2fa_challenge) using a dynamic key provider.
// See Auth for which authentication schemes are accepted.
func AuthChallengeDynamic(keyProvider func() map[string]*rsa.PublicKey, issuer, audience string, opts ...AuthOption) func(http.Handler) http.Handler {
	return authWithTypes(keyProvider, issuer, audience, opts, "Bearer", "2fa_challenge")
}

func authWithTypes(keyProvider func() map[string]*rsa.PublicKey, issuer, audience string, opts []AuthOption, allowedTypes ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedTypes))
	for _, t := range allowedTypes {
		allowed[t] = true
	}

	var o authOptions
	for _, opt := range opts {
		opt(&o)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httputil.WriteError(w, http.StatusUnauthorized, "missing_authorization")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !o.schemeAllowed(parts[0]) {
				httputil.WriteError(w, http.StatusUnauthorized, "invalid_authorization")
				return
			}

			tokenStr := parts[1]
			keys := keyProvider()

			claims, err := vaultcrypto.ParseAndValidate(tokenStr, func(t *vjwt.Token) (any, error) {
				kid, _ := t.Header["kid"].(string)
				key, ok := keys[kid]
				if !ok {
					return nil, vjwt.ErrTokenSignatureInvalid
				}
				return key, nil
			}, issuer, audience)
			if err != nil {
				httputil.WriteError(w, http.StatusUnauthorized, "invalid_token")
				return
			}

			// Reject tokens with types not in the allowed list
			tt := claims.TokenType
			if tt == "" {
				tt = "Bearer" // backward compat: empty = Bearer
			}
			if !allowed[tt] {
				httputil.WriteError(w, http.StatusUnauthorized, "invalid_token_type")
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims extracts VaultClaims from context.
func GetClaims(ctx context.Context) *vaultcrypto.VaultClaims {
	claims, _ := ctx.Value(ClaimsKey).(*vaultcrypto.VaultClaims)
	return claims
}

// RequireAuth is a handler wrapper that rejects unauthenticated requests.
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if GetClaims(r.Context()) == nil {
			httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	}
}

// RequireScope rejects authenticated requests whose token does not carry the
// given OAuth2 scope. It must be chained AFTER an Auth middleware so the
// validated claims are already in context. Used to gate the KMS unwrap oracle
// to client-credential tokens explicitly granted "kms:unwrap".
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			for _, s := range claims.Scopes {
				if s == scope {
					next.ServeHTTP(w, r)
					return
				}
			}
			httputil.WriteError(w, http.StatusForbidden, "insufficient_scope")
		})
	}
}

// Confirmed checks that the user recently confirmed their password via POST /auth/confirm.
// Returns 403 requires_confirmation if no recent confirmation exists.
func Confirmed(c cache.Cache) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			// Confirm key is per-user; the value is the JWT JTI of the access
			// token that performed the confirm. Reject if the JTI doesn't match
			// the current access token (M-3 binding) — prevents reusing the
			// confirm window across token refreshes.
			val, err := c.Get(r.Context(), "confirm:"+claims.Subject)
			if err != nil || val == "" || val != claims.ID {
				httputil.WriteError(w, http.StatusForbidden, "requires_confirmation")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
