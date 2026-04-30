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

// Auth validates JWT Bearer tokens from the Authorization header.
func Auth(keys map[string]*rsa.PublicKey, issuer, audience string) func(http.Handler) http.Handler {
	return authWithTypes(func() map[string]*rsa.PublicKey { return keys }, issuer, audience, "Bearer")
}

// AuthChallenge validates JWT tokens allowing both Bearer and 2fa_challenge types.
// Use this for 2FA verify endpoints that accept challenge tokens.
func AuthChallenge(keys map[string]*rsa.PublicKey, issuer, audience string) func(http.Handler) http.Handler {
	return authWithTypes(func() map[string]*rsa.PublicKey { return keys }, issuer, audience, "Bearer", "2fa_challenge")
}

// AuthDynamic validates JWT Bearer tokens using a dynamic key provider.
// Used when keys are managed by a KeyStore that rotates keys at runtime.
func AuthDynamic(keyProvider func() map[string]*rsa.PublicKey, issuer, audience string) func(http.Handler) http.Handler {
	return authWithTypes(keyProvider, issuer, audience, "Bearer")
}

// AuthChallengeDynamic validates JWT tokens (Bearer + 2fa_challenge) using a dynamic key provider.
func AuthChallengeDynamic(keyProvider func() map[string]*rsa.PublicKey, issuer, audience string) func(http.Handler) http.Handler {
	return authWithTypes(keyProvider, issuer, audience, "Bearer", "2fa_challenge")
}

func authWithTypes(keyProvider func() map[string]*rsa.PublicKey, issuer, audience string, allowedTypes ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedTypes))
	for _, t := range allowedTypes {
		allowed[t] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httputil.WriteError(w, http.StatusUnauthorized, "missing_authorization")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || (parts[0] != "Bearer" && parts[0] != "DPoP") {
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
