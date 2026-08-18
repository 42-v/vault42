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

	"github.com/42-v/vault42/internal/audit"
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
				// RFC 6750 §3: a request that carries no bearer credential gets
				// a bare challenge. An error code here would describe a
				// credential the client never sent.
				httputil.WriteBearerError(w, http.StatusUnauthorized, "missing_authorization", httputil.BearerChallenge{})
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !o.schemeAllowed(parts[0]) {
				// Also a bare challenge: an unsupported scheme, or a header with
				// no credential after it, is "the client attempted using an
				// unsupported authentication method" (§3), not a bad token.
				httputil.WriteBearerError(w, http.StatusUnauthorized, "invalid_authorization", httputil.BearerChallenge{})
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
				httputil.WriteBearerError(w, http.StatusUnauthorized, "invalid_token", httputil.BearerChallenge{
					Error:       httputil.BearerErrInvalidToken,
					Description: "the access token is expired, malformed, or signed by an unknown key",
				})
				return
			}

			// Reject tokens with types not in the allowed list
			tt := claims.TokenType
			if tt == "" {
				tt = "Bearer" // backward compat: empty = Bearer
			}
			if !allowed[tt] {
				// §3.1 has no code for "right signature, wrong purpose", and
				// invalid_token is the one that fits: the credential presented
				// is not usable at this resource.
				httputil.WriteBearerError(w, http.StatusUnauthorized, "invalid_token_type", httputil.BearerChallenge{
					Error:       httputil.BearerErrInvalidToken,
					Description: "the token type is not accepted at this resource",
				})
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
			httputil.WriteBearerError(w, http.StatusUnauthorized, "unauthorized", httputil.BearerChallenge{})
			return
		}
		next.ServeHTTP(w, r)
	}
}

// ScopeOption configures RequireScope.
type ScopeOption func(*scopeOptions)

type scopeOptions struct {
	auditLog   *audit.Logger
	auditEvent string
}

// WithScopeRefusalAudit makes RequireScope record every request it refuses.
//
// A refusal here happens before the handler, so nothing downstream can write
// the event: the pre-handler segment of the chain was the one place a
// credential probe left no trace at all. POST /mint is the case that matters.
// Its handler documents that "a client probing for roles it cannot mint is the
// early signal that the credential has been taken", and docs/api.md states that
// every path, accepted and refused, writes one token_minted event — neither of
// which was true of the refusals that never reached the handler. A stolen
// non-mint client token could be fired at the delegated-signing endpoint
// indefinitely and produce nothing.
//
// It is an option rather than a required argument because RequireScope is a
// general gate and most resources behind it are not signing oracles; the
// decision is enforced identically with or without it.
func WithScopeRefusalAudit(logger *audit.Logger, eventType string) ScopeOption {
	return func(o *scopeOptions) {
		o.auditLog = logger
		o.auditEvent = eventType
	}
}

// RequireScope rejects authenticated requests whose token does not carry the
// given OAuth2 scope. It must be chained AFTER an Auth middleware so the
// validated claims are already in context. Used to gate the KMS unwrap oracle
// to client-credential tokens explicitly granted "kms:unwrap".
func RequireScope(scope string, opts ...ScopeOption) func(http.Handler) http.Handler {
	var o scopeOptions
	for _, opt := range opts {
		opt(&o)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				httputil.WriteBearerError(w, http.StatusUnauthorized, "unauthorized", httputil.BearerChallenge{})
				return
			}
			for _, s := range claims.Scopes {
				if s == scope {
					next.ServeHTTP(w, r)
					return
				}
			}
			o.recordRefusal(r, claims, scope)
			// RFC 6750 §3: insufficient_scope carries the scope the resource
			// requires, so the client can ask for exactly it instead of
			// guessing or re-authorizing for everything.
			httputil.WriteBearerError(w, http.StatusForbidden, "insufficient_scope", httputil.BearerChallenge{
				Error:       httputil.BearerErrInsufficientScope,
				Description: "the access token does not carry the scope this resource requires",
				Scope:       scope,
			})
		})
	}
}

// recordRefusal writes the audit event for a scope refusal, when one was
// configured.
//
// context.WithoutCancel is load-bearing, not tidiness. The client being refused
// chooses when to hang up and can do it the instant the server starts handling
// the request, so a write riding the request context would let a prober delete
// their own record by closing the connection. The admin plane's refusal audits
// established this pattern for the same reason.
//
// The error is discarded deliberately: the refusal has already been decided and
// an audit store that is down must not turn a 403 into a 500.
func (o scopeOptions) recordRefusal(r *http.Request, claims *vaultcrypto.VaultClaims, scope string) {
	if o.auditLog == nil {
		return
	}
	// #nosec G104 -- audit is best-effort and must never change the decision
	o.auditLog.Log(context.WithoutCancel(r.Context()), o.auditEvent, claims.Subject, claims.ClientID,
		ClientIP(r), r.Header.Get("User-Agent"), "", "", map[string]interface{}{
			"success": false,
			"reason":  "insufficient_scope",
			"scope":   scope,
			"method":  r.Method,
			"path":    r.URL.Path,
		})
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
