package service

import (
	"context"
	"crypto/rsa"
	"fmt"
	"math/big"
	"sync"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/dpop"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TokenService handles JWT issuance and refresh token generation.
type TokenService struct {
	mu              sync.RWMutex
	privateKey      *rsa.PrivateKey
	kid             string
	issuer          string
	audience        string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	rememberMeTTL   time.Duration
	// maxSessionLifetime bounds how long a single refresh-token family may live,
	// measured from the instant the family was created and independent of how
	// often it is refreshed. Zero disables the bound.
	maxSessionLifetime time.Duration
	// inactivityTimeout bounds how long a refresh-token family may go unused
	// before it must reauthenticate, measured from the instant the family last
	// rotated. Zero disables the bound.
	inactivityTimeout time.Duration
}

// AuthContext carries the OIDC Core §2 authentication-event claims onto an
// issued access token: which assurance level the login reached (acr), which
// authenticators it presented (amr), and when it happened (auth_time).
//
// A zero value emits none of them, which is what an issuance that observed no
// authentication event — a client-credentials token — should say.
type AuthContext struct {
	ACR      string
	AMR      []string
	AuthTime time.Time
}

// NewAuthContext derives the authentication-event claims from the factors a
// login completed with. userVerified is the WebAuthn UV flag; it is false for
// every other authenticator.
func NewAuthContext(at time.Time, methods []string, userVerified bool) AuthContext {
	return AuthContext{
		ACR:      ACRForAAL(AALForMethods(methods, userVerified)),
		AMR:      AMRForMethods(methods, userVerified),
		AuthTime: at,
	}
}

// authTimeSeconds renders the authentication instant for the auth_time claim.
// A zero instant means "not recorded" and emits nothing, because the alternative
// is a token asserting the user authenticated at the Unix epoch.
func authTimeSeconds(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// TokenPair is an access+refresh token pair.
type TokenPair struct {
	AccessToken  string // #nosec G117 -- internal DTO, never serialized to JSON
	RefreshToken string // #nosec G117 -- raw token (to be hashed before storage)
	ExpiresAt    time.Time
	RefreshExpAt time.Time
	FamilyID     string
}

// NewTokenService creates a new token service.
func NewTokenService(key *rsa.PrivateKey, kid, issuer, audience string, accessTTL, refreshTTL, rememberTTL time.Duration) *TokenService {
	return &TokenService{
		privateKey:      key,
		kid:             kid,
		issuer:          issuer,
		audience:        audience,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
		rememberMeTTL:   rememberTTL,
	}
}

// SetMaxSessionLifetime sets the absolute bound on the age of a refresh-token
// family. Rotation refuses to extend a family past creation+d, and issuance
// clamps the refresh expiry to it, so the bound holds regardless of how often the
// client refreshes (NIST SP 800-63B-4 §2.2.3). Zero disables the bound.
//
// Call once at wiring time, before the service starts issuing.
func (s *TokenService) SetMaxSessionLifetime(d time.Duration) {
	s.mu.Lock()
	s.maxSessionLifetime = d
	s.mu.Unlock()
}

// MaxSessionLifetime returns the configured absolute session lifetime, or zero
// when no bound is set.
func (s *TokenService) MaxSessionLifetime() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxSessionLifetime
}

// SetInactivityTimeout sets the bound on how long a refresh-token family may go
// unused. Issuance clamps every refresh expiry to now+d, so a family that is not
// rotated inside the window expires on its own rather than waiting for the full
// refresh TTL (NIST SP 800-63B-4 §2.2.3). Zero disables the bound.
//
// This is the clamp only. AuthService.enforceSessionInactivity is what
// TERMINATES the family, and it is the control: the clamp cannot revoke, cannot
// audit, and cannot act on a row whose expiry was written before the bound was
// configured. Setting this without the check would leave every pre-existing
// session unbounded.
//
// Call once at wiring time, before the service starts issuing.
func (s *TokenService) SetInactivityTimeout(d time.Duration) {
	s.mu.Lock()
	s.inactivityTimeout = d
	s.mu.Unlock()
}

// InactivityTimeout returns the configured inactivity bound, or zero when no
// bound is set.
func (s *TokenService) InactivityTimeout() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inactivityTimeout
}

// sessionDeadline is the instant a family created at origin must end, or the zero
// time when no bound applies. A zero origin is "unknown", never "epoch": returning
// a deadline from it would silently expire every session.
func sessionDeadline(origin time.Time, maxLifetime time.Duration) time.Time {
	if maxLifetime <= 0 || origin.IsZero() {
		return time.Time{}
	}
	return origin.Add(maxLifetime)
}

// clampExpiry pulls exp back to deadline when the deadline is set and earlier.
//
// SECURITY INVARIANT: this only ever moves an expiry EARLIER. Every bound on a
// refresh token is applied by composing calls to it, so the effective expiry is
// the minimum of all of them and adding a bound can never extend one. The
// absolute session lifetime therefore stays the outer limit no matter what else
// is configured.
func clampExpiry(exp, deadline time.Time) time.Time {
	if !deadline.IsZero() && deadline.Before(exp) {
		return deadline
	}
	return exp
}

// IssueTokenPair creates a new access+refresh token pair.
//
// An empty familyID starts a new family, so its origin is now and the refresh
// expiry is clamped to the absolute session lifetime here. A non-empty familyID
// is a rotation whose origin this function cannot know; rotations must go through
// IssueRotatedPair, which supplies it.
//
// ctx is the REQUEST context, and it is read for exactly one thing: the
// thumbprint of a DPoP proof the middleware already validated. When one is
// present the access token carries cnf.jkt (RFC 9449 §6.1) and is
// sender-constrained; when it is absent the token is an ordinary bearer token,
// which every non-DPoP client depends on. This is the binding that did not exist:
// with cnf.jkt assigned nowhere, the middleware's thumbprint comparison never ran
// and a proof was checked against nothing.
func (s *TokenService) IssueTokenPair(ctx context.Context, userID string, roles, scopes []string, clientID, fingerprint, familyID string, rememberMe bool) (*TokenPair, error) {
	return s.IssueTokenPairWithAuth(ctx, userID, roles, scopes, clientID, fingerprint, familyID, rememberMe, AuthContext{})
}

// IssueTokenPairWithAuth is IssueTokenPair with the OIDC authentication-event
// claims attached. Call it from a path that just authenticated a user; the
// bare IssueTokenPair is for issuance that observed no such event.
//
// The two bindings are independent and both ride on this call: ctx sender-
// constrains the token to a DPoP key, auth describes the authentication event
// that produced it.
func (s *TokenService) IssueTokenPairWithAuth(ctx context.Context, userID string, roles, scopes []string, clientID, fingerprint, familyID string, rememberMe bool, auth AuthContext) (*TokenPair, error) {
	now := time.Now()
	jti, err := vaultcrypto.RandomUUID()
	if err != nil {
		return nil, fmt.Errorf("generate JTI: %w", err)
	}

	newFamily := familyID == ""

	accessClaims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    s.issuer,
			Audience:  vjwt.ClaimStrings{s.audience},
			Subject:   userID,
			ExpiresAt: vjwt.NewNumericDate(now.Add(s.accessTokenTTL)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        jti,
		},
		Roles:       roles,
		Scopes:      scopes,
		ClientID:    clientID,
		Fingerprint: fingerprint,
		TokenType:   "Bearer",
		ACR:         auth.ACR,
		AMR:         auth.AMR,
		AuthTime:    authTimeSeconds(auth.AuthTime),
	}
	if jkt := dpop.Thumbprint(ctx); jkt != "" {
		accessClaims.Confirmation = &vaultcrypto.Confirmation{JKT: jkt}
	}

	// Signing stays inside the read lock: UpdateSigningKey wipes the key it
	// rotates out, and that is only safe if no signer can still be holding it.
	s.mu.RLock()
	accessToken, err := vaultcrypto.SignToken(accessClaims, s.privateKey, s.kid)
	maxLifetime := s.maxSessionLifetime
	idleTimeout := s.inactivityTimeout
	s.mu.RUnlock()
	if err != nil {
		return nil, err
	}

	refreshToken, err := vaultcrypto.RandomToken(32)
	if err != nil {
		return nil, err
	}

	refreshTTL := s.refreshTokenTTL
	if rememberMe {
		refreshTTL = s.rememberMeTTL
	}

	if newFamily {
		familyID, err = vaultcrypto.RandomUUID()
		if err != nil {
			return nil, fmt.Errorf("generate family ID: %w", err)
		}
	}

	refreshExpAt := now.Add(refreshTTL)
	if newFamily {
		refreshExpAt = clampExpiry(refreshExpAt, sessionDeadline(now, maxLifetime))
	}
	// The inactivity clamp applies to a rotation as well as to a new family,
	// because it is measured from THIS issuance rather than from the family's
	// origin: whichever token the client is holding, it stops being accepted one
	// idle window after it was minted.
	//
	// Without it the stored expires_at, and the cookie max-age derived from it,
	// would go on claiming the full refresh TTL for a token the refresh path will
	// refuse an hour from now. The row would also stay non-expired in
	// countActiveFamilies, so a user's concurrent-session cap would be held by
	// sessions that can never be rotated again.
	refreshExpAt = clampExpiry(refreshExpAt, sessionDeadline(now, idleTimeout))

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    now.Add(s.accessTokenTTL),
		RefreshExpAt: refreshExpAt,
		FamilyID:     familyID,
	}, nil
}

// IssueRotatedPair issues the next pair in an existing family and clamps its
// refresh expiry to the family's absolute deadline, and to the inactivity
// window if one is configured.
//
// SECURITY INVARIANT: the returned refresh token can never outlive
// familyOrigin+maxSessionLifetime. The caller also rejects an already-expired
// family outright; this clamp is what makes the final rotation before the
// deadline honest, so the stored expires_at (checked on the next refresh) and the
// cookie max-age both end at the bound instead of a fresh full TTL past it.
//
// A zero familyOrigin means the age is unknown and no clamp is applied — callers
// must reject rather than rotate in that case.
//
// ctx sender-constrains the rotated access token exactly as it does a fresh one:
// a refresh presented with a DPoP proof yields a token bound to that same key.
func (s *TokenService) IssueRotatedPair(ctx context.Context, userID string, roles, scopes []string, clientID, fingerprint, familyID string, familyOrigin time.Time) (*TokenPair, error) {
	// A rotation cannot re-run the authentication, so it carries auth_time from
	// the family origin — which is the instant the user authenticated — and
	// omits acr and amr rather than restating factors it did not observe.
	pair, err := s.IssueTokenPairWithAuth(ctx, userID, roles, scopes, clientID, fingerprint, familyID, false,
		AuthContext{AuthTime: familyOrigin})
	if err != nil {
		return nil, err
	}
	// IssueTokenPairWithAuth has already applied the inactivity clamp, which is
	// measured from now. This one is measured from the family origin, which only
	// this function knows, and it is applied second so the absolute bound stays
	// the outer limit: clampExpiry never moves an expiry later, so composing the
	// two yields the earlier of the two deadlines.
	pair.RefreshExpAt = clampExpiry(pair.RefreshExpAt, sessionDeadline(familyOrigin, s.MaxSessionLifetime()))
	return pair, nil
}

// IssueChallengeToken creates a short-lived JWT for 2FA challenge.
//
// It is bound to a presented DPoP key for the same reason the access token is:
// the challenge token is what POST /auth/2fa/verify authenticates, so leaving it
// bearer-equivalent would put an unconstrained credential in the middle of an
// otherwise sender-constrained login.
//
// factors are the authenticator methods already completed when the challenge
// was minted; they travel on the challenge so the second-factor verify can
// state the full combination.
func (s *TokenService) IssueChallengeToken(ctx context.Context, userID, fingerprint string, factors ...string) (string, error) {
	now := time.Now()
	jti, err := vaultcrypto.RandomUUID()
	if err != nil {
		return "", fmt.Errorf("generate challenge JTI: %w", err)
	}

	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    s.issuer,
			Audience:  vjwt.ClaimStrings{s.audience},
			Subject:   userID,
			ExpiresAt: vjwt.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        jti,
		},
		Fingerprint: fingerprint,
		TokenType:   "2fa_challenge",
		Factors:     factors,
	}
	if jkt := dpop.Thumbprint(ctx); jkt != "" {
		claims.Confirmation = &vaultcrypto.Confirmation{JKT: jkt}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return vaultcrypto.SignToken(claims, s.privateKey, s.kid)
}

// AccessTokenTTL returns the configured access token TTL.
func (s *TokenService) AccessTokenTTL() time.Duration {
	return s.accessTokenTTL
}

// UpdateSigningKey updates the signing key and kid for key rotation, and clears
// the exported private components of the key it replaces.
//
// The wipe is far narrower than it looks; zeroPrivateKey documents why the
// retired key stays usable afterwards. It runs anyway, because clearing the
// fields that are reachable beats leaving them set, and because it becomes a
// real control again the day the standard library stops caching the key
// internally.
//
// Signers hold the read lock for the whole of SignToken. That is deliberate
// ordering hygiene rather than a consequence of the wipe: it stops a rotation
// publishing a new kid while a signature is still being produced under the old
// one, which is what would otherwise let a token carry a kid its signature does
// not match. It is not load-bearing for memory safety, because signing does not
// read the words the wipe overwrites.
func (s *TokenService) UpdateSigningKey(key *rsa.PrivateKey, kid string) {
	s.mu.Lock()
	old := s.privateKey
	s.privateKey = key
	s.kid = kid
	s.mu.Unlock()

	if old != key {
		zeroPrivateKey(old)
	}
}

// zeroPrivateKey overwrites the secret components of an RSA private key that is
// being discarded. The public modulus and exponent are left alone; they are not
// secret and a JWKS may still publish them for the tokens the key already signed.
//
// This is best-effort in the same sense as config.ZeroBytes: it clears the words
// currently backing each value, but the Go runtime may already have copied them
// during earlier big.Int arithmetic, and those copies are unreachable (see AR-4).
//
// It is weaker still than that caveat suggests, and the weakness is worth stating
// plainly because the function name promises more than it delivers. Since Go 1.24
// crypto/rsa derives an unexported representation of the key on first use and
// signs from it, so the fields cleared here are copies the signing path no longer
// consults. A key that has been through this function still produces valid
// signatures, byte for byte identical to the ones it produced before, and its
// secret components remain resident where no Go program can reach them.
// TestZeroPrivateKeyLeavesTheKeyUsable asserts exactly that, so the limit is
// recorded as executable fact rather than as a comment that can quietly rot.
// Recorded as an accepted risk in docs/security.md; it cannot be fixed from
// outside the standard library.
func zeroPrivateKey(key *rsa.PrivateKey) {
	if key == nil {
		return
	}
	zeroBigInt(key.D)
	for _, p := range key.Primes {
		zeroBigInt(p)
	}
	zeroBigInt(key.Precomputed.Dp)
	zeroBigInt(key.Precomputed.Dq)
	zeroBigInt(key.Precomputed.Qinv)
}

// zeroBigInt overwrites the words backing v and then resets it to zero.
func zeroBigInt(v *big.Int) {
	if v == nil {
		return
	}
	words := v.Bits()
	for i := range words {
		words[i] = 0
	}
	v.SetInt64(0)
}
