package oauth2

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// idTokenAlgs is the allowlist for OIDC ID-token signatures. Asymmetric RSA only
// — this rejects "none" (unsigned) and HMAC algs (which would enable key-confusion
// against the public JWKS material).
//
// It narrows; it never widens. jwt.ParseWithClaims verifies only the algorithms
// its own signature switch implements, so RS384 and RS512 are accepted by this
// list and then rejected as unverifiable one layer down. Adding an entry here
// cannot make an algorithm verifiable that the verifier does not implement.
var idTokenAlgs = []string{"RS256", "RS384", "RS512"}

// maxIDTokenSize is the ceiling on an ID token, matching the 8 KB the access
// token verifier applies and the 4 KB the DPoP proof verifier applies.
//
// Without one, the only bound was the megabyte cap on the token-endpoint
// response body, so an issuer decided how much base64 got decoded and
// unmarshalled into a claims map, and how much unauthenticated material reached
// the key lookup that fetches discovery and the JWKS. 8 KB is several times any
// real ID token, including the large ones Entra issues with group claims.
const maxIDTokenSize = 8 * 1024

// maxAuthTimeSeconds is the ceiling on the auth_time an issuer may assert, at
// roughly the year 36800.
//
// The claim is a JSON number, so it reaches the claims map as a float64 and has
// to be converted to seconds. Converting a float64 that does not fit in an int64
// is implementation-defined in Go, so without a ceiling an issuer sending 1e300
// would be the one deciding which instant the profile records. Anything this far
// out is not a login time under any clock, so it is discarded the same way an
// absent claim is.
const maxAuthTimeSeconds = 1 << 40

// jwksCache holds the issuer's signing keys, indexed by kid.
type jwksCache struct {
	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

// VerifyIDToken validates an OIDC ID token's signature (against the issuer's
// JWKS) and its iss, aud, exp and nonce claims, returning the normalized
// profile. It rejects unsigned/HMAC tokens and embedded-key headers
// (jku/x5u/x5c/jwk).
//
// expectedNonce is the nonce minted for this login attempt and is mandatory.
// An empty value is rejected rather than read as "skip the nonce check": the
// nonce is the only claim binding the token to this browser's authorization
// request, so skipping it would reopen the ID-token / code-injection attack
// that RFC 9700 §4.5.3 requires the nonce to close. The obligation is
// discharged by the authorization-code flow in internal/handler/oauth.go,
// which mints the nonce at /authorize and round-trips it through the
// HMAC-signed state parameter.
//
// Every failure path returns a nil profile: there is no partial result a
// caller could mistake for a verified identity.
func (p *OIDCProvider) VerifyIDToken(ctx context.Context, idToken, expectedNonce string) (*UserInfo, error) {
	if idToken == "" {
		return nil, fmt.Errorf("oidc id_token: empty")
	}
	if len(idToken) > maxIDTokenSize {
		return nil, fmt.Errorf("oidc id_token: exceeds maximum size")
	}
	if expectedNonce == "" {
		return nil, fmt.Errorf("oidc id_token: no expected nonce for this login attempt")
	}
	claims := vjwt.MapClaims{}
	_, err := vjwt.ParseWithClaims(idToken, &claims, func(t *vjwt.Token) (any, error) {
		// Reject headers that point verification at attacker-controlled keys.
		for _, h := range []string{"jku", "x5u", "x5c", "jwk"} {
			if _, ok := t.Header[h]; ok {
				return nil, fmt.Errorf("oidc id_token: rejected header %q", h)
			}
		}
		// crit names JOSE extensions the recipient must implement to accept the
		// token (RFC 7515 4.1.11). vault42 implements none, so any crit at all,
		// including the empty array the RFC forbids outright, is a MUST-reject.
		// The verifier already refuses this class of header for its own access
		// tokens and DPoP proofs; the id_token path is the same rule for a token
		// an external issuer signs.
		if _, ok := t.Header["crit"]; ok {
			return nil, fmt.Errorf("oidc id_token: rejected crit header, no JOSE extensions are implemented")
		}
		kid, _ := t.Header["kid"].(string)
		key, err := p.signingKey(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	},
		vjwt.WithValidMethods(idTokenAlgs),
		vjwt.WithIssuer(p.issuer),
		vjwt.WithAudience(p.clientID),
		vjwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc id_token: %w", err)
	}

	// Nonce binds the token to this login attempt (replay/injection defense).
	// expectedNonce is guaranteed non-empty above, so an issuer that omits the
	// claim entirely compares "" against it and is rejected here.
	if n, _ := claims["nonce"].(string); n != expectedNonce {
		return nil, fmt.Errorf("oidc id_token: nonce mismatch")
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("oidc id_token: missing sub")
	}
	email, _ := claims["email"].(string)
	emailVerified, _ := claims["email_verified"].(bool)
	name, _ := claims["name"].(string)
	picture, _ := claims["picture"].(string)

	// auth_time is when the issuer authenticated the end user, and that is not
	// when this exchange ran. An issuer answering out of an established SSO
	// session mints the ID token minutes or hours after the authentication it
	// describes, so a caller left to date the login by its own clock reports a
	// session as freshly authenticated when nobody touched an authenticator --
	// which is precisely the freshness a relying party enforcing max_age reads
	// out of the claim.
	//
	// OIDC Core §2 makes auth_time OPTIONAL unless the request sent max_age or
	// asked for it as an essential claim, so an issuer that omits it is
	// conformant and must not be turned away. It leaves the zero instant, which
	// [UserInfo.AuthTime] defines as "not stated". A non-positive value is
	// discarded for the same reason rather than carried: the epoch is already
	// what "no authentication event recorded" looks like to the token service.
	var authTime time.Time
	if secs, ok := claims["auth_time"].(float64); ok && secs > 0 && secs <= maxAuthTimeSeconds {
		authTime = time.Unix(int64(secs), 0).UTC()
	}

	return &UserInfo{
		ID:            sub,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		AvatarURL:     picture,
		Provider:      p.name,
		AuthTime:      authTime,
	}, nil
}

// signingKey returns the issuer signing key for kid, fetching/refreshing the
// JWKS once if the kid is unknown (handles key rotation).
func (p *OIDCProvider) signingKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("oidc id_token: missing kid")
	}
	if k := p.cachedKey(kid); k != nil {
		return k, nil
	}
	if err := p.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	if k := p.cachedKey(kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("oidc id_token: no signing key for kid %q", kid)
}

func (p *OIDCProvider) cachedKey(kid string) *rsa.PublicKey {
	p.jwks.mu.RLock()
	defer p.jwks.mu.RUnlock()
	return p.jwks.keys[kid]
}

// refreshJWKS fetches the issuer's jwks_uri and replaces the cached RSA keys.
func (p *OIDCProvider) refreshJWKS(ctx context.Context) error {
	d, err := p.discover(ctx)
	if err != nil {
		return err
	}
	if d.JWKSURI == "" {
		return fmt.Errorf("oidc jwks: issuer exposes no jwks_uri")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.JWKSURI, nil)
	if err != nil {
		return fmt.Errorf("oidc jwks: build request: %w", err)
	}
	resp, err := p.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("oidc jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc jwks: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxProviderResponse)).Decode(&doc); err != nil {
		return fmt.Errorf("oidc jwks: decode: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k.N, k.E)
		if err != nil {
			continue // skip malformed keys rather than fail the whole set
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("oidc jwks: no usable RSA signing keys")
	}
	p.jwks.mu.Lock()
	p.jwks.keys = keys
	p.jwks.mu.Unlock()
	return nil
}

// rsaPublicKeyFromJWK decodes the base64url modulus/exponent of an RSA JWK,
// enforcing a 2048-bit minimum modulus.
func rsaPublicKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	if n.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key too small: %d bits", n.BitLen())
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
