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

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// idTokenAlgs is the allowlist for OIDC ID-token signatures. Asymmetric RSA only
// — this rejects "none" (unsigned) and HMAC algs (which would enable key-confusion
// against the public JWKS material).
var idTokenAlgs = []string{"RS256", "RS384", "RS512"}

// jwksCache holds the issuer's signing keys, indexed by kid.
type jwksCache struct {
	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

// VerifyIDToken validates an OIDC ID token's signature (against the issuer's
// JWKS) and claims (iss, aud, exp, and nonce), returning the normalized profile.
// It rejects unsigned/HMAC tokens and embedded-key headers (jku/x5u/x5c/jwk).
func (p *OIDCProvider) VerifyIDToken(ctx context.Context, idToken, expectedNonce string) (*UserInfo, error) {
	if idToken == "" {
		return nil, fmt.Errorf("oidc id_token: empty")
	}
	claims := vjwt.MapClaims{}
	_, err := vjwt.ParseWithClaims(idToken, &claims, func(t *vjwt.Token) (any, error) {
		// Reject headers that point verification at attacker-controlled keys.
		for _, h := range []string{"jku", "x5u", "x5c", "jwk"} {
			if _, ok := t.Header[h]; ok {
				return nil, fmt.Errorf("oidc id_token: rejected header %q", h)
			}
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
	if expectedNonce != "" {
		if n, _ := claims["nonce"].(string); n != expectedNonce {
			return nil, fmt.Errorf("oidc id_token: nonce mismatch")
		}
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("oidc id_token: missing sub")
	}
	email, _ := claims["email"].(string)
	emailVerified, _ := claims["email_verified"].(bool)
	name, _ := claims["name"].(string)
	picture, _ := claims["picture"].(string)
	return &UserInfo{
		ID:            sub,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		AvatarURL:     picture,
		Provider:      p.name,
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
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
