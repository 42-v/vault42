package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// An issuer identifier may end in a slash, and some published ones do. OIDC
// Core 3.1.3.7 step 2 requires the id_token's iss to match the issuer
// identifier exactly, so a provider whose identifier carries a trailing slash
// puts that slash in every token it mints.
//
// NewOIDCProvider trims it. That is right for discover, which compares two
// spellings of one identifier and trims both sides -- so discovery passes. It
// was wrong for verification, which is a byte-for-byte comparison in
// internal/jwt with no normalization: every id_token failed
// ErrTokenInvalidIssuer, on every attempt, for a provider that was otherwise
// working. From the outside that is indistinguishable from a provider outage,
// and no configuration escapes it, because TrimRight strips whatever the
// operator writes.
//
// No issuer used anywhere else in this package's tests ends in a slash -- most
// are a bare httptest URL and the five written as literals were all chosen
// without one -- which is why nothing caught it.
func TestVerifyIDToken_AcceptsAnIssuerIdentifierEndingInASlash(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n, e := rsaJWKParts(&key.PublicKey)

	// The issuer publishes itself with a trailing slash, in the discovery
	// document and in the token, consistently -- which is what a real one does.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuerID := srv.URL + "/"

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuerID,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwksBody(jwkEntry{Kty: "RSA", Kid: "k1", N: n, E: e, Use: "sig"}))
	})

	// Configured without the slash, which is the likelier thing an operator
	// types and is also what TrimRight would produce either way.
	p := NewOIDCProvider("generic", srv.URL, "cid", "secret", "https://app/cb", "")

	ctx := context.Background()
	if _, err := p.discover(ctx); err != nil {
		t.Fatalf("discovery must still pass -- it compares trimmed: %v", err)
	}

	now := time.Now()
	signed, err := vjwt.SignRS256(vjwt.MapClaims{
		"iss":            issuerID,
		"aud":            "cid",
		"sub":            "user-1",
		"exp":            now.Add(5 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"nonce":          "the-nonce",
		"email":          "alice@example.com",
		"email_verified": true,
	}, key, "k1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	info, err := p.VerifyIDToken(ctx, signed, "the-nonce")
	if err != nil {
		t.Fatalf("an id_token whose iss matches the published issuer identifier was "+
			"rejected: %v. The provider is working; only the trim is not.", err)
	}
	if info.ID != "user-1" {
		t.Fatalf("subject = %q", info.ID)
	}
}

// The fix must not become "accept any issuer". A token from a different issuer
// is still refused, and so is one whose iss differs from the published
// identifier only by that slash in the other direction.
func TestVerifyIDToken_StillRefusesTheWrongIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n, e := rsaJWKParts(&key.PublicKey)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuerID := srv.URL + "/"

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuerID,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwksBody(jwkEntry{Kty: "RSA", Kid: "k1", N: n, E: e, Use: "sig"}))
	})

	p := NewOIDCProvider("generic", srv.URL, "cid", "secret", "https://app/cb", "")
	ctx := context.Background()
	if _, err := p.discover(ctx); err != nil {
		t.Fatalf("discover: %v", err)
	}

	now := time.Now()
	for _, bad := range []string{
		"https://evil.test/",
		srv.URL, // the published identifier minus its slash: still not an exact match
	} {
		signed, err := vjwt.SignRS256(vjwt.MapClaims{
			"iss": bad, "aud": "cid", "sub": "user-1", "nonce": "the-nonce",
			"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		}, key, "k1")
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := p.VerifyIDToken(ctx, signed, "the-nonce"); err == nil {
			t.Errorf("an id_token claiming iss=%q was accepted against published issuer %q", bad, issuerID)
		}
	}
}

// The same provider, verified without anyone having called discover first.
//
// This is the arm that was latent. WithIssuer takes its value as an argument, so
// expectedIDTokenIssuer is evaluated before ParseWithClaims runs the keyfunc,
// and the keyfunc is the only thing that used to trigger discovery. A caller
// reaching VerifyIDToken cold therefore compared against the trimmed configured
// issuer and rejected a perfectly good token. It never bit in production only
// because the single live caller runs Exchange first, which is correctness by
// call order rather than by the function.
func TestVerifyIDToken_DiscoversBeforeChoosingTheIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n, e := rsaJWKParts(&key.PublicKey)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuerID := srv.URL + "/"

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuerID,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwksBody(jwkEntry{Kty: "RSA", Kid: "k1", N: n, E: e, Use: "sig"}))
	})

	p := NewOIDCProvider("generic", srv.URL, "cid", "secret", "https://app/cb", "")

	now := time.Now()
	signed, err := vjwt.SignRS256(vjwt.MapClaims{
		"iss": issuerID, "aud": "cid", "sub": "user-1", "nonce": "the-nonce",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
	}, key, "k1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// No p.discover(ctx) here, deliberately.
	info, err := p.VerifyIDToken(context.Background(), signed, "the-nonce")
	if err != nil {
		t.Fatalf("a cold VerifyIDToken rejected a good token: %v. The issuer is chosen "+
			"before the keyfunc runs, so discovery has to happen earlier than the "+
			"signature check, not merely before it completes.", err)
	}
	if info.ID != "user-1" {
		t.Fatalf("subject = %q", info.ID)
	}
}

// Before discovery has run there is no published value, so the configured one
// is the only thing to compare against. This is the fallback arm.
func TestExpectedIDTokenIssuer_FallsBackToTheConfiguredValue(t *testing.T) {
	p := NewOIDCProvider("generic", "https://issuer.test/", "cid", "secret", "https://app/cb", "")
	if got := p.expectedIDTokenIssuer(); got != "https://issuer.test" {
		t.Fatalf("before discovery the configured (trimmed) issuer is all there is, got %q", got)
	}
}
