package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// idTokenIssuer serves discovery + a JWKS containing pub (kid "k1").
func idTokenIssuer(t *testing.T, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	})
	t.Cleanup(srv.Close)
	return srv
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims vjwt.MapClaims) string {
	t.Helper()
	tok, err := vjwt.SignRS256WithHeader(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}, claims, key)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return tok
}

func baseClaims(iss, aud string) vjwt.MapClaims {
	return vjwt.MapClaims{
		"iss": iss, "aud": aud, "sub": "subject-1",
		"email": "user@corp.test", "email_verified": true, "name": "User",
		"nonce": "nonce-xyz",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
	}
}

func TestVerifyIDToken_Valid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := idTokenIssuer(t, &key.PublicKey)
	p := NewOIDCProvider("okta", srv.URL, "client-1", "secret", "https://app/cb", "")

	tok := signIDToken(t, key, "k1", baseClaims(srv.URL, "client-1"))
	info, err := p.VerifyIDToken(context.Background(), tok, "nonce-xyz")
	if err != nil {
		t.Fatalf("valid id token rejected: %v", err)
	}
	if info.ID != "subject-1" || info.Email != "user@corp.test" || !info.EmailVerified {
		t.Fatalf("unexpected claims: %+v", info)
	}
}

func TestVerifyIDToken_Rejections(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := idTokenIssuer(t, &key.PublicKey)
	p := NewOIDCProvider("okta", srv.URL, "client-1", "secret", "https://app/cb", "")
	ctx := context.Background()

	t.Run("alg=none is rejected", func(t *testing.T) {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1","typ":"JWT"}`))
		body, _ := json.Marshal(baseClaims(srv.URL, "client-1"))
		unsigned := hdr + "." + base64.RawURLEncoding.EncodeToString(body) + "."
		if _, err := p.VerifyIDToken(ctx, unsigned, "nonce-xyz"); err == nil {
			t.Fatal("alg=none token must be rejected")
		}
	})

	t.Run("signature by wrong key is rejected", func(t *testing.T) {
		tok := signIDToken(t, otherKey, "k1", baseClaims(srv.URL, "client-1"))
		if _, err := p.VerifyIDToken(ctx, tok, "nonce-xyz"); err == nil {
			t.Fatal("token signed by an unknown key must be rejected")
		}
	})

	t.Run("wrong audience is rejected", func(t *testing.T) {
		tok := signIDToken(t, key, "k1", baseClaims(srv.URL, "someone-else"))
		if _, err := p.VerifyIDToken(ctx, tok, "nonce-xyz"); err == nil {
			t.Fatal("token for a different audience must be rejected")
		}
	})

	t.Run("wrong issuer is rejected", func(t *testing.T) {
		tok := signIDToken(t, key, "k1", baseClaims("https://evil.example.com", "client-1"))
		if _, err := p.VerifyIDToken(ctx, tok, "nonce-xyz"); err == nil {
			t.Fatal("token from a different issuer must be rejected")
		}
	})

	t.Run("expired is rejected", func(t *testing.T) {
		c := baseClaims(srv.URL, "client-1")
		c["exp"] = time.Now().Add(-time.Hour).Unix()
		tok := signIDToken(t, key, "k1", c)
		if _, err := p.VerifyIDToken(ctx, tok, "nonce-xyz"); err == nil {
			t.Fatal("expired token must be rejected")
		}
	})

	t.Run("nonce mismatch is rejected", func(t *testing.T) {
		tok := signIDToken(t, key, "k1", baseClaims(srv.URL, "client-1"))
		if _, err := p.VerifyIDToken(ctx, tok, "different-nonce"); err == nil {
			t.Fatal("nonce mismatch must be rejected")
		}
	})

	// An absent expected nonce must fail the login, not silently skip the
	// binding check: a token that verifies without one is an injected token.
	t.Run("empty expected nonce is rejected", func(t *testing.T) {
		tok := signIDToken(t, key, "k1", baseClaims(srv.URL, "client-1"))
		if _, err := p.VerifyIDToken(ctx, tok, ""); err == nil {
			t.Fatal("an otherwise-valid token must be rejected when no nonce is expected")
		}
	})
}
