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

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// jwksJSON renders a JWKS document body for the given JWK entries.
type jwkEntry struct {
	Kty, Kid, N, E, Use string
}

func jwksBody(entries ...jwkEntry) []byte {
	keys := make([]map[string]string, 0, len(entries))
	for _, e := range entries {
		k := map[string]string{"kty": e.Kty, "kid": e.Kid, "n": e.N, "e": e.E}
		if e.Use != "" {
			k["use"] = e.Use
		}
		keys = append(keys, k)
	}
	b, _ := json.Marshal(map[string]any{"keys": keys})
	return b
}

func rsaJWKParts(pub *rsa.PublicKey) (n, e string) {
	return base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
}

// configurableIssuer serves discovery whose jwks_uri/userinfo point at handlers
// the test controls, so JWKS/UserInfo error paths can be exercised deterministically.
func configurableIssuer(t *testing.T, jwks http.HandlerFunc, userinfo http.HandlerFunc, omitJWKS, omitUserinfo bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
		}
		if !omitJWKS {
			doc["jwks_uri"] = srv.URL + "/jwks"
		}
		if !omitUserinfo {
			doc["userinfo_endpoint"] = srv.URL + "/userinfo"
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	if jwks != nil {
		mux.HandleFunc("/jwks", jwks)
	}
	if userinfo != nil {
		mux.HandleFunc("/userinfo", userinfo)
	}
	t.Cleanup(srv.Close)
	return srv
}

// --- rsaPublicKeyFromJWK: decode + validation branches ---

func TestRSAPublicKeyFromJWK_Branches(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	goodN, goodE := rsaJWKParts(&key.PublicKey)

	t.Run("valid 2048-bit key", func(t *testing.T) {
		pub, err := rsaPublicKeyFromJWK(goodN, goodE)
		if err != nil {
			t.Fatalf("valid JWK rejected: %v", err)
		}
		if pub.N.Cmp(key.PublicKey.N) != 0 || pub.E != key.PublicKey.E {
			t.Fatalf("decoded key mismatch: got N/E %v/%d", pub.N, pub.E)
		}
	})

	t.Run("non-base64url modulus is rejected", func(t *testing.T) {
		if _, err := rsaPublicKeyFromJWK("not base64!!", goodE); err == nil {
			t.Fatal("malformed modulus must error")
		}
	})

	t.Run("non-base64url exponent is rejected", func(t *testing.T) {
		if _, err := rsaPublicKeyFromJWK(goodN, "not base64!!"); err == nil {
			t.Fatal("malformed exponent must error")
		}
	})

	t.Run("sub-2048-bit modulus is rejected", func(t *testing.T) {
		small, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		sN, sE := rsaJWKParts(&small.PublicKey)
		if _, err := rsaPublicKeyFromJWK(sN, sE); err == nil {
			t.Fatal("a 1024-bit key must be rejected by the 2048-bit floor")
		}
	})

	t.Run("exponent below 3 is rejected", func(t *testing.T) {
		badE := base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes())
		if _, err := rsaPublicKeyFromJWK(goodN, badE); err == nil {
			t.Fatal("exponent < 3 must be rejected")
		}
	})

	t.Run("oversized exponent is rejected", func(t *testing.T) {
		// 5 bytes -> exceeds the 2^31-1 ceiling.
		big5 := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x00, 0x00, 0x00})
		if _, err := rsaPublicKeyFromJWK(goodN, big5); err == nil {
			t.Fatal("exponent above 2^31-1 must be rejected")
		}
	})
}

// --- refreshJWKS / signingKey error and rotation paths ---

func TestRefreshJWKS_DiscoverFailure(t *testing.T) {
	// Issuer that 404s discovery: discover() inside refreshJWKS fails.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux) // no handlers registered -> 404
	t.Cleanup(srv.Close)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if err := p.refreshJWKS(context.Background()); err == nil {
		t.Fatal("refreshJWKS must fail when discovery fails")
	}
}

func TestRefreshJWKS_NoJWKSURI(t *testing.T) {
	srv := configurableIssuer(t, nil, nil, true, true)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if err := p.refreshJWKS(context.Background()); err == nil {
		t.Fatal("refreshJWKS must fail when issuer exposes no jwks_uri")
	}
}

func TestRefreshJWKS_FetchFailure(t *testing.T) {
	// Discovery advertises a jwks_uri, but the JWKS handler hijacks and closes
	// the connection so the GET errors at the transport layer.
	srv := configurableIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}, nil, false, true)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if err := p.refreshJWKS(context.Background()); err == nil {
		t.Fatal("refreshJWKS must fail when the JWKS fetch errors")
	}
}

func TestRefreshJWKS_Non200(t *testing.T) {
	srv := configurableIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}, nil, false, true)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if err := p.refreshJWKS(context.Background()); err == nil {
		t.Fatal("refreshJWKS must fail on a non-200 JWKS status")
	}
}

func TestRefreshJWKS_DecodeError(t *testing.T) {
	srv := configurableIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}, nil, false, true)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if err := p.refreshJWKS(context.Background()); err == nil {
		t.Fatal("refreshJWKS must fail when the JWKS body is not valid JSON")
	}
}

func TestRefreshJWKS_SkipsUnusableKeysButLoadsGood(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	goodN, goodE := rsaJWKParts(&key.PublicKey)
	srv := configurableIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwksBody(
			jwkEntry{Kty: "EC", Kid: "ec-1", N: goodN, E: goodE},                          // non-RSA -> skipped
			jwkEntry{Kty: "RSA", Kid: "enc-1", N: goodN, E: goodE, Use: "enc"},             // wrong use -> skipped
			jwkEntry{Kty: "RSA", Kid: "bad-1", N: "@@@bad@@@", E: goodE, Use: "sig"},       // malformed -> skipped
			jwkEntry{Kty: "RSA", Kid: "good-1", N: goodN, E: goodE, Use: "sig"},            // usable
		))
	}, nil, false, true)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")

	if err := p.refreshJWKS(context.Background()); err != nil {
		t.Fatalf("refreshJWKS must succeed when at least one usable key exists: %v", err)
	}
	if p.cachedKey("good-1") == nil {
		t.Fatal("the usable RSA sig key must be cached")
	}
	for _, kid := range []string{"ec-1", "enc-1", "bad-1"} {
		if p.cachedKey(kid) != nil {
			t.Fatalf("unusable key %q must not be cached", kid)
		}
	}
}

func TestRefreshJWKS_NoUsableKeys(t *testing.T) {
	goodN := base64.RawURLEncoding.EncodeToString(big.NewInt(0).Bytes())
	srv := configurableIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		// Only non-RSA / malformed entries -> map ends up empty.
		_, _ = w.Write(jwksBody(
			jwkEntry{Kty: "oct", Kid: "sym-1", N: goodN, E: "AQAB"},
			jwkEntry{Kty: "RSA", Kid: "", N: goodN, E: "AQAB"}, // empty kid -> skipped
		))
	}, nil, false, true)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if err := p.refreshJWKS(context.Background()); err == nil {
		t.Fatal("refreshJWKS must fail when no usable RSA signing keys remain")
	}
}

func TestSigningKey_MissingKid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := idTokenIssuer(t, &key.PublicKey)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if _, err := p.signingKey(context.Background(), ""); err == nil {
		t.Fatal("signingKey must reject an empty kid")
	}
}

func TestSigningKey_RefreshFailurePropagates(t *testing.T) {
	// Discovery 404s, so the refresh triggered by an uncached kid fails and the
	// error is returned rather than a nil key.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if _, err := p.signingKey(context.Background(), "k1"); err == nil {
		t.Fatal("signingKey must surface a refresh failure for an uncached kid")
	}
}

func TestSigningKey_UnknownKidAfterRefresh(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Issuer publishes kid "k1"; we ask for a kid that the refreshed set lacks.
	srv := idTokenIssuer(t, &key.PublicKey)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if _, err := p.signingKey(context.Background(), "unknown-kid"); err == nil {
		t.Fatal("signingKey must fail when the kid is absent even after a refresh")
	}
}

// --- VerifyIDToken: header/claim branches not exercised elsewhere ---

func TestVerifyIDToken_EmptyToken(t *testing.T) {
	p := NewOIDCProvider("okta", "https://iss.example", "cid", "secret", "https://app/cb", "")
	if _, err := p.VerifyIDToken(context.Background(), "", "nonce"); err == nil {
		t.Fatal("an empty id_token must be rejected without any network call")
	}
}

func TestVerifyIDToken_EmbeddedKeyHeaderRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := idTokenIssuer(t, &key.PublicKey)
	p := NewOIDCProvider("okta", srv.URL, "client-1", "secret", "https://app/cb", "")
	// A "jwk" header points verification at attacker-supplied key material.
	hdr := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1", "jwk": map[string]string{"kty": "RSA"}}
	tok, err := vjwt.SignRS256WithHeader(hdr, baseClaims(srv.URL, "client-1"), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := p.VerifyIDToken(context.Background(), tok, "nonce-xyz"); err == nil {
		t.Fatal("a token carrying an embedded-key header must be rejected")
	}
}

func TestVerifyIDToken_MissingSub(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := idTokenIssuer(t, &key.PublicKey)
	p := NewOIDCProvider("okta", srv.URL, "client-1", "secret", "https://app/cb", "")
	c := baseClaims(srv.URL, "client-1")
	delete(c, "sub")
	tok := signIDToken(t, key, "k1", c)
	if _, err := p.VerifyIDToken(context.Background(), tok, "nonce-xyz"); err == nil {
		t.Fatal("a token with no sub claim must be rejected")
	}
}

func TestVerifyIDToken_UnknownKidRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := idTokenIssuer(t, &key.PublicKey) // serves kid "k1"
	p := NewOIDCProvider("okta", srv.URL, "client-1", "secret", "https://app/cb", "")
	// Token references a kid the issuer's JWKS does not contain.
	tok := signIDToken(t, key, "rotated-out", baseClaims(srv.URL, "client-1"))
	if _, err := p.VerifyIDToken(context.Background(), tok, "nonce-xyz"); err == nil {
		t.Fatal("a token whose kid is absent from the JWKS must be rejected")
	}
}

// --- UserInfo error branches ---

func TestUserInfo_DiscoverFailure(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux) // discovery 404s
	t.Cleanup(srv.Close)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if _, err := p.UserInfo(context.Background(), "at-123"); err == nil {
		t.Fatal("UserInfo must fail when discovery fails")
	}
}

func TestUserInfo_NoUserInfoEndpoint(t *testing.T) {
	srv := configurableIssuer(t, nil, nil, false, true) // no userinfo_endpoint in discovery
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if _, err := p.UserInfo(context.Background(), "at-123"); err == nil {
		t.Fatal("UserInfo must fail when the issuer exposes no userinfo endpoint")
	}
}

func TestUserInfo_Non200(t *testing.T) {
	srv := configurableIssuer(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}, false, false)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if _, err := p.UserInfo(context.Background(), "at-123"); err == nil {
		t.Fatal("UserInfo must fail on a non-200 userinfo status")
	}
}

func TestUserInfo_FetchFailure(t *testing.T) {
	srv := configurableIssuer(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}, false, false)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if _, err := p.UserInfo(context.Background(), "at-123"); err == nil {
		t.Fatal("UserInfo must fail when the userinfo fetch errors at the transport")
	}
}

func TestUserInfo_DecodeError(t *testing.T) {
	srv := configurableIssuer(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}, false, false)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if _, err := p.UserInfo(context.Background(), "at-123"); err == nil {
		t.Fatal("UserInfo must fail when the userinfo body is not valid JSON")
	}
}
