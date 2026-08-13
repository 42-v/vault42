package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// wellFormedOversizedIDToken builds a syntactically valid RS256 JWT whose
// payload alone runs to sizeBytes. It parses far enough to reach the key
// lookup, which is the point: only a length check placed ahead of parsing stops
// it before the issuer is contacted.
func wellFormedOversizedIDToken(t *testing.T, sizeBytes int) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss": "https://issuer.test", "sub": "s", "aud": "cid",
		"padding": strings.Repeat("A", sizeBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc(header) + "." + enc(payload) + "." + enc([]byte("not-a-real-signature"))
}

// TestVerifyIDTokenRefusesAnOversizedTokenBeforeTouchingTheIssuer is the length
// bound the other two JWT entry points already have and this one did not.
//
// ValidateAccessToken refuses anything past MaxJWTSize (8 KB) and
// ValidateDPoPProof past DPoPMaxSize (4 KB), both before parsing. VerifyIDToken
// had no ceiling of its own: the only limit was the megabyte LimitReader on the
// token-endpoint response, so an issuer got to hand the parser a megabyte of
// base64 and have it decoded and unmarshalled into a claims map.
//
// The observable consequence is that the work happens at all. Parsing an
// unbounded token reaches the key lookup, which fetches discovery and the JWKS
// from the issuer, so the size of the allocation and the outbound fetch are both
// decided by a document that has not been authenticated yet. A token that could
// not be a real one should cost nothing.
func TestVerifyIDTokenRefusesAnOversizedTokenBeforeTouchingTheIssuer(t *testing.T) {
	var discoveryHits atomic.Int64
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		discoveryHits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})

	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://vault.test/cb", "")

	if _, err := p.VerifyIDToken(context.Background(), wellFormedOversizedIDToken(t, 64*1024), "the-nonce"); err == nil {
		t.Fatal("a 64 KB id_token verified without error")
	}
	if n := discoveryHits.Load(); n != 0 {
		t.Fatalf("an oversized id_token drove %d discovery fetch(es) at the issuer; "+
			"it was parsed and its kid looked up before its length was ever considered", n)
	}
}

// TestVerifyIDTokenStillAcceptsAnOrdinarySizedToken is the counterweight: a
// ceiling low enough to catch real tokens would make every rejection above pass
// for the wrong reason. This token is bad for a different reason (nothing signed
// it), so what is being checked is that it got past the length gate and into
// verification, which is what the discovery fetch proves.
func TestVerifyIDTokenStillAcceptsAnOrdinarySizedToken(t *testing.T) {
	var discoveryHits atomic.Int64
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		discoveryHits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	})

	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://vault.test/cb", "")

	_, _ = p.VerifyIDToken(context.Background(), wellFormedOversizedIDToken(t, 64), "the-nonce")

	if discoveryHits.Load() == 0 {
		t.Fatal("a token of ordinary size never reached key lookup; the length gate is refusing real tokens")
	}
}

// TestOIDCDiscoveryRefusesAPlaintextEndpoint covers what the discovery document
// is allowed to point at.
//
// Discovery is the trust root for every other URL this provider uses, and the
// document was taken at face value: whatever it named became the token endpoint,
// the userinfo endpoint and, worst of the three, the jwks_uri that supplies the
// keys every id_token signature is checked against. Nothing required those to be
// https.
//
// An issuer does not have to be hostile for that to matter. A self-hosted
// Keycloak or Authentik behind a proxy that gets X-Forwarded-Proto wrong
// advertises its own endpoints as http, which is a common misconfiguration and
// entirely invisible from vault42's side. From there anyone on the path between
// the pod and that host serves their own JWKS, and every id_token signature is
// then checked against a key they chose: they mint a token for any sub and any
// verified email at that issuer and the callback signs them in as that user.
// The client secret goes out over the same plaintext on the token exchange.
func TestOIDCDiscoveryRefusesAPlaintextEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"the signing key endpoint", "jwks_uri"},
		{"the token endpoint", "token_endpoint"},
		{"the userinfo endpoint", "userinfo_endpoint"},
		{"the authorize endpoint", "authorization_endpoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
				doc := map[string]string{
					"issuer":                 srv.URL,
					"authorization_endpoint": srv.URL + "/authorize",
					"token_endpoint":         srv.URL + "/token",
					"userinfo_endpoint":      srv.URL + "/userinfo",
					"jwks_uri":               srv.URL + "/jwks",
				}
				doc[tc.field] = "http://keys.elsewhere.test/x"
				_ = json.NewEncoder(w).Encode(doc)
			})

			p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://vault.test/cb", "")

			if _, err := p.discover(context.Background()); err == nil {
				t.Fatalf("accepted a discovery document naming %s over plaintext to a host off the loopback interface", tc.field)
			}
		})
	}
}

// TestOIDCDiscoveryStillAllowsALoopbackIssuer keeps the rule from swallowing the
// local case it must not: a developer's issuer, and every fake issuer in this
// package's own tests, is plain http on 127.0.0.1, where there is no network
// segment for anyone to sit on. If this fails, the check above is passing
// because discovery stopped working at all.
func TestOIDCDiscoveryStillAllowsALoopbackIssuer(t *testing.T) {
	srv := fakeIssuer(t, "")
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://vault.test/cb", "")

	if _, err := p.discover(context.Background()); err != nil {
		t.Fatalf("refused a loopback issuer: %v", err)
	}
}
