package attack

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
)

// TestDPoPHostHeaderInjection_HostHeaderIsIgnored pins the rule the whole file
// rests on: the middleware builds the validation URI from the configured origin
// plus the request path, so nothing a client puts in Host can steer it. Each
// row sends the same valid proof for the configured origin under a different
// hostile Host, and every one has to reach the handler.
func TestDPoPHostHeaderInjection_HostHeaderIsIgnored(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proof := makeDPoPProof(t, key, "POST", "https://vault.example.com/auth/token")

	cases := []struct {
		name string
		host string
	}{
		{"unrelated host", "evil.com"},
		{"configured host with a port", "vault.example.com:8443"},
		{"subdomain of the configured host", "sub.vault.example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := middleware.DPoP(nil, "https://vault.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
			req.Host = tc.host
			req.TLS = &tls.ConnectionState{}
			req.Header.Set("DPoP", proof)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if !called {
				t.Fatalf("Host %q reached the middleware and stopped the request with %d; DPoP validates against the configured origin, not Host", tc.host, rec.Code)
			}
		})
	}
}

// TestDPoPHostHeaderInjection_CorrectHostAccepted verifies the positive case:
// when the DPoP proof htu matches the actual request URI (including Host), the
// proof is accepted.
func TestDPoPHostHeaderInjection_CorrectHostAccepted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	correctURI := "https://vault.example.com/auth/token"
	proof := makeDPoPProof(t, key, "POST", correctURI)

	called := false
	handler := middleware.DPoP(nil, "https://vault.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	req.Host = "vault.example.com"
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("Handler should be called when DPoP proof matches request URI")
	}
}

// TestDPoPHostHeaderInjection_WrongOriginRejected verifies that a DPoP proof
// targeting a different origin than the configured one is rejected.
func TestDPoPHostHeaderInjection_WrongOriginRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	proof := makeDPoPProof(t, key, "POST", "https://evil.com/auth/token")

	handler := middleware.DPoP(nil, "https://vault.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should NOT be called when proof targets wrong origin")
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	req.Host = "evil.com"
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for wrong origin, got %d", rec.Code)
	}
}

// TestDPoPHostHeaderInjection_PathTraversalRejected verifies that a DPoP proof
// targeting /auth/token cannot be used for /auth/admin.
func TestDPoPHostHeaderInjection_PathTraversalRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Proof is for /auth/token
	proof := makeDPoPProof(t, key, "GET", "https://vault.example.com/auth/token")

	handler := middleware.DPoP(nil, "https://vault.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should NOT be called for path mismatch")
	}))

	// Request is for /auth/admin
	req := httptest.NewRequest(http.MethodGet, "/auth/admin", nil)
	req.Host = "vault.example.com"
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for path mismatch, got %d", rec.Code)
	}
}

// TestDPoPHostHeaderInjection_SchemeFromOriginNotTLS verifies that the DPoP
// middleware uses the configured origin's scheme, not the request TLS state.
// This is correct because TLS is typically terminated at the load balancer.
func TestDPoPHostHeaderInjection_SchemeFromOriginNotTLS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	proof := makeDPoPProof(t, key, "POST", "https://vault.example.com/auth/token")

	called := false
	handler := middleware.DPoP(nil, "https://vault.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	req.Host = "vault.example.com"
	req.TLS = nil
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("Handler should be called: DPoP uses origin scheme, not request TLS state")
	}
}

// makeDPoPProof creates a DPoP proof JWT signed with the given RSA key.
func makeDPoPProof(t *testing.T, key *rsa.PrivateKey, method, uri string) string {
	t.Helper()

	claims := &vaultcrypto.DPoPClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			IssuedAt: vjwt.NewNumericDate(time.Now()),
			ID:       "dpop-host-test-jti",
		},
		HTM: method,
		HTU: uri,
	}

	header := map[string]any{
		"alg": "RS256",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		},
	}

	tokenStr, err := vjwt.SignRS256WithHeader(header, claims, key)
	if err != nil {
		t.Fatal(err)
	}
	return tokenStr
}
