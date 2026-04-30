package middleware

import (
	"context"
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
)

func TestDPoPNoDPoPHeaderAllowedSecurity(t *testing.T) {
	called := false
	handler := DPoP(nil, "https://vault.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("handler should be called when no DPoP header and no cnf.jkt")
	}
}

func TestDPoPRequiredButMissingSecurity(t *testing.T) {
	handler := DPoP(nil, "https://vault.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called when DPoP is required but missing")
	}))

	claims := &vaultcrypto.VaultClaims{
		Confirmation: &vaultcrypto.Confirmation{JKT: "some-thumbprint"},
	}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when DPoP required but missing, got %d", rec.Code)
	}
}

func TestDPoPURISchemeFromTLS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	proof := makeDPoPProofForTest(t, key, "GET", "https://vault.test/user/profile")

	called := false
	handler := DPoP(nil, "https://vault.test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Host = "vault.test"
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("handler should be called for valid DPoP proof over TLS")
	}
}

func TestDPoPURISchemeNoTLS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	proof := makeDPoPProofForTest(t, key, "GET", "http://vault.test/user/profile")

	called := false
	handler := DPoP(nil, "http://vault.test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Host = "vault.test"
	req.TLS = nil
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("handler should be called for valid DPoP proof over HTTP")
	}
}

func TestDPoPSchemeMismatchRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	proof := makeDPoPProofForTest(t, key, "GET", "https://vault.test/user/profile")

	handler := DPoP(nil, "http://vault.test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called for DPoP proof with scheme mismatch")
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Host = "vault.test"
	req.TLS = nil
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when scheme mismatches, got %d", rec.Code)
	}
}

func TestDPoPInvalidProofRejected(t *testing.T) {
	handler := DPoP(nil, "https://vault.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called for invalid DPoP proof")
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("DPoP", "not-a-valid-jwt")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid DPoP proof, got %d", rec.Code)
	}
}

// makeDPoPProofForTest creates a DPoP proof JWT for testing.
func makeDPoPProofForTest(t *testing.T, key *rsa.PrivateKey, method, uri string) string {
	t.Helper()

	claims := &vaultcrypto.DPoPClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			IssuedAt: vjwt.NewNumericDate(time.Now()),
			ID:       "dpop-middleware-test",
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
