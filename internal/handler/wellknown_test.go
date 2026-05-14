package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testRSAKey(t *testing.T) *rsa.PublicKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	return &priv.PublicKey
}

func TestNewDynamicWellKnownHandler_ServesJWKS(t *testing.T) {
	pub := testRSAKey(t)
	provider := func() map[string]*rsa.PublicKey { return map[string]*rsa.PublicKey{"kid-1": pub} }
	h := NewDynamicWellKnownHandler(provider, "https://vault.42-v.com")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	h.JWKS(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("JWKS status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}
