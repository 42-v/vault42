package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthDynamic_NoTokenRejects(t *testing.T) {
	provider := func() map[string]*rsa.PublicKey { return nil }
	h := AuthDynamic(provider, "https://vault.42-v.com", "vault")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuthChallengeDynamic_NoTokenRejects(t *testing.T) {
	provider := func() map[string]*rsa.PublicKey {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		return map[string]*rsa.PublicKey{"k1": &priv.PublicKey}
	}
	h := AuthChallengeDynamic(provider, "https://vault.42-v.com", "vault")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/2fa/verify", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
