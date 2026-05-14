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

func TestStaticTokenAuth_AcceptsMatch(t *testing.T) {
	h := StaticTokenAuth("the-right-token")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	r.Header.Set("Authorization", "Bearer the-right-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestStaticTokenAuth_RejectsMismatch(t *testing.T) {
	h := StaticTokenAuth("the-right-token")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 401/403", rec.Code)
	}
}
