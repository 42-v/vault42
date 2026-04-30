package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

func TestFingerprintNoAuth(t *testing.T) {
	var called bool
	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Error("handler should be called when no claims present")
	}
}

func TestFingerprintEmptyClaim(t *testing.T) {
	var called bool
	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: ""}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Error("handler should be called when fingerprint claim is empty")
	}
}

func TestFingerprintMatch(t *testing.T) {
	ip := "1.2.3.4"
	ua := "TestAgent/1.0"
	lang := "en-US"

	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             ip,
		UserAgent:      ua,
		AcceptLanguage: lang,
	})

	var called bool
	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = ip + ":12345"
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept-Language", lang)
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Error("handler should be called when fingerprint matches")
	}
}

func TestFingerprintMismatchStrict(t *testing.T) {
	// Compute fingerprint for one set of values
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "OriginalAgent",
		AcceptLanguage: "en-US",
	})

	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request comes from a different IP/UA
	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "9.8.7.6:12345"
	req.Header.Set("User-Agent", "DifferentAgent")
	req.Header.Set("Accept-Language", "de-DE")
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if body := rec.Body.String(); body != "{\"error\":\"invalid_token\"}\n" {
		t.Errorf("body = %q, want invalid_token error", body)
	}
}

func TestFingerprintMismatchSoft(t *testing.T) {
	// Compute fingerprint for one set of values
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "OriginalAgent",
		AcceptLanguage: "en-US",
	})

	var called bool
	handler := Fingerprint(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	// Request comes from a different IP/UA — soft mode should allow it
	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "9.8.7.6:12345"
	req.Header.Set("User-Agent", "DifferentAgent")
	req.Header.Set("Accept-Language", "de-DE")
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (soft mode should allow mismatch)", rec.Code)
	}
	if !called {
		t.Error("handler should be called in soft mode even with fingerprint mismatch")
	}
}
