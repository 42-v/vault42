package handler

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// WellKnownHandler extended tests
// ---------------------------------------------------------------------------

func TestWellKnown_JWKS_MultipleKeys(t *testing.T) {
	key1 := newTestRSAKey(t)
	key2 := newTestRSAKey(t)
	keys := map[string]*rsa.PublicKey{
		"kid-1": &key1.PublicKey,
		"kid-2": &key2.PublicKey,
	}

	h := NewWellKnownHandler(keys, "https://vault.test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	h.JWKS(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	keysArr, ok := result["keys"].([]interface{})
	if !ok {
		t.Fatal("expected keys array in JWKS response")
	}
	if len(keysArr) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keysArr))
	}
}

func TestWellKnown_JWKS_EmptyKeys(t *testing.T) {
	h := NewWellKnownHandler(map[string]*rsa.PublicKey{}, "https://vault.test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	h.JWKS(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	keysArr, ok := result["keys"].([]interface{})
	if !ok {
		t.Fatal("expected keys array in JWKS response")
	}
	if len(keysArr) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keysArr))
	}
}

func TestWellKnown_JWKS_CacheHeaders(t *testing.T) {
	key := newTestRSAKey(t)
	h := NewWellKnownHandler(map[string]*rsa.PublicKey{"kid": &key.PublicKey}, "https://vault.test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	h.JWKS(rec, req)

	cacheControl := rec.Header().Get("Cache-Control")
	if cacheControl != "public, max-age=300" {
		t.Fatalf("expected Cache-Control=public, max-age=300, got %q", cacheControl)
	}
}

func TestWellKnown_JWKS_KeyFields(t *testing.T) {
	key := newTestRSAKey(t)
	h := NewWellKnownHandler(map[string]*rsa.PublicKey{"test-kid-42": &key.PublicKey}, "https://vault.test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	h.JWKS(rec, req)

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	keysArr := result["keys"].([]interface{})
	k := keysArr[0].(map[string]interface{})

	if k["kty"] != "RSA" {
		t.Fatalf("expected kty=RSA, got %v", k["kty"])
	}
	if k["use"] != "sig" {
		t.Fatalf("expected use=sig, got %v", k["use"])
	}
	if k["alg"] != "RS256" {
		t.Fatalf("expected alg=RS256, got %v", k["alg"])
	}
	if k["kid"] != "test-kid-42" {
		t.Fatalf("expected kid=test-kid-42, got %v", k["kid"])
	}
	if k["n"] == nil || k["n"] == "" {
		t.Fatal("expected non-empty n (modulus) in key")
	}
	if k["e"] == nil || k["e"] == "" {
		t.Fatal("expected non-empty e (exponent) in key")
	}
}

// ---------------------------------------------------------------------------
// OpenIDConfig tests
// ---------------------------------------------------------------------------

func TestWellKnown_OpenIDConfig_Endpoints(t *testing.T) {
	h := NewWellKnownHandler(nil, "https://auth.example.com")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	h.OpenIDConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)

	expected := map[string]string{
		"issuer":                 "https://auth.example.com",
		"authorization_endpoint": "https://auth.example.com/auth/oauth2/authorize",
		"token_endpoint":         "https://auth.example.com/auth/login",
		"userinfo_endpoint":      "https://auth.example.com/user/profile",
		"jwks_uri":               "https://auth.example.com/.well-known/jwks.json",
		"registration_endpoint":  "https://auth.example.com/auth/register",
	}

	for key, want := range expected {
		got, _ := result[key].(string)
		if got != want {
			t.Fatalf("expected %s=%s, got %s", key, want, got)
		}
	}
}

func TestWellKnown_OpenIDConfig_ScopesSupported(t *testing.T) {
	h := NewWellKnownHandler(nil, "https://vault.test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	h.OpenIDConfig(rec, req)

	var result map[string]interface{}
	decodeResponse(t, rec, &result)

	scopes, ok := result["scopes_supported"].([]interface{})
	if !ok || len(scopes) == 0 {
		t.Fatal("expected scopes_supported array")
	}

	scopeSet := make(map[string]bool)
	for _, s := range scopes {
		scopeSet[s.(string)] = true
	}
	for _, expected := range []string{"openid", "profile", "email"} {
		if !scopeSet[expected] {
			t.Fatalf("expected scope %q in scopes_supported", expected)
		}
	}
}

func TestWellKnown_OpenIDConfig_GrantTypes(t *testing.T) {
	h := NewWellKnownHandler(nil, "https://vault.test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	h.OpenIDConfig(rec, req)

	var result map[string]interface{}
	decodeResponse(t, rec, &result)

	grantTypes, ok := result["grant_types_supported"].([]interface{})
	if !ok || len(grantTypes) == 0 {
		t.Fatal("expected grant_types_supported array")
	}

	grantSet := make(map[string]bool)
	for _, g := range grantTypes {
		grantSet[g.(string)] = true
	}
	for _, expected := range []string{"authorization_code", "refresh_token", "client_credentials"} {
		if !grantSet[expected] {
			t.Fatalf("expected grant type %q in grant_types_supported", expected)
		}
	}
}

func TestWellKnown_OpenIDConfig_PKCE(t *testing.T) {
	h := NewWellKnownHandler(nil, "https://vault.test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	h.OpenIDConfig(rec, req)

	var result map[string]interface{}
	decodeResponse(t, rec, &result)

	methods, ok := result["code_challenge_methods_supported"].([]interface{})
	if !ok || len(methods) == 0 {
		t.Fatal("expected code_challenge_methods_supported array")
	}
	if methods[0] != "S256" {
		t.Fatalf("expected S256 in code_challenge_methods, got %v", methods[0])
	}
}

func TestWellKnown_OpenIDConfig_ContentType(t *testing.T) {
	h := NewWellKnownHandler(nil, "https://vault.test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	h.OpenIDConfig(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type=application/json, got %q", ct)
	}
}

// ---------------------------------------------------------------------------
// UpdateKeys tests
// ---------------------------------------------------------------------------

func TestWellKnown_UpdateKeys(t *testing.T) {
	key1 := newTestRSAKey(t)
	h := NewWellKnownHandler(map[string]*rsa.PublicKey{
		"old-kid": &key1.PublicKey,
	}, "https://vault.test")

	// Verify we start with 1 key
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h.JWKS(rec, req)

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	keysArr := result["keys"].([]interface{})
	if len(keysArr) != 1 {
		t.Fatalf("expected 1 key before update, got %d", len(keysArr))
	}

	// Update with 2 new keys
	key2 := newTestRSAKey(t)
	key3 := newTestRSAKey(t)
	h.UpdateKeys(map[string]*rsa.PublicKey{
		"new-kid-1": &key2.PublicKey,
		"new-kid-2": &key3.PublicKey,
	})

	// Verify we now have 2 keys
	req = httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec = httptest.NewRecorder()
	h.JWKS(rec, req)

	decodeResponse(t, rec, &result)
	keysArr = result["keys"].([]interface{})
	if len(keysArr) != 2 {
		t.Fatalf("expected 2 keys after update, got %d", len(keysArr))
	}
}

func TestWellKnown_UpdateKeys_Empty(t *testing.T) {
	key := newTestRSAKey(t)
	h := NewWellKnownHandler(map[string]*rsa.PublicKey{
		"kid": &key.PublicKey,
	}, "https://vault.test")

	// Replace with empty key set
	h.UpdateKeys(map[string]*rsa.PublicKey{})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h.JWKS(rec, req)

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	keysArr := result["keys"].([]interface{})
	if len(keysArr) != 0 {
		t.Fatalf("expected 0 keys after clearing, got %d", len(keysArr))
	}
}
