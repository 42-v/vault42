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

func TestWellKnown_OpenIDConfig_TruthfulKeysOnly(t *testing.T) {
	h := NewWellKnownHandler(nil, "https://auth.example.com")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	h.OpenIDConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)

	if got, _ := result["issuer"].(string); got != "https://auth.example.com" {
		t.Errorf("issuer = %q, want https://auth.example.com", got)
	}
	if got, _ := result["jwks_uri"].(string); got != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %q, want https://auth.example.com/.well-known/jwks.json", got)
	}

	algs, ok := result["access_token_signing_alg_values_supported"].([]interface{})
	if !ok || len(algs) != 1 || algs[0] != "RS256" {
		t.Fatalf("access_token_signing_alg_values_supported = %v, want [RS256]", result["access_token_signing_alg_values_supported"])
	}

	if len(result) != 3 {
		t.Errorf("discovery document has %d keys, want exactly 3: %v", len(result), result)
	}
}

// vault42 is not an OIDC provider. Advertising a capability at 1.0.0 and
// retracting it later is a breaking change, so these keys must stay absent
// until the behavior behind each one exists.
func TestWellKnown_OpenIDConfig_RetractedKeysAbsent(t *testing.T) {
	h := NewWellKnownHandler(nil, "https://vault.test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	h.OpenIDConfig(rec, req)

	var result map[string]interface{}
	decodeResponse(t, rec, &result)

	retracted := []string{
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"registration_endpoint",
		"scopes_supported",
		"response_types_supported",
		"grant_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"token_endpoint_auth_methods_supported",
		"code_challenge_methods_supported",
		"dpop_signing_alg_values_supported",
	}

	for _, key := range retracted {
		if _, present := result[key]; present {
			t.Errorf("discovery document advertises %q, which this server does not implement", key)
		}
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

func TestWellKnown_OpenIDConfig_TableDriven(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   string
	}{
		{"default issuer", "https://vault.test", "https://vault.test"},
		{"custom", "https://c.test:8443", "https://c.test:8443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewWellKnownHandler(nil, tt.issuer)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
			h.OpenIDConfig(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("code %d", rec.Code)
			}
			var res map[string]interface{}
			decodeResponse(t, rec, &res)
			if iss, _ := res["issuer"].(string); iss != tt.want {
				t.Errorf("issuer %q want %q", iss, tt.want)
			}
		})
	}
}
