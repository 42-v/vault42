package unit_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
)

const wkIssuer = "https://vault.test"

// generateTestKeys creates n RSA 2048-bit key pairs and returns them as a
// kid -> *rsa.PublicKey map ready for the WellKnownHandler.
func generateTestKeys(t *testing.T, n int) map[string]*rsa.PublicKey {
	t.Helper()
	keys := make(map[string]*rsa.PublicKey, n)
	for i := 0; i < n; i++ {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key %d: %v", i, err)
		}
		kid, err := vaultcrypto.RandomUUID()
		if err != nil {
			t.Fatalf("generate kid %d: %v", i, err)
		}
		keys[kid] = &priv.PublicKey
	}
	return keys
}

// ---- TestJWKS_Valid ----

func TestJWKS_Valid(t *testing.T) {
	keys := generateTestKeys(t, 1)
	h := handler.NewWellKnownHandler(keys, wkIssuer)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.JWKS(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}

	var jwks vaultcrypto.JWKS
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(jwks.Keys))
	}

	k := jwks.Keys[0]
	if k.KTY != "RSA" {
		t.Errorf("expected kty=RSA, got %q", k.KTY)
	}
	if k.ALG != "RS256" {
		t.Errorf("expected alg=RS256, got %q", k.ALG)
	}
	if k.Use != "sig" {
		t.Errorf("expected use=sig, got %q", k.Use)
	}
	if k.N == "" {
		t.Error("expected non-empty N (modulus)")
	}
	if k.E == "" {
		t.Error("expected non-empty E (exponent)")
	}
}

// ---- TestOpenIDConfig_Valid ----

func TestOpenIDConfig_Valid(t *testing.T) {
	keys := generateTestKeys(t, 1)
	h := handler.NewWellKnownHandler(keys, wkIssuer)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	h.OpenIDConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}

	var config map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&config); err != nil {
		t.Fatalf("decode openid-config: %v", err)
	}

	if config["issuer"] != wkIssuer {
		t.Errorf("expected issuer=%q, got %v", wkIssuer, config["issuer"])
	}
	if config["jwks_uri"] != wkIssuer+"/.well-known/jwks.json" {
		t.Errorf("expected jwks_uri=%q, got %v", wkIssuer+"/.well-known/jwks.json", config["jwks_uri"])
	}
	if config["token_endpoint"] != wkIssuer+"/auth/login" {
		t.Errorf("expected token_endpoint=%q, got %v", wkIssuer+"/auth/login", config["token_endpoint"])
	}
}

// ---- TestOpenIDConfig_RequiredFields ----

func TestOpenIDConfig_RequiredFields(t *testing.T) {
	keys := generateTestKeys(t, 1)
	h := handler.NewWellKnownHandler(keys, wkIssuer)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	h.OpenIDConfig(w, req)

	var config map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&config); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// OIDC Discovery 1.0 required fields
	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	}

	for _, field := range requiredFields {
		if _, ok := config[field]; !ok {
			t.Errorf("missing required OIDC field %q", field)
		}
	}

	// Verify array fields have expected values
	algValues, ok := config["id_token_signing_alg_values_supported"].([]interface{})
	if !ok || len(algValues) == 0 {
		t.Fatal("id_token_signing_alg_values_supported missing or empty")
	}
	if algValues[0] != "RS256" {
		t.Errorf("expected RS256 in signing alg values, got %v", algValues[0])
	}

	// S256 must be the only supported PKCE method
	codeMethods, ok := config["code_challenge_methods_supported"].([]interface{})
	if !ok || len(codeMethods) == 0 {
		t.Fatal("code_challenge_methods_supported missing or empty")
	}
	if codeMethods[0] != "S256" {
		t.Errorf("expected S256 as PKCE method, got %v", codeMethods[0])
	}

	// Verify scopes_supported includes openid
	scopes, ok := config["scopes_supported"].([]interface{})
	if !ok || len(scopes) == 0 {
		t.Fatal("scopes_supported missing or empty")
	}
	foundOpenID := false
	for _, s := range scopes {
		if s == "openid" {
			foundOpenID = true
			break
		}
	}
	if !foundOpenID {
		t.Error("scopes_supported does not include 'openid'")
	}
}
