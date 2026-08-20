package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// newTestKey generates a 2048-bit RSA key pair for testing.
func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

// signTestToken creates a valid signed JWT for testing.
func signTestToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience, subject string, expiry time.Duration) string {
	t.Helper()
	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  vjwt.ClaimStrings{audience},
			Subject:   subject,
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(expiry)),
			NotBefore: vjwt.NewNumericDate(time.Now()),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
			ID:        "test-jti",
		},
		Roles: []string{"user"},
	}
	tokenStr, err := vaultcrypto.SignToken(claims, key, kid)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenStr
}

// TestAuthRejects covers every way an Authorization header fails to get past the
// middleware. They share a table because the interesting part is that each one
// stops at 401 with its own error code: a caller must be able to tell "you sent
// nothing" from "your token is not valid", and the middleware must never let one
// of these fall through to the handler.
func TestAuthRejects(t *testing.T) {
	key := newTestKey(t)
	kid := "aabbccdd-1234"
	wrongKID := "00112233-5678"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	expired := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  vjwt.ClaimStrings{"test-audience"},
			Subject:   "user-123",
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
			ID:        "expired-jti",
		},
	}
	expiredToken, err := vaultcrypto.SignToken(expired, key, kid)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	tests := []struct {
		name string
		// authorization is set verbatim; the empty string means no header at all.
		authorization string
		wantError     string
	}{
		{name: "no Authorization header", wantError: "missing_authorization"},
		{name: "a scheme that is not Bearer", authorization: "Basic dXNlcjpwYXNz", wantError: "invalid_authorization"},
		{name: "a Bearer value that is not a JWT", authorization: "Bearer garbage-token-value", wantError: "invalid_token"},
		{
			name:          "a token signed under a kid the server does not hold",
			authorization: "Bearer " + signTestToken(t, key, wrongKID, "test-issuer", "test-audience", "user-123", 5*time.Minute),
			wantError:     "invalid_token",
		},
		{name: "an expired token", authorization: "Bearer " + expiredToken, wantError: "invalid_token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("the handler ran on a request that should have been refused")
			}))

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			assertJSONError(t, rec, tt.wantError)
		})
	}
}

func TestAuthValidToken(t *testing.T) {
	key := newTestKey(t)
	kid := "aabbccdd-1234"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	var gotClaims *vaultcrypto.VaultClaims
	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = GetClaims(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	tokenStr := signTestToken(t, key, kid, "test-issuer", "test-audience", "user-123", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if gotClaims == nil {
		t.Fatal("claims should be set in context")
	}
	if gotClaims.Subject != "user-123" {
		t.Errorf("subject = %q, want user-123", gotClaims.Subject)
	}
	if len(gotClaims.Roles) != 1 || gotClaims.Roles[0] != "user" {
		t.Errorf("roles = %v, want [user]", gotClaims.Roles)
	}
}

func TestGetClaimsNil(t *testing.T) {
	ctx := context.Background()
	claims := GetClaims(ctx)
	if claims != nil {
		t.Errorf("expected nil claims from empty context, got %v", claims)
	}
}

func TestGetClaimsPresent(t *testing.T) {
	want := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "user-456",
		},
		Roles: []string{"admin"},
	}
	ctx := context.WithValue(context.Background(), ClaimsKey, want)
	got := GetClaims(ctx)
	if got == nil {
		t.Fatal("expected claims, got nil")
	}
	if got.Subject != want.Subject {
		t.Errorf("subject = %q, want %q", got.Subject, want.Subject)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin]", got.Roles)
	}
}

// assertJSONError decodes the response body as JSON and asserts the "error" field matches want.
func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body as JSON: %v", err)
	}
	got, _ := body["error"].(string)
	if got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}
