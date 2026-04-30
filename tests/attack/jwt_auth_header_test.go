package attack

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
)

// setupAuthMiddleware creates an auth middleware with a valid key and a signed token for testing.
func setupAuthMiddleware(t *testing.T) (http.Handler, string) {
	t.Helper()
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}
	handler := middleware.Auth(keys, "test", "test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	return handler, tokenStr
}

// TestJWT_AuthHeader_LowercaseBearer verifies that "bearer" (lowercase) is rejected.
func TestJWT_AuthHeader_LowercaseBearer(t *testing.T) {
	handler, token := setupAuthMiddleware(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for lowercase 'bearer', got %d", rec.Code)
	}
}

// TestJWT_AuthHeader_UppercaseBearer verifies that "BEARER" (all caps) is rejected.
func TestJWT_AuthHeader_UppercaseBearer(t *testing.T) {
	handler, token := setupAuthMiddleware(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "BEARER "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for uppercase 'BEARER', got %d", rec.Code)
	}
}

// TestJWT_AuthHeader_TrailingSpace verifies that trailing space in token is rejected.
func TestJWT_AuthHeader_TrailingSpace(t *testing.T) {
	handler, token := setupAuthMiddleware(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token+" ")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for trailing space in token, got %d", rec.Code)
	}
}

// TestJWT_AuthHeader_LeadingSpace verifies that leading space in Authorization value is handled.
func TestJWT_AuthHeader_LeadingSpace(t *testing.T) {
	handler, token := setupAuthMiddleware(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", " Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	// SplitN(" Bearer token", " ", 2) → [" Bearer", "token"] — scheme doesn't match "Bearer"
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for leading space in Authorization, got %d", rec.Code)
	}
}

// TestJWT_AuthHeader_MissingToken verifies that "Bearer" with no token is rejected.
func TestJWT_AuthHeader_MissingToken(t *testing.T) {
	handler, _ := setupAuthMiddleware(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for 'Bearer' without token, got %d", rec.Code)
	}
}

// TestJWT_AuthHeader_NoScheme verifies that a bare token without scheme is rejected.
func TestJWT_AuthHeader_NoScheme(t *testing.T) {
	handler, token := setupAuthMiddleware(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for bare token without scheme, got %d", rec.Code)
	}
}

// TestJWT_AuthHeader_BasicAuth verifies that Basic auth scheme is rejected.
func TestJWT_AuthHeader_BasicAuth(t *testing.T) {
	handler, _ := setupAuthMiddleware(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for Basic auth, got %d", rec.Code)
	}
}

// TestJWT_AuthHeader_EmptyValue verifies that empty Authorization header is rejected.
func TestJWT_AuthHeader_EmptyValue(t *testing.T) {
	handler, _ := setupAuthMiddleware(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for empty Authorization, got %d", rec.Code)
	}
}
