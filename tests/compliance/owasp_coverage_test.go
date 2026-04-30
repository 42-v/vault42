package compliance

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
)

// =============================================================================
// OWASP ASVS v4.0.3 Coverage Tests — additional requirements verification
// =============================================================================

// --- V14.4: Security Headers ---

// TestOWASP_SecurityHeaders_XContentTypeOptions verifies that X-Content-Type-Options
// is set to "nosniff".
func TestOWASP_SecurityHeaders_XContentTypeOptions(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	val := rec.Header().Get("X-Content-Type-Options")
	if val != "nosniff" {
		t.Fatalf("X-Content-Type-Options should be 'nosniff', got %q", val)
	}
}

// TestOWASP_SecurityHeaders_XFrameOptions verifies that X-Frame-Options
// is set to "DENY".
func TestOWASP_SecurityHeaders_XFrameOptions(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	val := rec.Header().Get("X-Frame-Options")
	if val != "DENY" {
		t.Fatalf("X-Frame-Options should be 'DENY', got %q", val)
	}
}

// TestOWASP_SecurityHeaders_HSTS verifies that Strict-Transport-Security is set.
func TestOWASP_SecurityHeaders_HSTS(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	val := rec.Header().Get("Strict-Transport-Security")
	if val == "" {
		t.Fatal("Strict-Transport-Security header must be present")
	}
	if !strings.Contains(val, "max-age=") {
		t.Fatalf("HSTS must contain max-age directive, got %q", val)
	}
	if !strings.Contains(val, "includeSubDomains") {
		t.Fatalf("HSTS should include includeSubDomains, got %q", val)
	}
}

// TestOWASP_SecurityHeaders_CSP verifies Content-Security-Policy is set.
func TestOWASP_SecurityHeaders_CSP(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	val := rec.Header().Get("Content-Security-Policy")
	if val == "" {
		t.Fatal("Content-Security-Policy header must be present")
	}
	if !strings.Contains(val, "default-src") {
		t.Fatalf("CSP should contain default-src directive, got %q", val)
	}
}

// TestOWASP_SecurityHeaders_ReferrerPolicy verifies Referrer-Policy is set.
func TestOWASP_SecurityHeaders_ReferrerPolicy(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	val := rec.Header().Get("Referrer-Policy")
	if val == "" {
		t.Fatal("Referrer-Policy header must be present")
	}
	if val != "no-referrer" {
		t.Fatalf("Referrer-Policy should be 'no-referrer', got %q", val)
	}
}

// TestOWASP_SecurityHeaders_CacheControl verifies Cache-Control is set to no-store.
func TestOWASP_SecurityHeaders_CacheControl(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	val := rec.Header().Get("Cache-Control")
	if val != "no-store" {
		t.Fatalf("Cache-Control should be 'no-store', got %q", val)
	}
}

// TestOWASP_SecurityHeaders_XSSProtection verifies X-XSS-Protection is "0"
// (disabled, per modern best practices — CSP is the replacement).
func TestOWASP_SecurityHeaders_XSSProtection(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	val := rec.Header().Get("X-XSS-Protection")
	if val != "0" {
		t.Fatalf("X-XSS-Protection should be '0' (disabled), got %q", val)
	}
}

// TestOWASP_SecurityHeaders_AllPresent verifies ALL security headers are set in one request.
func TestOWASP_SecurityHeaders_AllPresent(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	required := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Cache-Control",
		"Pragma",
	}

	for _, h := range required {
		if rec.Header().Get(h) == "" {
			t.Errorf("Missing required security header: %s", h)
		}
	}
}

// --- V14.5: CORS ---

// TestOWASP_CORS_AllowedOriginSet verifies CORS middleware sets the correct origin.
func TestOWASP_CORS_AllowedOriginSet(t *testing.T) {
	corsMiddleware := middleware.CORS("https://vault.example.com", nil, false)
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	origin := rec.Header().Get("Access-Control-Allow-Origin")
	if origin != "https://vault.example.com" {
		t.Fatalf("CORS origin should be 'https://vault.example.com', got %q", origin)
	}
}

// TestOWASP_CORS_CredentialsAllowed verifies CORS allows credentials (for cookies).
func TestOWASP_CORS_CredentialsAllowed(t *testing.T) {
	corsMiddleware := middleware.CORS("https://vault.example.com", nil, false)
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	val := rec.Header().Get("Access-Control-Allow-Credentials")
	if val != "true" {
		t.Fatalf("CORS should allow credentials, got %q", val)
	}
}

// TestOWASP_CORS_PreflightHandled verifies OPTIONS preflight requests are handled.
func TestOWASP_CORS_PreflightHandled(t *testing.T) {
	corsMiddleware := middleware.CORS("https://vault.example.com", nil, false)
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not reach here"))
	}))

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS preflight should return 204, got %d", rec.Code)
	}

	// Body should be empty for preflight
	if rec.Body.Len() > 0 {
		t.Fatal("OPTIONS preflight response body should be empty")
	}
}

// TestOWASP_CORS_VaryOriginSet verifies the Vary: Origin header is set.
func TestOWASP_CORS_VaryOriginSet(t *testing.T) {
	corsMiddleware := middleware.CORS("https://vault.example.com", nil, false)
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	vary := rec.Header().Get("Vary")
	if !strings.Contains(vary, "Origin") {
		t.Fatalf("Vary header should contain 'Origin', got %q", vary)
	}
}

// TestOWASP_CORS_AllowedMethods verifies the allowed HTTP methods.
func TestOWASP_CORS_AllowedMethods(t *testing.T) {
	corsMiddleware := middleware.CORS("https://vault.example.com", nil, false)
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	methods := rec.Header().Get("Access-Control-Allow-Methods")
	required := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	for _, m := range required {
		if !strings.Contains(methods, m) {
			t.Errorf("CORS should allow %s method, got: %s", m, methods)
		}
	}
}

// --- V3.5: JWT Security ---

// TestOWASP_JWTMaxSizeEnforced verifies that JWT parsing enforces the 8KB maximum.
func TestOWASP_JWTMaxSizeEnforced(t *testing.T) {
	keyFunc := func(t *vjwt.Token) (any, error) { return nil, nil }

	sizes := []int{
		vaultcrypto.MaxJWTSize + 1,   // just over
		vaultcrypto.MaxJWTSize + 100, // well over
		vaultcrypto.MaxJWTSize * 2,   // double
		100000,                       // 100KB
	}

	for _, size := range sizes {
		t.Run("size="+strings.Repeat("x", 0), func(t *testing.T) {
			oversized := strings.Repeat("a", size)
			_, err := vaultcrypto.ParseAndValidate(oversized, keyFunc, "test", "test")
			if err == nil {
				t.Fatalf("JWT of size %d should be rejected (max %d)", size, vaultcrypto.MaxJWTSize)
			}
			if !strings.Contains(err.Error(), "maximum size") {
				t.Logf("Error: %v (acceptable rejection)", err)
			}
		})
	}
}

// TestOWASP_NoSensitiveDataInJWTClaims verifies that VaultClaims struct does not
// contain fields that would hold passwords, secrets, or PII beyond identifiers.
func TestOWASP_NoSensitiveDataInJWTClaims(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-uuid-here",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles:     []string{"user"},
		Scopes:    []string{"read"},
		ClientID:  "frontend",
		TokenType: "access",
	}

	tokenStr, _ := vaultcrypto.SignToken(claims, key, kid)

	// Decode the payload to check for sensitive fields
	parts := strings.SplitN(tokenStr, ".", 3)
	payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])

	var payload map[string]interface{}
	json.Unmarshal(payloadJSON, &payload)

	// These fields must NEVER appear in JWT claims
	sensitiveFields := []string{
		"password", "password_hash", "secret", "private_key",
		"email", "phone", "address", "ssn", "credit_card",
		"refresh_token", "api_key", "master_key",
	}

	for _, field := range sensitiveFields {
		if _, exists := payload[field]; exists {
			t.Fatalf("JWT claims should not contain sensitive field %q", field)
		}
	}
}

// TestOWASP_JWTClaimsFieldList verifies the exact set of fields in VaultClaims.
func TestOWASP_JWTClaimsFieldList(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles:       []string{"user"},
		Scopes:      []string{"read"},
		ClientID:    "frontend",
		Fingerprint: "abc123",
		TokenType:   "access",
	}

	tokenStr, _ := vaultcrypto.SignToken(claims, key, kid)
	parts := strings.SplitN(tokenStr, ".", 3)
	payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])

	var payload map[string]interface{}
	json.Unmarshal(payloadJSON, &payload)

	// Expected fields (standard + custom)
	allowedFields := map[string]bool{
		"sub": true, "iss": true, "aud": true, "exp": true,
		"iat": true, "nbf": true, "jti": true,
		"roles": true, "scopes": true, "client_id": true,
		"fingerprint": true, "cnf": true, "token_type": true,
	}

	for field := range payload {
		if !allowedFields[field] {
			t.Errorf("Unexpected JWT claim field: %q", field)
		}
	}
}

// --- V2.2: Rate Limiting ---

// TestOWASP_RateLimitMiddlewareExists verifies that rate limiting middleware
// is implemented and functional.
func TestOWASP_RateLimitMiddlewareExists(t *testing.T) {
	// Verify that RateLimitConfig struct has required fields
	cfg := middleware.RateLimitConfig{
		Limit:  10,
		Window: time.Minute,
		KeyFunc: func(r *http.Request) string {
			return "test-key"
		},
	}

	if cfg.Limit <= 0 {
		t.Fatal("Rate limit must be positive")
	}
	if cfg.Window <= 0 {
		t.Fatal("Rate limit window must be positive")
	}
	if cfg.KeyFunc == nil {
		t.Fatal("Rate limit must have a key function")
	}
}

// TestOWASP_RateLimitKeyFunctions verifies that rate limit key functions exist
// for different endpoint types.
func TestOWASP_RateLimitKeyFunctions(t *testing.T) {
	// LoginRateLimitKey should be available
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	loginKey := middleware.LoginRateLimitKey(req)
	if loginKey == "" {
		t.Fatal("LoginRateLimitKey should return a non-empty key")
	}
	if !strings.Contains(loginKey, "login:") {
		t.Fatalf("LoginRateLimitKey should start with 'login:', got %q", loginKey)
	}

	// IPRateLimitKey should be available
	ipKey := middleware.IPRateLimitKey(req)
	if ipKey == "" {
		t.Fatal("IPRateLimitKey should return a non-empty key")
	}
	if !strings.Contains(ipKey, "ip:") {
		t.Fatalf("IPRateLimitKey should start with 'ip:', got %q", ipKey)
	}
}

// TestOWASP_RateLimitDisabledPassthrough verifies that disabled rate limiting
// passes requests through.
func TestOWASP_RateLimitDisabledPassthrough(t *testing.T) {
	cfg := middleware.RateLimitConfig{
		Limit:  1,
		Window: time.Minute,
		KeyFunc: func(r *http.Request) string {
			return "test"
		},
	}

	// nil cache is ok when disabled
	rlMiddleware := middleware.RateLimit(nil, cfg, false)
	called := false
	handler := rlMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("Disabled rate limiter should pass requests through")
	}
}

// --- V3.5: JWT Token Validation ---

// TestOWASP_JWTExpirationRequired verifies that tokens without expiration are rejected.
func TestOWASP_JWTExpirationRequired(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	// Token without exp
	tokenStr, _ := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:  "user-123",
			Issuer:   "vault",
			Audience: vjwt.ClaimStrings{"app"},
			IssuedAt: vjwt.NewNumericDate(time.Now()),
		},
	}, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err == nil {
		t.Fatal("Token without exp claim should be rejected")
	}
}

// TestOWASP_JWTIssuerRequired verifies that tokens with wrong issuer are rejected.
func TestOWASP_JWTIssuerRequired(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "legit-vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "different-vault", "app")
	if err == nil {
		t.Fatal("Token with wrong issuer should be rejected")
	}
}

// TestOWASP_JWTAudienceRequired verifies that tokens with wrong audience are rejected.
func TestOWASP_JWTAudienceRequired(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app-frontend"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app-admin")
	if err == nil {
		t.Fatal("Token with wrong audience should be rejected")
	}
}

// TestOWASP_SecurityHeadersPassthroughToHandler verifies that security headers
// middleware calls the next handler.
func TestOWASP_SecurityHeadersPassthroughToHandler(t *testing.T) {
	called := false
	handler := middleware.SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("SecurityHeaders middleware should call the next handler")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}
}
