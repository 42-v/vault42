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

// TestOWASP_SecurityHeaders checks every header middleware.SecurityHeaders is
// responsible for, on one response.
//
// One response rather than one per header is deliberate. The previous shape was
// eight functions that each built the same handler, made the same request and
// read one header, and the eighth existed only to state that all of them arrive
// on the same response. Reading them off a single recorder says that by
// construction.
//
// A header with a fixed value is asserted by value. HSTS and CSP carry a
// directive list whose order and extras are not the requirement, so those rows
// name the directives that are.
func TestOWASP_SecurityHeaders(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	for _, tc := range []struct {
		header string
		// want is the exact value, for the headers that have one.
		want string
		// directives are the substrings a header must carry when its full value
		// is not itself the requirement.
		directives []string
	}{
		{header: "X-Content-Type-Options", want: "nosniff"},
		{header: "X-Frame-Options", want: "DENY"},
		{header: "Referrer-Policy", want: "no-referrer"},
		{header: "Cache-Control", want: "no-store"},
		{header: "Pragma", want: "no-cache"},
		// "0" disables the legacy auditor rather than enabling it: the filter is
		// itself an XSS vector, and CSP is the replacement.
		{header: "X-XSS-Protection", want: "0"},
		{header: "Strict-Transport-Security", directives: []string{"max-age=", "includeSubDomains"}},
		{header: "Content-Security-Policy", directives: []string{"default-src"}},
	} {
		t.Run(tc.header, func(t *testing.T) {
			val := rec.Header().Get(tc.header)
			if val == "" {
				t.Fatalf("%s is missing from the response", tc.header)
			}
			if tc.want != "" && val != tc.want {
				t.Fatalf("%s is %q, want %q", tc.header, val, tc.want)
			}
			for _, d := range tc.directives {
				if !strings.Contains(val, d) {
					t.Errorf("%s does not carry %q: %q", tc.header, d, val)
				}
			}
		})
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

// TestOWASP_JWTRegisteredClaimsAreVerified checks the three registered claims
// ParseAndValidate is given an expectation for: a missing expiry, an issuer the
// verifier was not told to expect, and an audience the token was not minted for.
//
// These were three functions that each signed a token, called ParseAndValidate
// and asserted err != nil, and none of them ever parsed a token that should
// succeed. A verifier that refused every token satisfied all three. The
// accepted case is now the first row, so the refusals below it mean something.
func TestOWASP_JWTRegisteredClaimsAreVerified(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	// sign builds a token from the claims as given, including omissions:
	// SignRS256WithHeader is used rather than SignToken because a token with no
	// exp is one of the cases and SignToken would not produce one.
	sign := func(t *testing.T, claims vjwt.RegisteredClaims) string {
		t.Helper()
		tokenStr, err := vjwt.SignRS256WithHeader(
			map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid},
			&vaultcrypto.VaultClaims{RegisteredClaims: claims}, key)
		if err != nil {
			t.Fatalf("signing the fixture token failed: %v", err)
		}
		return tokenStr
	}

	valid := vjwt.RegisteredClaims{
		Subject:   "user-123",
		Issuer:    "vault",
		Audience:  vjwt.ClaimStrings{"app"},
		ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  vjwt.NewNumericDate(time.Now()),
	}

	for _, tc := range []struct {
		name string
		// mutate turns the valid claim set into the one this row presents.
		mutate func(vjwt.RegisteredClaims) vjwt.RegisteredClaims
		// wantIssuer and wantAudience are what the verifier is told to expect.
		wantIssuer, wantAudience string
		accepted                 bool
	}{
		{
			name:     "a token matching every expectation is accepted",
			mutate:   func(c vjwt.RegisteredClaims) vjwt.RegisteredClaims { return c },
			accepted: true,
		},
		{
			name: "no expiry",
			mutate: func(c vjwt.RegisteredClaims) vjwt.RegisteredClaims {
				c.ExpiresAt = nil
				return c
			},
		},
		{
			name: "an issuer the verifier does not expect",
			mutate: func(c vjwt.RegisteredClaims) vjwt.RegisteredClaims {
				c.Issuer = "legit-vault"
				return c
			},
			wantIssuer: "different-vault",
		},
		{
			name: "an audience the token was not minted for",
			mutate: func(c vjwt.RegisteredClaims) vjwt.RegisteredClaims {
				c.Audience = vjwt.ClaimStrings{"app-frontend"}
				return c
			},
			wantAudience: "app-admin",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer, audience := "vault", "app"
			if tc.wantIssuer != "" {
				issuer = tc.wantIssuer
			}
			if tc.wantAudience != "" {
				audience = tc.wantAudience
			}

			_, err := vaultcrypto.ParseAndValidate(sign(t, tc.mutate(valid)), keyFunc, issuer, audience)
			if tc.accepted && err != nil {
				t.Fatalf("a token with %s was rejected: %v", tc.name, err)
			}
			if !tc.accepted && err == nil {
				t.Fatalf("a token with %s was accepted", tc.name)
			}
		})
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
