package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// ===========================================================================
// Auth middleware — malformed Authorization header edge cases
// ===========================================================================

// TestAuth_MalformedAuthorizationHeaders tests various malformed Authorization
// header values that should all result in rejection.
func TestAuth_MalformedAuthorizationHeaders(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb1100-2233"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name       string
		authHeader string
		wantStatus int
		wantError  string
	}{
		// Missing authorization
		{"empty_header", "", http.StatusUnauthorized, "missing_authorization"},

		// Invalid scheme (single word, no space)
		{"bearer_no_space_no_token", "Bearer", http.StatusUnauthorized, "invalid_authorization"},
		{"single_word", "token-value-here", http.StatusUnauthorized, "invalid_authorization"},

		// Wrong scheme with valid structure
		{"basic_scheme", "Basic dXNlcjpwYXNz", http.StatusUnauthorized, "invalid_authorization"},
		{"digest_scheme", "Digest username=test", http.StatusUnauthorized, "invalid_authorization"},
		{"token_scheme", "Token abc123", http.StatusUnauthorized, "invalid_authorization"},
		{"negotiate_scheme", "Negotiate base64data", http.StatusUnauthorized, "invalid_authorization"},

		// Case sensitivity — only "Bearer" and "DPoP" are accepted
		{"lowercase_bearer", "bearer valid-token", http.StatusUnauthorized, "invalid_authorization"},
		{"uppercase_bearer", "BEARER valid-token", http.StatusUnauthorized, "invalid_authorization"},
		{"mixed_case_bearer", "BeArEr valid-token", http.StatusUnauthorized, "invalid_authorization"},
		{"lowercase_dpop", "dpop valid-token", http.StatusUnauthorized, "invalid_authorization"},
		{"uppercase_dpop", "DPOP valid-token", http.StatusUnauthorized, "invalid_authorization"},

		// Whitespace variations
		{"tab_separated", "Bearer\ttoken", http.StatusUnauthorized, "invalid_authorization"},
		{"multiple_spaces", "Bearer  token", http.StatusUnauthorized, "invalid_token"},
		{"leading_space", " Bearer token", http.StatusUnauthorized, "invalid_authorization"},

		// Garbage tokens (valid scheme, invalid JWT)
		{"bearer_empty_token", "Bearer ", http.StatusUnauthorized, "invalid_token"},
		{"bearer_single_char", "Bearer x", http.StatusUnauthorized, "invalid_token"},
		{"bearer_null_byte", "Bearer \x00", http.StatusUnauthorized, "invalid_token"},
		{"dpop_garbage", "DPoP not-a-jwt", http.StatusUnauthorized, "invalid_token"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			body := strings.TrimSpace(rec.Body.String())
			if !strings.Contains(body, tc.wantError) {
				t.Errorf("body = %q, want error containing %q", body, tc.wantError)
			}
		})
	}
}

// TestAuth_OversizedJWTInHeader tests that an oversized JWT in the Authorization
// header is rejected (>8KB).
func TestAuth_OversizedJWTInHeader(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb1111-4455"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create a token string larger than 8KB
	oversizedToken := strings.Repeat("A", 9000)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+oversizedToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for oversized token", rec.Code)
	}
}

// TestAuthChallenge_Accepts2FAToken tests that AuthChallenge middleware accepts
// tokens with token_type=2fa_challenge.
func TestAuthChallenge_Accepts2FAToken(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb1122-5566"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := AuthChallenge(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  vjwt.ClaimStrings{"test-audience"},
			Subject:   "user-2fa",
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(time.Now()),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
			ID:        "challenge-jti",
		},
		TokenType: "2fa_challenge",
	}
	tokenStr, err := vaultcrypto.SignToken(claims, key, kid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/2fa/verify", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for 2fa_challenge token on AuthChallenge", rec.Code)
	}
}

// TestAuthChallenge_RejectsUnknownTokenType tests that AuthChallenge rejects
// tokens with arbitrary token types.
func TestAuthChallenge_RejectsUnknownTokenType(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb1133-6677"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := AuthChallenge(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  vjwt.ClaimStrings{"test-audience"},
			Subject:   "user-unknown",
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(time.Now()),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
			ID:        "unknown-jti",
		},
		TokenType: "refresh_token",
	}
	tokenStr, err := vaultcrypto.SignToken(claims, key, kid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/2fa/verify", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for unknown token type", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid_token_type") {
		t.Errorf("body = %q, want invalid_token_type error", rec.Body.String())
	}
}

// TestAuth_NilKeyMap tests that nil key map returns invalid_token (not panic).
func TestAuth_NilKeyMap(t *testing.T) {
	handler := Auth(nil, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenStr := signTestToken(t, key, "aabb2200-1122", "test-issuer", "test-audience", "user-nil", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for nil key map", rec.Code)
	}
}

// ===========================================================================
// Rate limiter edge cases
// ===========================================================================

// TestRateLimit_CacheFailureGracefulDegradation tests that when the cache
// returns an error, the rate limiter allows the request through.
func TestRateLimit_CacheFailureGracefulDegradation(t *testing.T) {
	c := cache.NewMemoryCache()
	c.Close() // Close immediately to put cache in closed state

	var called bool
	handler := RateLimit(c, RateLimitConfig{
		Limit:   1,
		Window:  time.Minute,
		KeyFunc: IPRateLimitKey,
	}, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/endpoint", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// When cache fails, rate limiter should allow the request (graceful degradation)
	if !called {
		t.Error("handler should be called when cache fails (graceful degradation)")
	}
}

// TestRateLimit_RateLimitHeaders tests that rate limit headers are set correctly.
func TestRateLimit_RateLimitHeaders(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	handler := RateLimit(c, RateLimitConfig{
		Limit:   10,
		Window:  time.Minute,
		KeyFunc: IPRateLimitKey,
	}, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.RemoteAddr = "10.10.10.10:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	limit := rec.Header().Get("X-RateLimit-Limit")
	if limit != "10" {
		t.Errorf("X-RateLimit-Limit = %q, want 10", limit)
	}

	remaining := rec.Header().Get("X-RateLimit-Remaining")
	if remaining != "9" {
		t.Errorf("X-RateLimit-Remaining = %q, want 9", remaining)
	}

	reset := rec.Header().Get("X-RateLimit-Reset")
	if reset == "" {
		t.Error("X-RateLimit-Reset should be set")
	}
}

// TestRateLimit_ZeroLimit tests behavior with a zero limit (all requests blocked).
func TestRateLimit_ZeroLimit(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	handler := RateLimit(c, RateLimitConfig{
		Limit:   0,
		Window:  time.Minute,
		KeyFunc: IPRateLimitKey,
	}, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "5.5.5.5:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 for zero limit", rec.Code)
	}
}

// TestRateLimit_CustomKeyFunc tests rate limiting with a custom key function.
func TestRateLimit_CustomKeyFunc(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	// Custom key func that uses a fixed key (all requests share the same bucket)
	fixedKeyFunc := func(r *http.Request) string {
		return "global-bucket"
	}

	handler := RateLimit(c, RateLimitConfig{
		Limit:   2,
		Window:  time.Minute,
		KeyFunc: fixedKeyFunc,
	}, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First two requests pass
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rec.Code)
		}
	}

	// Third request from different IP should also be blocked (shared bucket)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "9.8.7.6:5678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 for shared bucket", rec.Code)
	}
}

// ===========================================================================
// CORS middleware edge cases
// ===========================================================================

// TestCORS_NoOriginHeader_FixedMode tests fixed CORS mode with no Origin header.
func TestCORS_NoOriginHeader_FixedMode(t *testing.T) {
	handler := CORS("https://vault.example.com", nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	// No Origin header
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	// Should still set the configured origin
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://vault.example.com" {
		t.Errorf("origin = %q, want https://vault.example.com", got)
	}
}

// TestCORS_PostRequestWithOrigin tests that POST requests get CORS headers.
func TestCORS_PostRequestWithOrigin(t *testing.T) {
	handler := CORS("https://vault.example.com", nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req.Header.Set("Origin", "https://vault.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://vault.example.com" {
		t.Errorf("origin = %q, want https://vault.example.com", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("credentials = %q, want true", got)
	}
}

// TestCORS_AllowAll_EmptyOriginHeader tests allow-all mode when Origin header
// is explicitly set to empty string (versus not set at all).
func TestCORS_AllowAll_EmptyOriginHeader(t *testing.T) {
	handler := CORS("", nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Empty origin header (r.Header.Get returns "") should fall back to "*"
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("origin = %q, want * for empty Origin header in allow-all mode", got)
	}
}

// ===========================================================================
// Fingerprint middleware additional edge cases
// ===========================================================================

// TestFingerprint_NilClaimsPointerInContext tests Fingerprint middleware when
// a nil *VaultClaims is stored in context.
func TestFingerprint_NilClaimsPointerInContext(t *testing.T) {
	var called bool
	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	// Store nil pointer of correct type in context
	var nilClaims *vaultcrypto.VaultClaims
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	ctx := context.WithValue(req.Context(), ClaimsKey, nilClaims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (nil claims should skip fingerprint)", rec.Code)
	}
	if !called {
		t.Error("handler should be called when claims pointer is nil")
	}
}

// TestFingerprint_ConcurrentRequests tests that the fingerprint middleware is
// safe for concurrent use.
func TestFingerprint_ConcurrentRequests(t *testing.T) {
	ip := "10.20.30.40"
	ua := "ConcurrentAgent/1.0"
	lang := "en-US"

	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             ip,
		UserAgent:      ua,
		AcceptLanguage: lang,
	})

	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
			req := httptest.NewRequest(http.MethodGet, "/resource", nil)
			req.RemoteAddr = ip + ":12345"
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Accept-Language", lang)
			ctx := context.WithValue(req.Context(), ClaimsKey, claims)
			req = req.WithContext(ctx)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			done <- rec.Code == http.StatusOK
		}()
	}

	for i := 0; i < 10; i++ {
		if ok := <-done; !ok {
			t.Fatalf("concurrent request %d failed", i)
		}
	}
}

// ===========================================================================
// Confirmed middleware edge cases
// ===========================================================================

// TestConfirmed_NoClaims tests Confirmed middleware without auth context.
func TestConfirmed_NoClaims(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	handler := Confirmed(c)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for missing claims", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unauthorized") {
		t.Errorf("body = %q, want unauthorized error", rec.Body.String())
	}
}

// TestConfirmed_NoConfirmation tests Confirmed middleware when user hasn't confirmed.
func TestConfirmed_NoConfirmation(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	handler := Confirmed(c)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: "user-no-confirm"},
	}
	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 when not confirmed", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "requires_confirmation") {
		t.Errorf("body = %q, want requires_confirmation error", rec.Body.String())
	}
}

// TestConfirmed_WithConfirmation tests Confirmed middleware when user has confirmed.
func TestConfirmed_WithConfirmation(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	// Per-A-8 layout: key is per-user, value is the JTI of the confirming token.
	c.Set(context.Background(), "confirm:user-confirmed", "jwt-123", 5*time.Minute)

	var called bool
	handler := Confirmed(c)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: "user-confirmed", ID: "jwt-123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when confirmed", rec.Code)
	}
	if !called {
		t.Error("handler should be called when user is confirmed")
	}
}

// ===========================================================================
// IsAccountLocked / RecordFailedAttempt edge cases
// ===========================================================================

// TestIsAccountLocked_NoFailures tests that a fresh user is not locked.
func TestIsAccountLocked_NoFailures(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	locked, err := IsAccountLocked(context.Background(), c, "fresh-user", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if locked {
		t.Error("fresh user should not be locked")
	}
}

// TestRecordFailedAttempt_ThenCheck tests recording failures and checking lockout.
func TestRecordFailedAttempt_ThenCheck(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	ctx := context.Background()
	userID := "lockout-test-user"

	// Record 5 failures (threshold is 5, so count must exceed)
	for i := 0; i < 5; i++ {
		RecordFailedAttempt(ctx, c, userID, time.Minute)
	}

	// At exactly 5 failures, should NOT be locked (count > threshold, not >=)
	locked, err := IsAccountLocked(ctx, c, userID, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if locked {
		t.Error("should not be locked at exactly threshold")
	}

	// One more failure should trigger lockout
	RecordFailedAttempt(ctx, c, userID, time.Minute)
	locked, err = IsAccountLocked(ctx, c, userID, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !locked {
		t.Error("should be locked after exceeding threshold")
	}
}

// ===========================================================================
// ClientIP edge cases
// ===========================================================================

// TestClientIP_XFFWithGarbage tests ClientIP with garbage in X-Forwarded-For.
func TestClientIP_XFFWithGarbage(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "not-a-valid-ip")

	ip := ClientIP(req)
	// "not-a-valid-ip" is not an IP, so it is discarded rather than returned as
	// the rightmost non-trusted entry: RemoteAddr is the fallback.
	if ip != "10.0.0.1" {
		t.Errorf("ClientIP with garbage XFF = %q, want %q", ip, "10.0.0.1")
	}
}

// TestClientIP_EmptyRemoteAddr tests ClientIP with empty RemoteAddr.
func TestClientIP_EmptyRemoteAddr(t *testing.T) {
	SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ""

	ip := ClientIP(req)
	if ip != "" {
		t.Errorf("ClientIP with empty RemoteAddr = %q, want empty", ip)
	}
}

// TestClientIP_UntrustedProxyDoesNotTrustXFF tests that when the direct
// connection is not from a trusted proxy, XFF is completely ignored.
func TestClientIP_UntrustedProxyDoesNotTrustXFF(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.50:1234" // Not trusted
	req.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")

	ip := ClientIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("ClientIP = %q, want 203.0.113.50 (should ignore XFF from untrusted source)", ip)
	}
}
