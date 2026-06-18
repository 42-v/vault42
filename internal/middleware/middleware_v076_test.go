package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// DPoP: JTI replay prevention and thumbprint matching branches
// ---------------------------------------------------------------------------

func TestDPoPJTIReplayRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proof := makeDPoPProofForTest(t, key, "GET", "https://vault.test/user/profile")

	// SetIfNotExists returns false → JTI already seen → reuse.
	c := &mocks.MockCache{
		SetIfNotExistsFn: func(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
			return false, nil
		},
	}
	handler := DPoP(c, "https://vault.test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called for replayed DPoP JTI")
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Host = "vault.test"
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for replayed JTI, got %d", rec.Code)
	}
}

func TestDPoPJTIFreshAllowed(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proof := makeDPoPProofForTest(t, key, "GET", "https://vault.test/user/profile")

	c := &mocks.MockCache{
		SetIfNotExistsFn: func(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
			return true, nil // first use
		},
	}
	called := false
	handler := DPoP(c, "https://vault.test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Host = "vault.test"
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("handler should be called for a fresh (non-replayed) DPoP JTI")
	}
}

func TestDPoPCacheErrorNotBoundAllowed(t *testing.T) {
	// Cache error + token NOT DPoP-bound → fail open (request proceeds).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proof := makeDPoPProofForTest(t, key, "GET", "https://vault.test/user/profile")

	c := &mocks.MockCache{
		SetIfNotExistsFn: func(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
			return false, errors.New("cache down")
		},
	}
	called := false
	handler := DPoP(c, "https://vault.test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Host = "vault.test"
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("handler should proceed on cache error when token is not DPoP-bound")
	}
}

func TestDPoPCacheErrorBoundFailsClosed(t *testing.T) {
	// Cache error + token IS DPoP-bound (cnf.jkt set) → fail closed (503).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proof := makeDPoPProofForTest(t, key, "GET", "https://vault.test/user/profile")

	c := &mocks.MockCache{
		SetIfNotExistsFn: func(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
			return false, errors.New("cache down")
		},
	}
	handler := DPoP(c, "https://vault.test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called when replay check fails closed")
	}))

	claims := &vaultcrypto.VaultClaims{
		Confirmation: &vaultcrypto.Confirmation{JKT: "some-bound-thumbprint"},
	}
	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Host = "vault.test"
	req.Header.Set("DPoP", proof)
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 fail-closed for DPoP-bound token on cache error, got %d", rec.Code)
	}
}

func TestDPoPNilCacheBoundFailsClosed(t *testing.T) {
	// nil cache + DPoP-bound token → replay check unavailable → 503.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proof := makeDPoPProofForTest(t, key, "GET", "https://vault.test/user/profile")

	handler := DPoP(nil, "https://vault.test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called with nil cache and DPoP-bound token")
	}))

	claims := &vaultcrypto.VaultClaims{
		Confirmation: &vaultcrypto.Confirmation{JKT: "bound-thumbprint"},
	}
	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Host = "vault.test"
	req.Header.Set("DPoP", proof)
	req = req.WithContext(context.WithValue(req.Context(), ClaimsKey, claims))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 with nil cache and DPoP-bound token, got %d", rec.Code)
	}
}

func TestDPoPThumbprintMismatchRejected(t *testing.T) {
	// Valid proof, fresh JTI, but cnf.jkt doesn't match the proof's thumbprint.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proof := makeDPoPProofForTest(t, key, "GET", "https://vault.test/user/profile")

	c := &mocks.MockCache{
		SetIfNotExistsFn: func(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
			return true, nil
		},
	}
	handler := DPoP(c, "https://vault.test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called on thumbprint mismatch")
	}))

	claims := &vaultcrypto.VaultClaims{
		Confirmation: &vaultcrypto.Confirmation{JKT: "definitely-not-the-real-thumbprint"},
	}
	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Host = "vault.test"
	req.Header.Set("DPoP", proof)
	req = req.WithContext(context.WithValue(req.Context(), ClaimsKey, claims))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 on DPoP thumbprint mismatch, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// localRateLimiter.increment + addLimiter
// ---------------------------------------------------------------------------

func TestLocalRateLimiterIncrement(t *testing.T) {
	l := &localRateLimiter{entries: make(map[string]*localRLEntry)}

	// First two increments within the window accumulate.
	if got := l.increment("k1", time.Minute); got != 1 {
		t.Fatalf("first increment = %d, want 1", got)
	}
	if got := l.increment("k1", time.Minute); got != 2 {
		t.Fatalf("second increment = %d, want 2", got)
	}

	// A different key has its own independent counter.
	if got := l.increment("k2", time.Minute); got != 1 {
		t.Fatalf("independent key increment = %d, want 1", got)
	}
}

func TestLocalRateLimiterIncrementWindowReset(t *testing.T) {
	l := &localRateLimiter{entries: make(map[string]*localRLEntry)}

	// A zero-duration window means the entry is immediately expired, so the next
	// increment resets the counter to 1 rather than accumulating.
	if got := l.increment("k", 0); got != 1 {
		t.Fatalf("first increment = %d, want 1", got)
	}
	if got := l.increment("k", time.Minute); got != 1 {
		t.Fatalf("post-expiry increment = %d, want 1 (window reset)", got)
	}
}

func TestAddLimiterRegisters(t *testing.T) {
	before := func() int {
		activeLimiters.mu.Lock()
		defer activeLimiters.mu.Unlock()
		return len(activeLimiters.limiters)
	}()

	l := &localRateLimiter{entries: make(map[string]*localRLEntry)}
	addLimiter(l)

	after := func() int {
		activeLimiters.mu.Lock()
		defer activeLimiters.mu.Unlock()
		return len(activeLimiters.limiters)
	}()

	if after != before+1 {
		t.Fatalf("addLimiter should register one limiter: before=%d after=%d", before, after)
	}
}

// ---------------------------------------------------------------------------
// RateLimit middleware: cache-error fallback to in-memory increment + 429
// ---------------------------------------------------------------------------

func TestRateLimitCacheErrorFallbackEnforced(t *testing.T) {
	// Cache.Increment always errors → middleware falls back to the in-memory
	// counter via local.increment. With Limit=1, the second request exceeds it.
	c := &mocks.MockCache{
		IncrementFn: func(ctx context.Context, key string, ttl time.Duration) (int64, error) {
			return 0, errors.New("cache unavailable")
		},
	}
	cfg := RateLimitConfig{
		Limit:   1,
		Window:  time.Minute,
		KeyFunc: func(r *http.Request) string { return "fixed-key" },
	}
	mw := RateLimit(c, cfg, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	mw.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", first.Code)
	}

	second := httptest.NewRecorder()
	mw.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: expected 429 via in-memory fallback, got %d", second.Code)
	}
	if second.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on rate-limit rejection")
	}
}

func TestRateLimitDisabledPassesThrough(t *testing.T) {
	cfg := RateLimitConfig{
		Limit:   0,
		Window:  time.Minute,
		KeyFunc: func(r *http.Request) string { return "k" },
	}
	called := false
	mw := RateLimit(&mocks.MockCache{}, cfg, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if !called {
		t.Error("disabled rate limiter should pass requests straight through")
	}
}
