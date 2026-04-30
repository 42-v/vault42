package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
)

func TestRateLimitAllows(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	handler := RateLimit(c, RateLimitConfig{
		Limit: 5, Window: time.Minute,
		KeyFunc: IPRateLimitKey,
	}, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First 5 requests should pass
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want 200", i+1, rec.Code)
		}
	}
}

func TestRateLimitBlocks(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	handler := RateLimit(c, RateLimitConfig{
		Limit: 3, Window: time.Minute,
		KeyFunc: IPRateLimitKey,
	}, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust limit
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// Next request should be blocked
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("over-limit request: status = %d, want 429", rec.Code)
	}

	// Check headers
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header should be set")
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("X-RateLimit-Remaining = %q, want 0", rec.Header().Get("X-RateLimit-Remaining"))
	}
}

func TestRateLimitDisabled(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	handler := RateLimit(c, RateLimitConfig{
		Limit: 1, Window: time.Minute,
		KeyFunc: IPRateLimitKey,
	}, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Even over limit, should pass when disabled
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("disabled rate limit should not block: status = %d", rec.Code)
		}
	}
}

func TestRateLimitDifferentIPs(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	handler := RateLimit(c, RateLimitConfig{
		Limit: 1, Window: time.Minute,
		KeyFunc: IPRateLimitKey,
	}, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// IP1 uses its limit
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "1.1.1.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Error("first IP should pass")
	}

	// IP2 should still have its own limit
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "2.2.2.2:5678"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Error("different IP should have its own limit")
	}
}
