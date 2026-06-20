package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/tests/mocks"
)

// L4: when the cache errors, a FailClosed limiter returns 503 (no per-pod
// in-memory fallback that would multiply the limit across replicas), while a
// default limiter degrades gracefully (still serves the request).
func TestRateLimit_FailClosedOnCacheError(t *testing.T) {
	errCache := &mocks.MockCache{
		IncrementFn: func(_ context.Context, _ string, _ time.Duration) (int64, error) {
			return 0, errors.New("cache down")
		},
	}
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

	t.Run("fail closed -> 503", func(t *testing.T) {
		h := RateLimit(errCache, RateLimitConfig{
			Limit: 5, Window: time.Minute, KeyFunc: IPRateLimitKey, FailClosed: true,
		}, true)(http.HandlerFunc(ok))
		req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		req.RemoteAddr = "1.2.3.4:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("fail-closed should be 503 on cache error, got %d", rec.Code)
		}
	})

	t.Run("default degrades gracefully -> 200", func(t *testing.T) {
		h := RateLimit(errCache, RateLimitConfig{
			Limit: 5, Window: time.Minute, KeyFunc: IPRateLimitKey,
		}, true)(http.HandlerFunc(ok))
		req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		req.RemoteAddr = "1.2.3.4:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("default limiter should fall back and serve, got %d", rec.Code)
		}
	})
}
