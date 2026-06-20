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

// When the direct connection is from a trusted proxy and every entry in
// X-Forwarded-For is itself a trusted proxy, ClientIP has no untrusted client
// to attribute. If the leftmost XFF entry is blank, it cannot be used as the
// origin either, so ClientIP falls back to the direct RemoteAddr rather than
// returning an empty or attacker-influenced value.
func TestClientIP_AllTrustedXFFBlankLeftmostFallsBackToRemote(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	// First entry is whitespace-only (blank after trim); the remaining entry is
	// a trusted proxy. No untrusted client and no usable leftmost value.
	req.Header.Set("X-Forwarded-For", " , 10.0.0.1")

	if got := ClientIP(req); got != "10.0.0.5" {
		t.Fatalf("expected fallback to RemoteAddr 10.0.0.5, got %q", got)
	}
}

// CheckAccountLockout must fail open: when the cache backend errors while
// incrementing the failed-attempt counter, it reports "not locked" with a nil
// error so a cache outage can never block authentication.
func TestCheckAccountLockout_CacheErrorFailsOpen(t *testing.T) {
	c := &mocks.MockCache{
		IncrementFn: func(_ context.Context, _ string, _ time.Duration) (int64, error) {
			return 0, errors.New("cache unavailable")
		},
	}

	locked, err := CheckAccountLockout(context.Background(), c, "test-user", 1, time.Minute)
	if err != nil {
		t.Fatalf("cache error must fail open with nil error, got %v", err)
	}
	if locked {
		t.Fatal("cache error must report not-locked (fail open)")
	}
}
