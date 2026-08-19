package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
)

// The weighting exists to make a flagged address burn its budget faster without
// ever telling it that it is flagged. X-RateLimit-Remaining reported the weighted
// figure, which handed that classification back in the response to a single
// unauthenticated request: an attacker sorts a proxy pool one probe per address
// and runs the whole credential-stuffing attempt through the addresses vault42
// would not have weighted.
//
// The remaining count is therefore the unweighted one for both callers, and both
// advertise 0 once the bucket is spent, so the only thing still separating them
// is when the 429 arrives — which no header can hide.
func TestTheRemainingHeaderDoesNotLeakTheScrutinyWeight(t *testing.T) {
	weightedRemaining := func(t *testing.T, weight int) string {
		t.Helper()
		memCache := cache.NewMemoryCache()
		t.Cleanup(func() { _ = memCache.Close() })

		h := RateLimit(memCache, RateLimitConfig{
			Name: "probe", Limit: 5, Window: time.Minute,
			KeyFunc: func(*http.Request) string { return "probe-key" },
			Weight:  func(*http.Request) int { return weight },
		}, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/login", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("first request status = %d, want 200", rec.Code)
		}
		return rec.Header().Get("X-RateLimit-Remaining")
	}

	flagged := weightedRemaining(t, 3)
	plain := weightedRemaining(t, 1)
	if flagged != plain {
		t.Errorf("X-RateLimit-Remaining is %q for a weighted caller and %q for an unweighted one, "+
			"so one request reads back the ipintel classification", flagged, plain)
	}
	if plain != "4" {
		t.Errorf("X-RateLimit-Remaining = %q after one request against a limit of 5, want \"4\"", plain)
	}
}

// The bucket a weighted caller has spent must advertise 0 like any other spent
// bucket. Reporting the unweighted figure alongside a 429 would put the same bit
// back on the wire from the other direction.
func TestASpentBucketAdvertisesZeroForAWeightedCaller(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	h := RateLimit(memCache, RateLimitConfig{
		Name: "spent", Limit: 5, Window: time.Minute,
		KeyFunc: func(*http.Request) string { return "spent-key" },
		Weight:  func(*http.Request) int { return 3 },
	}, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	var last *httptest.ResponseRecorder
	for range 3 {
		last = httptest.NewRecorder()
		h.ServeHTTP(last, httptest.NewRequest(http.MethodPost, "/auth/login", nil))
	}

	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d after 3 requests at weight 3 against a limit of 5, want 429", last.Code)
	}
	if got := last.Header().Get("X-RateLimit-Remaining"); got != "0" {
		t.Errorf("a spent bucket advertised %q remaining alongside its 429, want \"0\"", got)
	}
}
