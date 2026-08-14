package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/ipintel"
)

// =============================================================================
// VPN / anonymiser rate-limit scrutiny.
//
// An IP that ipintel flags as anonymising or hosting infrastructure consumes a
// credential-guessing bucket faster (heavier weight), so it meets the ordinary
// 429 sooner. It is NEVER hard-blocked: the outcome is always the standard
// 429 rate_limit_exceeded that any caller can hit, never a 403. Default weight
// (nil, or ipintel absent) leaves the limiter's behavior unchanged.
// =============================================================================

// vpnTestIPIntel: 198.51.100.0/24 is hosting (=> IsAnonymous); 203.0.113.0/24 is
// a clean, country-only block.
func vpnTestIPIntel(t *testing.T) *ipintel.DB {
	t.Helper()
	addr := func(s string) netip.Addr {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parse %s: %v", s, err)
		}
		return a
	}
	blob := ipintel.Marshal([]ipintel.Range{
		{Lo: addr("198.51.100.0"), Hi: addr("198.51.100.255"), CC: "US", Hosting: true},
		{Lo: addr("203.0.113.0"), Hi: addr("203.0.113.255"), CC: "DE"},
	})
	db, err := ipintel.Load(blob)
	if err != nil {
		t.Fatalf("load ipintel: %v", err)
	}
	return db
}

func TestIPIntelWeight_FlagsAnonymousHeavierCleanUnchanged(t *testing.T) {
	db := vpnTestIPIntel(t)
	weigh := IPIntelWeight(db, 3)
	if weigh == nil {
		t.Fatal("IPIntelWeight returned nil for a present db and heavy>1")
	}

	req := func(remote string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		r.RemoteAddr = remote
		return r
	}

	if got := weigh(req("198.51.100.10:1111")); got != 3 {
		t.Errorf("hosting IP weight = %d, want 3", got)
	}
	if got := weigh(req("203.0.113.10:2222")); got != 1 {
		t.Errorf("clean IP weight = %d, want 1", got)
	}
	// Unknown / private addresses fail open to weight 1.
	if got := weigh(req("10.0.0.5:3333")); got != 1 {
		t.Errorf("private IP weight = %d, want 1", got)
	}
}

func TestIPIntelWeight_NilWhenDisabled(t *testing.T) {
	if IPIntelWeight(nil, 3) != nil {
		t.Error("IPIntelWeight(nil, 3) should be nil (ipintel absent => feature off)")
	}
	if IPIntelWeight(vpnTestIPIntel(t), 1) != nil {
		t.Error("IPIntelWeight(db, 1) should be nil (weight of 1 cannot widen a bucket)")
	}
}

// serveN drives n sequential requests from one remote address through the
// limiter and returns the status codes in order.
func serveN(t *testing.T, mw func(http.Handler) http.Handler, remote string, n int) []int {
	t.Helper()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := mw(ok)
	codes := make([]int, 0, n)
	for i := 0; i < n; i++ {
		r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		r.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		codes = append(codes, rec.Code)
	}
	return codes
}

func TestRateLimit_VPNScrutinyIsTighterButNeverBlocks(t *testing.T) {
	db := vpnTestIPIntel(t)
	c := cache.NewMemoryCache()
	t.Cleanup(func() { _ = c.Close() })

	// Limit 5 per window; a flagged IP weighs 3, so it trips on the 2nd request
	// (2*3=6 > 5) while a clean IP gets all 5 through before the 6th trips.
	mw := RateLimit(c, RateLimitConfig{
		Limit: 5, Window: time.Minute, KeyFunc: IPRateLimitKey, Weight: IPIntelWeight(db, 3),
	}, true)

	hosting := serveN(t, mw, "198.51.100.10:1000", 3)
	// First request from a VPN is still allowed — scrutiny, not denial.
	if hosting[0] != http.StatusOK {
		t.Errorf("VPN first request = %d, want 200 (must not be blocked outright)", hosting[0])
	}
	if hosting[1] != http.StatusTooManyRequests {
		t.Errorf("VPN second request = %d, want 429 (tighter bucket)", hosting[1])
	}
	// The refusal is the ordinary rate-limit 429, never a 403 hard block.
	for i, code := range hosting {
		if code == http.StatusForbidden {
			t.Errorf("VPN request %d returned 403; a VPN must never be hard-blocked here", i)
		}
	}

	clean := serveN(t, mw, "203.0.113.10:2000", 6)
	for i := 0; i < 5; i++ {
		if clean[i] != http.StatusOK {
			t.Errorf("clean request %d = %d, want 200 (full budget)", i, clean[i])
		}
	}
	if clean[5] != http.StatusTooManyRequests {
		t.Errorf("clean request 6 = %d, want 429", clean[5])
	}
}

// TestRateLimit_DefaultWeightUnchanged pins that a nil Weight leaves the limiter
// exactly as it was: 5 through, 429 on the 6th, for any IP.
func TestRateLimit_DefaultWeightUnchanged(t *testing.T) {
	c := cache.NewMemoryCache()
	t.Cleanup(func() { _ = c.Close() })
	mw := RateLimit(c, RateLimitConfig{
		Limit: 5, Window: time.Minute, KeyFunc: IPRateLimitKey,
	}, true)

	codes := serveN(t, mw, "198.51.100.10:1000", 6)
	for i := 0; i < 5; i++ {
		if codes[i] != http.StatusOK {
			t.Errorf("request %d = %d, want 200", i, codes[i])
		}
	}
	if codes[5] != http.StatusTooManyRequests {
		t.Errorf("request 6 = %d, want 429", codes[5])
	}
}
