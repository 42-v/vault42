package attack

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/middleware"
)

// TestRateLimitBypass_XForwardedForSpoofing verifies that rate limiting
// cannot be bypassed by manipulating the X-Forwarded-For header when the
// request does not come from a trusted proxy.
func TestRateLimitBypass_XForwardedForSpoofing(t *testing.T) {
	// Reset trusted proxies to empty (no trusted proxies)
	middleware.SetTrustedProxies(nil)

	mc := cache.NewMemoryCache()
	defer mc.Close()

	limit := 3
	cfg := middleware.RateLimitConfig{
		Window:  time.Minute,
		Limit:   limit,
		KeyFunc: middleware.LoginRateLimitKey,
	}

	handler := middleware.RateLimit(mc, cfg, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Simulate requests from the same IP, spoofing X-Forwarded-For each time
	spoofedIPs := []string{
		"10.0.0.1",
		"10.0.0.2",
		"172.16.0.1",
		"192.168.1.1",
		"8.8.8.8",
	}

	for i, spoofed := range spoofedIPs {
		req := httptest.NewRequest("POST", "/auth/login", nil)
		req.RemoteAddr = "203.0.113.50:12345" // actual client IP stays the same
		req.Header.Set("X-Forwarded-For", spoofed)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// After limit requests, should be rate limited regardless of spoofed XFF
		if i >= limit && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("Request %d with spoofed XFF %q should be rate limited (got %d)",
				i+1, spoofed, rec.Code)
		}
	}
}

// TestRateLimitBypass_IPRotation verifies that rate limits track per-IP
// and different IPs get independent rate limit buckets.
func TestRateLimitBypass_IPRotation(t *testing.T) {
	mc := cache.NewMemoryCache()
	defer mc.Close()

	middleware.SetTrustedProxies(nil)

	limit := 3
	cfg := middleware.RateLimitConfig{
		Window:  time.Minute,
		Limit:   limit,
		KeyFunc: middleware.LoginRateLimitKey,
	}

	handler := middleware.RateLimit(mc, cfg, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Different real IPs get separate rate limit windows
	ips := []string{
		"203.0.113.1:1234",
		"203.0.113.2:1234",
		"203.0.113.3:1234",
	}

	for _, ip := range ips {
		for i := 0; i < limit; i++ {
			req := httptest.NewRequest("POST", "/auth/login", nil)
			req.RemoteAddr = ip
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code == http.StatusTooManyRequests {
				t.Fatalf("IP %s should not be rate limited at request %d (limit=%d)",
					ip, i+1, limit)
			}
		}
	}
}

// TestRateLimitBypass_AccountLockoutPerUser attacks the two properties an
// attacker would test first: does locking one account lock another, and does
// rotating the source address buy unlimited guesses.
//
// The old body proved that a map keyed on user id returns different values for
// different keys, using a helper the binary never calls. It could not have seen
// the second question at all, because that helper had no notion of a source
// address — which is precisely where the bypass would be.
func TestRateLimitBypass_AccountLockoutPerUser(t *testing.T) {
	perSource := atkPerSourceLimit(t, atkSearchCeiling)

	const (
		userA      = "bypass-a@example.com"
		userB      = "bypass-b@example.com"
		attackerIP = "198.51.100.50"
	)
	a := newAtkLockout(t)
	a.account(userA)
	a.account(userB)

	for i := 0; i < perSource; i++ {
		a.guess(userA, attackerIP)
	}
	if a.canReach(t, userA, attackerIP) == atkAdmitted {
		t.Fatalf("%d wrong passwords did not lock %s to %s", perSource, userA, attackerIP)
	}
	if a.canReach(t, userB, attackerIP) != atkAdmitted {
		t.Errorf("locking %s also locked %s from the same address; the counter is not per-account", userA, userB)
	}

	// Rotation is the bypass this suite exists to try. Every attempt below comes
	// from an address that has never been seen before, so the per-address lock
	// can never engage — and yet the account must still stop answering, or the
	// only cost of unlimited guessing is a proxy list.
	const rotated = "bypass-rotate@example.com"
	r := newAtkLockout(t)
	r.account(rotated)
	locked := false
	const rotations = 100
	for n := 1; n <= rotations && !locked; n++ {
		r.guess(rotated, fmt.Sprintf("198.51.%d.%d", 200+n/250, n%250))
		switch r.canReach(t, rotated, fmt.Sprintf("203.0.%d.%d", 200+n/250, n%250)) {
		case atkAdmitted:
		case atkMasked:
			locked = true
			t.Logf("rotating the source address bought %d guesses before the account itself locked", n)
		case atkAddressLocked:
			t.Fatalf("the probing address was refused after %d rotations; it should have been fresh", n)
		}
	}
	if !locked {
		t.Errorf("%d failures from %d distinct addresses left the account open: rotating the source "+
			"address is a complete bypass of the lockout", rotations, rotations)
	}
}

// TestRateLimitBypass_MultipleXFFHeaders verifies that multiple
// X-Forwarded-For headers cannot be used to confuse IP extraction.
func TestRateLimitBypass_MultipleXFFHeaders(t *testing.T) {
	middleware.SetTrustedProxies(nil)

	tests := []struct {
		name     string
		xff      []string
		expected string
	}{
		{
			name:     "single_xff",
			xff:      []string{"10.0.0.1"},
			expected: "203.0.113.50", // untrusted proxy -> use RemoteAddr
		},
		{
			name:     "multiple_xff_values",
			xff:      []string{"10.0.0.1, 10.0.0.2, 10.0.0.3"},
			expected: "203.0.113.50",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "203.0.113.50:12345"
			for _, xff := range tc.xff {
				req.Header.Add("X-Forwarded-For", xff)
			}

			ip := middleware.ClientIP(req)
			if ip != tc.expected {
				t.Fatalf("Expected ClientIP=%q, got %q", tc.expected, ip)
			}
		})
	}
}

// TestRateLimitBypass_EmptyXFF verifies that empty X-Forwarded-For values
// cannot bypass rate limiting by causing empty IP resolution.
func TestRateLimitBypass_EmptyXFF(t *testing.T) {
	middleware.SetTrustedProxies(nil)

	cases := []string{
		"",
		"   ",
		",,,",
		", , ,",
	}

	for _, xff := range cases {
		t.Run("xff="+xff, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "198.51.100.1:8080"
			if xff != "" {
				req.Header.Set("X-Forwarded-For", xff)
			}

			ip := middleware.ClientIP(req)
			if ip == "" {
				t.Fatal("ClientIP should never return empty string")
			}
		})
	}
}

// TestRateLimitBypass_IPv6Variations verifies that IPv6 address variations
// (full, compressed, mapped) are handled consistently for rate limiting.
func TestRateLimitBypass_IPv6Variations(t *testing.T) {
	middleware.SetTrustedProxies(nil)

	// These represent the same conceptual client in different formats
	addrs := []struct {
		name       string
		remoteAddr string
	}{
		{"ipv6_full", "[2001:0db8:0000:0000:0000:0000:0000:0001]:1234"},
		{"ipv6_loopback", "[::1]:1234"},
		{"ipv4_mapped_ipv6", "[::ffff:192.0.2.1]:1234"},
		{"ipv4_plain", "192.0.2.1:1234"},
	}

	for _, tc := range addrs {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remoteAddr

			ip := middleware.ClientIP(req)
			if ip == "" {
				t.Fatalf("ClientIP returned empty for %s (%s)", tc.name, tc.remoteAddr)
			}
		})
	}
}

// TestRateLimitBypass_AccountLockoutThresholdExact attacks the boundary from the
// two independent routes the code can take to it, and requires them to agree.
//
// The limit is enforced from a cache counter when the cache can answer, and from
// the durable failed_login_count column when it cannot. Those are different
// reads, different comparisons, and different code. If they disagree, the number
// of guesses an attacker gets changes with the health of a component they can
// often influence and can always wait for — and it changes silently, because
// both paths answer with the same masked error.
//
// This also pins the boundary itself without hardcoding it. The old body swept
// six invented thresholds — 1, 3, 5, 10, 50, 100 — through a helper that took
// the threshold as an argument, so what it asserted was that a comparison
// operator compares. An off-by-one in the shipped code, which takes its
// threshold from nobody, was invisible to it. An off-by-one on either path here
// shows up as a disagreement.
func TestRateLimitBypass_AccountLockoutThresholdExact(t *testing.T) {
	cached := atkPerSourceLimit(t, atkSearchCeiling)
	// The durable search is quadratic in the answer, so it is bounded relative to
	// the number the cache path already produced. A durable limit past that
	// bound is a disagreement too, and is reported as one.
	durable := atkDurableLimit(t, 2*cached+5)

	if cached != durable {
		t.Fatalf("the account locks after %d failures when the cache answers and after %d when it "+
			"cannot. The number of guesses on offer changes with the health of a component an "+
			"attacker can wait for, and nothing in the response says which limit is in force.",
			cached, durable)
	}
	if cached < 2 {
		t.Fatalf("measured a limit of %d; there is no boundary to pin", cached)
	}
	t.Logf("boundary agrees at %d consecutive failures on both the cache and the durable path", cached)

	const (
		email      = "boundary@example.com"
		attackerIP = "198.51.100.60"
	)

	// One short of the limit, the correct password still works. A control that
	// locks early is a denial of service against the account owner.
	below := newAtkLockout(t)
	below.account(email)
	for i := 0; i < cached-1; i++ {
		below.guess(email, attackerIP)
	}
	if below.canReach(t, email, attackerIP) != atkAdmitted {
		t.Errorf("locked at %d failures, one short of the measured limit of %d: an account is denied "+
			"before its owner has spent the attempts they are allowed", cached-1, cached)
	}

	// At the limit, it does not.
	at := newAtkLockout(t)
	at.account(email)
	for i := 0; i < cached; i++ {
		at.guess(email, attackerIP)
	}
	if at.canReach(t, email, attackerIP) == atkAdmitted {
		t.Errorf("still open at %d failures, the measured limit: the attacker gets one more guess "+
			"than the limit claims", cached)
	}
}
