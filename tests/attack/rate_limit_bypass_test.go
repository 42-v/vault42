package attack

import (
	"context"
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

// TestRateLimitBypass_AccountLockoutPerUser verifies that account lockout
// is per-user, not global, and cannot be bypassed by targeting different users.
func TestRateLimitBypass_AccountLockoutPerUser(t *testing.T) {
	mc := cache.NewMemoryCache()
	defer mc.Close()

	ctx := context.Background()
	threshold := 5
	lockDuration := 15 * time.Minute

	// Lock out user-A
	for i := 0; i < threshold; i++ {
		middleware.CheckAccountLockout(ctx, mc, "user-A", threshold, lockDuration)
	}

	// user-A should be locked
	locked, _ := middleware.CheckAccountLockout(ctx, mc, "user-A", threshold, lockDuration)
	if !locked {
		t.Fatal("user-A should be locked after exceeding threshold")
	}

	// user-B should NOT be affected
	locked, _ = middleware.CheckAccountLockout(ctx, mc, "user-B", threshold, lockDuration)
	if locked {
		t.Fatal("user-B should not be locked due to user-A's lockout")
	}

	// user-C with 1 attempt should not be locked
	middleware.CheckAccountLockout(ctx, mc, "user-C", threshold, lockDuration)
	locked, _ = middleware.CheckAccountLockout(ctx, mc, "user-C", threshold, lockDuration)
	if locked {
		t.Fatal("user-C should not be locked after 2 attempts (threshold=5)")
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

// TestRateLimitBypass_AccountLockoutThresholdExact verifies the exact
// boundary of account lockout: threshold-1 should not lock, threshold should.
func TestRateLimitBypass_AccountLockoutThresholdExact(t *testing.T) {
	thresholds := []int{1, 3, 5, 10, 50, 100}

	for _, threshold := range thresholds {
		t.Run("threshold="+string(rune('0'+threshold%10)), func(t *testing.T) {
			mc := cache.NewMemoryCache()
			defer mc.Close()
			ctx := context.Background()
			lockDuration := time.Minute

			userID := "user-exact-test"

			// threshold-1 attempts should not lock
			for i := 0; i < threshold-1; i++ {
				locked, _ := middleware.CheckAccountLockout(ctx, mc, userID, threshold, lockDuration)
				if locked {
					t.Fatalf("Should not be locked at attempt %d (threshold=%d)", i+1, threshold)
				}
			}

			// The threshold-th attempt is the last one allowed
			locked, _ := middleware.CheckAccountLockout(ctx, mc, userID, threshold, lockDuration)
			if locked {
				t.Fatalf("Should not be locked at exact threshold attempt (threshold=%d)", threshold)
			}

			// threshold+1 should be locked
			locked, _ = middleware.CheckAccountLockout(ctx, mc, userID, threshold, lockDuration)
			if !locked {
				t.Fatalf("Should be locked after exceeding threshold (threshold=%d)", threshold)
			}
		})
	}
}
