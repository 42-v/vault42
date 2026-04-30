package middleware

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/httputil"
)

// trustedProxies holds the configured trusted proxy CIDRs/IPs.
// Stored via atomic.Pointer for concurrent-safe reads from HTTP handlers.
// Set via SetTrustedProxies at startup.
var trustedProxyCIDRs atomic.Pointer[[]*net.IPNet]

// realIPHeader holds the name of the proxy-provided real IP header (e.g. "CF-Connecting-IP").
// Set via SetRealIPHeader at startup. Empty = disabled.
var realIPHeader atomic.Value

// tlsFingerprintHeader holds the name of the proxy-provided TLS fingerprint header
// (e.g. "X-TLS-Fingerprint"). Set via SetTLSFingerprintHeader at startup. Empty = disabled.
var tlsFingerprintHeader atomic.Value

// SetTrustedProxies parses and stores the trusted proxy list.
// Each entry can be a CIDR (e.g. "10.0.0.0/8") or a single IP (e.g. "10.0.0.1").
func SetTrustedProxies(proxies []string) {
	cidrs := make([]*net.IPNet, 0, len(proxies))
	for _, p := range proxies {
		if !strings.Contains(p, "/") {
			// Bare IP — normalize to CIDR
			if strings.Contains(p, ":") {
				p += "/128"
			} else {
				p += "/32"
			}
		}
		_, cidr, err := net.ParseCIDR(p)
		if err != nil {
			log.Printf("WARNING: invalid trusted proxy entry %q: %v", p, err)
			continue
		}
		cidrs = append(cidrs, cidr)
	}
	trustedProxyCIDRs.Store(&cidrs)
}

// SetRealIPHeader stores the proxy-provided real IP header name.
// Only trusted when the direct connection is from a trusted proxy.
// Examples: "CF-Connecting-IP" (Cloudflare), "X-Real-IP" (nginx).
func SetRealIPHeader(header string) {
	realIPHeader.Store(header)
}

// SetTLSFingerprintHeader stores the name of the HTTP header that the TLS-terminating
// proxy uses to pass the client's TLS fingerprint (e.g. JA4). Empty = disabled.
func SetTLSFingerprintHeader(header string) {
	tlsFingerprintHeader.Store(header)
}

// TLSFingerprint returns the TLS fingerprint from the configured header, or empty
// string if no header is configured or the header is absent from the request.
func TLSFingerprint(r *http.Request) string {
	h, _ := tlsFingerprintHeader.Load().(string)
	if h == "" {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(h))
}

// loadRealIPHeader returns the configured real IP header name (empty = disabled).
func loadRealIPHeader() string {
	v, _ := realIPHeader.Load().(string)
	return v
}

// loadTrustedProxyCIDRs returns the current trusted proxy list (nil-safe).
func loadTrustedProxyCIDRs() []*net.IPNet {
	p := trustedProxyCIDRs.Load()
	if p == nil {
		return nil
	}
	return *p
}

// RateLimitConfig defines rate limit parameters for an endpoint.
type RateLimitConfig struct {
	Limit   int
	Window  time.Duration
	KeyFunc func(r *http.Request) string
}

// localRateLimiter provides in-memory fallback rate limiting when the cache backend is unavailable.
type localRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*localRLEntry
}

type localRLEntry struct {
	count     int64
	windowEnd time.Time
}

func (l *localRateLimiter) increment(key string, window time.Duration) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	e, ok := l.entries[key]
	if !ok || now.After(e.windowEnd) {
		l.entries[key] = &localRLEntry{count: 1, windowEnd: now.Add(window)}
		return 1
	}
	e.count++
	return e.count
}

// evictOnce guards the eviction goroutine so only one is started per process.
var evictOnce sync.Once

// startEviction launches a background goroutine that removes expired entries
// from all localRateLimiter instances registered via addLimiter. Runs once per
// process (guarded by sync.Once) and sweeps every 60 seconds.
var activeLimiters struct {
	mu       sync.Mutex
	limiters []*localRateLimiter
}

func addLimiter(l *localRateLimiter) {
	activeLimiters.mu.Lock()
	activeLimiters.limiters = append(activeLimiters.limiters, l)
	activeLimiters.mu.Unlock()

	evictOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(60 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				activeLimiters.mu.Lock()
				for _, limiter := range activeLimiters.limiters {
					limiter.mu.Lock()
					for k, e := range limiter.entries {
						if now.After(e.windowEnd) {
							delete(limiter.entries, k)
						}
					}
					limiter.mu.Unlock()
				}
				activeLimiters.mu.Unlock()
			}
		}()
	})
}

// RateLimit returns a rate limiting middleware using a sliding window counter.
// Falls back to an in-memory counter when the cache backend is unavailable.
func RateLimit(c cache.Cache, cfg RateLimitConfig, enabled bool) func(http.Handler) http.Handler {
	local := &localRateLimiter{entries: make(map[string]*localRLEntry)}
	addLimiter(local)
	var fallbackWarned atomic.Bool

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				next.ServeHTTP(w, r)
				return
			}

			key := fmt.Sprintf("rl:%s", cfg.KeyFunc(r))
			ctx := r.Context()

			count, err := c.Increment(ctx, key, cfg.Window)
			if err != nil {
				// Cache failure — use in-memory fallback instead of allowing unlimited requests
				if fallbackWarned.CompareAndSwap(false, true) {
					log.Printf("WARNING: rate limiter falling back to in-memory counter (cache unavailable)")
				}
				count = local.increment(key, cfg.Window)
			}

			remaining := int64(cfg.Limit) - count
			if remaining < 0 {
				remaining = 0
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(cfg.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(cfg.Window).Unix(), 10))

			if count > int64(cfg.Limit) {
				w.Header().Set("Retry-After", strconv.Itoa(int(cfg.Window.Seconds())))
				httputil.WriteError(w, http.StatusTooManyRequests, "rate_limit_exceeded")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// LoginRateLimitKey generates a rate limit key from client IP.
func LoginRateLimitKey(r *http.Request) string {
	ip := ClientIP(r)
	return fmt.Sprintf("login:%s", ip)
}

// IPRateLimitKey generates a rate limit key from IP only.
func IPRateLimitKey(r *http.Request) string {
	return fmt.Sprintf("ip:%s", ClientIP(r))
}

// GeneralRateLimitKey generates a key from the authenticated user ID.
func GeneralRateLimitKey(r *http.Request) string {
	claims := GetClaims(r.Context())
	if claims != nil {
		return fmt.Sprintf("user:%s", claims.Subject)
	}
	return fmt.Sprintf("anon:%s", ClientIP(r))
}

// ClientIP extracts the client IP from a request, respecting X-Forwarded-For
// only when the direct connection comes from a trusted proxy.
// When trustedProxyCIDRs is empty, XFF is never trusted and RemoteAddr is used.
// When trustedProxyCIDRs is set and the remote address is trusted, the rightmost
// non-trusted IP from XFF is returned.
func ClientIP(r *http.Request) string {
	remoteIP := stripPort(r.RemoteAddr)

	// If no trusted proxies configured, never trust XFF
	if len(loadTrustedProxyCIDRs()) == 0 {
		return remoteIP
	}

	// Only trust proxy headers if the direct connection is from a trusted proxy
	if !isTrustedProxy(remoteIP) {
		return remoteIP
	}

	// Prefer the configured real IP header (e.g. CF-Connecting-IP, X-Real-IP)
	// when set — it's a single authoritative IP from the trusted proxy.
	//
	// A-6: pick the LAST value if the header appears multiple times — when a
	// misconfigured upstream APPENDS rather than overwrites, an attacker can
	// prepend a spoofed value via their own header and the proxy's value is
	// the last one. Using r.Header.Values + last entry treats the proxy as
	// authoritative regardless.
	if h := loadRealIPHeader(); h != "" {
		if values := r.Header.Values(h); len(values) > 0 {
			if v := strings.TrimSpace(values[len(values)-1]); v != "" {
				return v
			}
		}
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteIP
	}

	// Parse all IPs from XFF, walk from right to left,
	// return the first (rightmost) IP that is NOT a trusted proxy
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip == "" {
			continue
		}
		if !isTrustedProxy(ip) {
			return ip
		}
	}

	// All XFF entries are trusted proxies — use the leftmost
	if first := strings.TrimSpace(parts[0]); first != "" {
		return first
	}
	return remoteIP
}

func stripPort(addr string) string {
	// Handle IPv6 addresses like [::1]:8080
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func isTrustedProxy(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range loadTrustedProxyCIDRs() {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsAccountLocked checks if a user is currently locked out without modifying the counter.
func IsAccountLocked(ctx context.Context, c cache.Cache, userID string, threshold int) (bool, error) {
	key := fmt.Sprintf("lockout:%s", userID)
	val, err := c.Get(ctx, key)
	if err != nil {
		// Graceful degradation: a cache miss or transient cache failure must not
		// block authentication. Auth never fails because the cache is down.
		return false, nil //nolint:nilerr // intentional fail-open per docs/spec.md cache invariants
	}
	count, _ := strconv.ParseInt(val, 10, 64)
	return count > int64(threshold), nil
}

// RecordFailedAttempt increments the failed-attempt counter for lockout tracking.
// Call this only after a confirmed authentication failure.
func RecordFailedAttempt(ctx context.Context, c cache.Cache, userID string, lockDuration time.Duration) {
	key := fmt.Sprintf("lockout:%s", userID)
	c.Increment(ctx, key, lockDuration) // #nosec G104 -- best-effort counter
}

// CheckAccountLockout atomically increments the failed-attempt counter and
// reports whether the threshold has been crossed. Equivalent to
// RecordFailedAttempt + IsAccountLocked but in a single round-trip — useful
// in tight failure paths and for compliance assertions.
func CheckAccountLockout(ctx context.Context, c cache.Cache, userID string, threshold int, lockDuration time.Duration) (bool, error) {
	key := fmt.Sprintf("lockout:%s", userID)
	count, err := c.Increment(ctx, key, lockDuration)
	if err != nil {
		// Graceful degradation: same fail-open invariant as IsAccountLocked.
		return false, nil //nolint:nilerr // intentional fail-open per docs/spec.md cache invariants
	}
	return count > int64(threshold), nil
}
