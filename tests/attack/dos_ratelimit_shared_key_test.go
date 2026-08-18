package attack

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/middleware"
)

// The shared-bucket finding (DOS-REVIEW F1): every limiter that passed
// IPRateLimitKey wrote rl:ip:<addr>, and Increment stamps a TTL only on the
// first write of a key. One password-reset request (3/hour) therefore chose a
// one-hour expiry for refresh (30/min), client-token (10/min), TOTP, OAuth,
// KMS unwrap and register as well, and thirty-one unauthenticated requests
// bought an hour of 429s for everyone behind that address.
//
// These tests assert the FIXED behavior: each limiter carries a Name that
// namespaces its counter, so exhausting one leaves the others untouched and a
// short window expires on its own schedule.

func dosOKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func dosHit(h http.Handler) int {
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.RemoteAddr = "203.0.113.77:443"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestDoS_ExhaustingOneIPLimiterLeavesSiblingsIntact is the regression for F1.
// Two limiters share IPRateLimitKey and the same client address; draining one
// to a 429 must not move the other's counter at all.
func TestDoS_ExhaustingOneIPLimiterLeavesSiblingsIntact(t *testing.T) {
	middleware.SetTrustedProxies(nil)

	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })

	ok := dosOKHandler()
	// Analogs of refresh (30/min) and password reset (3/hour), scaled so the
	// assertion runs in a unit test.
	refresh := middleware.RateLimit(mc, middleware.RateLimitConfig{
		Name: "refresh", Limit: 3, Window: 200 * time.Millisecond, KeyFunc: middleware.IPRateLimitKey,
	}, true)(ok)
	reset := middleware.RateLimit(mc, middleware.RateLimitConfig{
		Name: "pwreset", Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey,
	}, true)(ok)

	// Seed the long-window limiter first. Before the fix this stamped a
	// one-hour TTL on the key the short-window limiter then had to live with.
	if code := dosHit(reset); code != http.StatusOK {
		t.Fatalf("seed request on the long-window limiter: got %d, want 200", code)
	}

	// Drain the short-window limiter to a 429.
	for i := 0; i < 3; i++ {
		if code := dosHit(refresh); code != http.StatusOK {
			t.Fatalf("refresh hit %d: got %d, want 200", i+1, code)
		}
	}
	if code := dosHit(refresh); code != http.StatusTooManyRequests {
		t.Fatalf("refresh should be exhausted at its own limit, got %d", code)
	}

	// The sibling limiter must still have its full remaining budget: it was hit
	// once, so two more requests are allowed and the fourth is the first 429.
	for i := 0; i < 2; i++ {
		if code := dosHit(reset); code != http.StatusOK {
			t.Fatalf("password-reset hit %d after exhausting refresh: got %d, want 200 — "+
				"the buckets are still shared", i+2, code)
		}
	}
	if code := dosHit(reset); code != http.StatusTooManyRequests {
		t.Fatalf("password-reset limiter did not enforce its own limit, got %d", code)
	}

	// The short window must expire on its own schedule rather than inheriting
	// the hour the long-window limiter stamped.
	time.Sleep(300 * time.Millisecond)
	if code := dosHit(refresh); code != http.StatusOK {
		t.Fatalf("after its own 200ms window lapsed the refresh limiter returned %d; "+
			"a 429 means it is still sharing the long-window TTL", code)
	}

	// Login uses a different KeyFunc and must not share either bucket.
	login := middleware.RateLimit(mc, middleware.RateLimitConfig{
		Name: "login", Limit: 5, Window: time.Minute, KeyFunc: middleware.LoginRateLimitKey,
	}, true)(ok)
	if code := dosHit(login); code != http.StatusOK {
		t.Fatalf("login limiter was contaminated by the ip:<ip> buckets: got %d", code)
	}
}

// TestDoS_UnnamedLimitersDoNotShareAcrossWindows covers the fallback: a limiter
// that forgets to set Name still gets its own budget's namespace, so a
// one-hour counter can never be the counter a one-minute limiter reads.
func TestDoS_UnnamedLimitersDoNotShareAcrossWindows(t *testing.T) {
	middleware.SetTrustedProxies(nil)

	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })

	ok := dosOKHandler()
	long := middleware.RateLimit(mc, middleware.RateLimitConfig{
		Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey,
	}, true)(ok)
	short := middleware.RateLimit(mc, middleware.RateLimitConfig{
		Limit: 3, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
	}, true)(ok)

	for i := 0; i < 4; i++ {
		_ = dosHit(long)
	}
	if code := dosHit(short); code != http.StatusOK {
		t.Fatalf("an unnamed one-minute limiter inherited an unnamed one-hour counter: got %d", code)
	}
}

// TestDoS_IPRateLimitKeyIsRemoteAddrWhenProxiesEmpty pins that an
// unauthenticated client cannot mint a fresh bucket per request via
// X-Forwarded-For unless the operator has declared trusted proxies.
func TestDoS_IPRateLimitKeyIsRemoteAddrWhenProxiesEmpty(t *testing.T) {
	middleware.SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.RemoteAddr = "198.51.100.9:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	got := middleware.IPRateLimitKey(req)
	if got != "ip:198.51.100.9" {
		t.Fatalf("IPRateLimitKey = %q, want ip:198.51.100.9 (XFF must be ignored)", got)
	}
}

// TestDoS_EveryServerLimiterIsNamed walks the AST of setupRoutes so a limiter
// added later cannot silently reintroduce the shared bucket. Two limiters that
// both omit Name and happen to share a budget would collide again, and the
// grep-free way to stop that is to require the field.
func TestDoS_EveryServerLimiterIsNamed(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "server", "server.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	seen := map[string]token.Position{}
	total := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "RateLimitConfig" {
			return true
		}
		total++
		pos := fset.Position(lit.Pos())
		name := ""
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Name" {
				continue
			}
			val, ok := kv.Value.(*ast.BasicLit)
			if ok {
				name = val.Value
			}
		}
		if name == "" || name == `""` {
			t.Errorf("%s: RateLimitConfig has no Name; its counter would share a cache key with every other limiter of the same budget", pos)
			return true
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("%s: rate-limiter Name %s is already used at %s; the two share one counter", pos, name, prev)
		}
		seen[name] = pos
		return true
	})

	if total < 15 {
		t.Fatalf("found only %d RateLimitConfig literals in server.go; the walk is not seeing the limiters", total)
	}
}
