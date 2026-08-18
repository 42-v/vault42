package attack

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The behavioral half of the admin-plane chain gate.
//
// adminapi.NewRouter installs seven middleware and six of them could be removed
// with every suite green. Seven test functions across four files reference
// LocalOnly and RejectProxyHeaders, and every one of them constructs the
// middleware and wraps its own handler; nothing asserted presence in the chain
// the router builds. The consequences of the mutated state are not small: no
// CSP, HSTS or frame options on the admin UI, a client-supplied X-Request-ID
// reaching the logs, unbounded admin bodies, a handler panic becoming a process
// kill on a single-replica plane, and the loss of what the source calls layer 4
// and layer 6 of the six-layer local-only enforcement — including the
// admin:killswitch_triggered audit record.
//
// tests/spec/chain_wiring_test.go pins the layer list and its order structurally.
// These drive the router NewRouter actually returns, which is the same thing
// TestAdminAuth_EveryGuardedRouteRefusesAnAnonymousCaller does for
// authentication, and for the same reason: a chain nothing drives is a chain
// nothing can see stop working.

// A non-loopback caller must be refused before authentication runs. The admin
// plane's entire deployment argument is that it is loopback-only behind an mTLS
// gateway, and this is the layer that makes that true rather than assumed.
func TestAdminChain_RefusesANonLoopbackCallerBeforeAuthentication(t *testing.T) {
	h := adminRouterUnderTest(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.RemoteAddr = "203.0.113.9:44444"
	req.Header.Set("Authorization", "Bearer "+validAdminToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("a non-loopback caller holding a valid admin session = %d, want 403. The "+
			"loopback gate is not installed on the chain the router builds, and the admin plane's "+
			"whole containment argument rests on it: body=%s", rec.Code, rec.Body.String())
	}
	if reason := refusalReason(t, rec); reason != "local_only" {
		t.Errorf("refused with %q, want local_only. Any other reason means the refusal came from a "+
			"later layer and the loopback check itself is gone.", reason)
	}
}

// A loopback caller carrying a proxy header must be refused too. The header says
// the request was forwarded, and a forwarded request reaching a loopback-only
// plane means something is in front of it that should not be.
func TestAdminChain_RefusesALoopbackCallerCarryingAProxyHeader(t *testing.T) {
	h := adminRouterUnderTest(t)

	for _, header := range []string{"X-Forwarded-For", "X-Real-IP"} {
		t.Run(header, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
			req.RemoteAddr = "127.0.0.1:54321"
			req.Header.Set(header, "203.0.113.9")
			req.Header.Set("Authorization", "Bearer "+validAdminToken)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("a request carrying %s = %d, want 403. Without this layer the loopback "+
					"check can be satisfied by anything that terminates the connection locally, "+
					"which is what an ingress controller does: body=%s",
					header, rec.Code, rec.Body.String())
			}
			if reason := refusalReason(t, rec); reason != "proxy_not_allowed" {
				t.Errorf("refused with %q, want proxy_not_allowed", reason)
			}
		})
	}
}

// The admin UI is HTML rendered in a browser, and these four headers are the
// whole of its client-side containment. The vault plane has a live-request test
// for its own header layer; this is the admin plane's.
func TestAdminChain_SetsTheSecurityHeadersOnEveryResponse(t *testing.T) {
	h := adminRouterUnderTest(t)
	rec := hitAdminRoute(t, h, http.MethodGet, "/admin/login", "")

	for header, want := range map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=",
	} {
		if got := rec.Header().Get(header); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it to contain %q. The security-header layer is not on the "+
				"chain, so the admin UI is served to a browser bare.", header, got, want)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("Content-Security-Policy = %q, want a default-src 'none' policy", csp)
	}
}

// The request-id layer does two things and the second is the security one: it
// deletes the caller's own X-Request-ID before generating its own. Left in
// place, a client-chosen id is written into every log line the request
// produces, which is a log-injection and log-forging primitive on the one plane
// whose logs are the audit trail.
func TestAdminChain_ReplacesAClientSuppliedRequestID(t *testing.T) {
	h := adminRouterUnderTest(t)

	const forged = "forged-by-the-caller"
	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Request-ID", forged)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	got := rec.Header().Get("X-Request-ID")
	if got == "" {
		t.Fatal("the response carries no X-Request-ID; the correlation id every admin log line " +
			"quotes is empty")
	}
	if got == forged {
		t.Fatalf("the caller's own X-Request-ID (%q) was echoed back and used. It is stripped for a "+
			"reason: on this plane the logs are the audit trail, and a caller who chooses the "+
			"correlation id chooses what the trail says.", forged)
	}
}

// The admin login route verifies a client secret with Argon2id and is reachable
// without credentials, which makes it both a password-guessing surface and a CPU
// exhaustion surface. Its limiter's own doc says it is independent of account
// lockout, so lockout does not substitute. Mutating the limiter's internals
// fails three tests, because all three build their own; removing it from the
// deployed route failed nothing.
func TestAdminChain_TheLoginRouteEnforcesItsRateLimit(t *testing.T) {
	h := adminRouterUnderTest(t)

	const budget = 10
	for i := 1; i <= budget; i++ {
		rec := hitAdminRoute(t, h, http.MethodPost, "/admin/auth/login", "")
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d of %d was rate limited; the deployed budget is smaller than the "+
				"one the register pins", i, budget)
		}
	}

	rec := hitAdminRoute(t, h, http.MethodPost, "/admin/auth/login", "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429. Admin password guessing is unbounded per source, and "+
			"so is the Argon2id work an unauthenticated caller can make this plane do: body=%s",
			budget+1, rec.Code, rec.Body.String())
	}
}
