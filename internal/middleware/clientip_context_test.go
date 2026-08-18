package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/httputil"
)

// The service layer only ever receives a context. Without the address on it,
// the account lockout could not tell one source from another and had to key
// solely on the user id — which made five failed logins from any single address
// a fifteen-minute denial of service against any account whose email the caller
// knew. Resolving it once here also guarantees the lockout and the rate limiter
// agree on what "the client" is.

func TestClientIPContextCarriesTheResolvedAddress(t *testing.T) {
	SetTrustedProxies(nil)

	var got string
	h := ClientIPContext(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = httputil.ClientIPFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "203.0.113.44:5000"
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got != "203.0.113.44" {
		t.Fatalf("context address = %q, want the peer address; with no trusted proxies "+
			"configured a client-supplied header must not choose it", got)
	}
}

func TestClientIPContextHonoursATrustedProxy(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies([]string{"10.0.0.0/8"})

	var got string
	h := ClientIPContext(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = httputil.ClientIPFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got != "203.0.113.9" {
		t.Fatalf("context address = %q, want the address the trusted hop reported", got)
	}
	// The rate limiter must resolve the same thing, or the lockout and the
	// limiter would be counting two different callers.
	if key := IPRateLimitKey(req); key != "ip:203.0.113.9" {
		t.Fatalf("IPRateLimitKey = %q, disagreeing with the context address", key)
	}
}

// TestClientIPFromAnUnmarkedContextIsEmpty pins the safe zero value: a context
// that did not come through the HTTP edge — a background sweeper, the CLI, a
// test — reports "source unknown", never "source trusted".
func TestClientIPFromAnUnmarkedContextIsEmpty(t *testing.T) {
	if got := httputil.ClientIPFromContext(t.Context()); got != "" {
		t.Fatalf("ClientIPFromContext on a bare context = %q, want empty", got)
	}
}
