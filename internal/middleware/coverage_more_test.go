package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
