package attack

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/middleware"
)

// ClientIP splits X-Forwarded-For on comma and walks right to left, calling
// normalizeIP and isTrustedProxy per hop. MaxHeaderBytes is 1 MiB, so an
// uncapped walk is bounded by the header rather than by a hop count: ~70k hops
// of "203.0.113.1, ", each a ParseIP plus a walk of the trusted-proxy list, per
// request, before the handler runs.

// TestDoS_ClientIPCapsTheXFFHopWalk is the regression for the uncapped walk.
func TestDoS_ClientIPCapsTheXFFHopWalk(t *testing.T) {
	t.Cleanup(func() { middleware.SetTrustedProxies(nil) })
	middleware.SetTrustedProxies([]string{"10.0.0.0/8"})

	const hops = 4000
	parts := make([]string, hops)
	// The originating address sits at the far left behind thousands of trusted
	// hops, so only an uncapped walk can reach it.
	parts[0] = "203.0.113.50"
	for i := 1; i < hops; i++ {
		parts[i] = "10.0.0.2"
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Forwarded-For", strings.Join(parts, ", "))

	// Capped, the walk sees only trusted hops and falls back to the peer.
	if got := middleware.ClientIP(req); got != "10.0.0.1" {
		t.Fatalf("ClientIP = %q after a %d-hop header; the walk should be capped and fall "+
			"through to the peer address", got, hops)
	}
}

// TestDoS_ClientIPStillResolvesARealisticChain is the negative control: the cap
// must not break the deployments it exists to protect. Two or three hops is
// what an ingress plus a load balancer produces.
func TestDoS_ClientIPStillResolvesARealisticChain(t *testing.T) {
	t.Cleanup(func() { middleware.SetTrustedProxies(nil) })
	middleware.SetTrustedProxies([]string{"10.0.0.0/8"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.9, 10.0.0.2")

	if got := middleware.ClientIP(req); got != "203.0.113.50" {
		t.Fatalf("ClientIP = %q, want the originating address through a three-hop chain", got)
	}
}

// TestDoS_ClientIPReadsEveryForwardedForLine is the regression for reading only
// the first header field line. A peer that appends X-Forwarded-For as its own
// line rather than comma-joining it left the walk reading the client's line and
// dropping the real appended hop, which is leftmost trust reopened.
func TestDoS_ClientIPReadsEveryForwardedForLine(t *testing.T) {
	t.Cleanup(func() { middleware.SetTrustedProxies(nil) })
	middleware.SetTrustedProxies([]string{"10.0.0.0/8"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Add("X-Forwarded-For", "192.0.2.66")  // the client's own line
	req.Header.Add("X-Forwarded-For", "203.0.113.9") // appended by the real hop

	if got := middleware.ClientIP(req); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want 203.0.113.9 — only the first header line was read, so a "+
			"client-supplied line won over the hop the proxy actually observed", got)
	}
}

// BenchmarkDoS_ClientIPXFFHops shows the walk is linear in hop count and now
// flat past the cap. Superlinear growth here would be a new finding.
func BenchmarkDoS_ClientIPXFFHops(b *testing.B) {
	middleware.SetTrustedProxies([]string{"10.0.0.0/8", "192.168.0.0/16"})
	b.Cleanup(func() { middleware.SetTrustedProxies(nil) })

	for _, hops := range []int{10, 100, 1000} {
		parts := make([]string, hops)
		parts[0] = "203.0.113.50"
		for i := 1; i < hops; i++ {
			parts[i] = "10.0.0.2"
		}
		xff := strings.Join(parts, ", ")
		b.Run(strconv.Itoa(hops), func(b *testing.B) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "10.1.2.3:443"
			req.Header.Set("X-Forwarded-For", xff)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = middleware.ClientIP(req)
			}
		})
	}
}
