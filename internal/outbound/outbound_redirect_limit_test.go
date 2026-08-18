package outbound

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestClientForIssuerStopsAnEndlessRedirectChain covers the hop bound.
//
// CheckDerived answers whose host a hop names, and says nothing about how many
// hops there have been. A provider that redirects within its own domain
// therefore satisfies the domain rule on every hop, and without a bound the
// client follows it until something else gives out -- one compromised issuer
// holding a connection and a goroutine open for as long as it likes. The limit
// is the only thing that ends it, so it needs a test that would notice its
// removal.
func TestClientForIssuerStopsAnEndlessRedirectChain(t *testing.T) {
	var hops int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		// A relative Location resolves against the same host, so CheckDerived
		// admits every hop and only the count can stop it.
		http.Redirect(w, r, fmt.Sprintf("/hop/%d", hops), http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	// Loopback is admitted by CheckDerived, which is what isolates the hop bound
	// as the thing under test.
	client := New(nil, true).ClientForIssuer(srv.URL, 5*time.Second)
	resp, err := client.Get(srv.URL) //nolint:bodyclose // the error path returns no body to close
	if err == nil {
		resp.Body.Close() //nolint:errcheck,gosec // best effort on an unexpected success
		t.Fatal("followed a redirect chain with no end; a compromised issuer can hold the client " +
			"open by redirecting to itself forever")
	}
	if !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("the chain ended for the wrong reason: %v", err)
	}
	if hops < 10 {
		t.Errorf("the client gave up after %d hops, before the bound it is supposed to enforce", hops)
	}
}
