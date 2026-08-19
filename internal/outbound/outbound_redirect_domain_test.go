package outbound

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An in-domain endpoint that 302s to another public host must not be followed.
// DialContext only refuses private/link-local addresses, so without
// ClientForIssuer the domain rule CheckDerived established at discovery is
// silently dropped on the first hop — and Exchange would POST client_secret
// to whatever host answered.
func TestClientForIssuerRefusesARedirectOffTheIssuerDomain(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(final.Close)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	// Both servers are loopback; CheckDerived admits loopback. Use a non-loopback
	// redirect target by rewriting the Location to a public host the issuer
	// does not own.
	origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	client := New(nil, true).ClientForIssuer("https://accounts.example/", 5*time.Second)
	resp, err := client.Get(origin.URL) //nolint:bodyclose // error path
	if err == nil {
		resp.Body.Close() //nolint:errcheck,gosec
		t.Fatal("followed a redirect off the issuer's domain to evil.example")
	}
	if !strings.Contains(err.Error(), "refusing redirect") && !strings.Contains(err.Error(), "evil.example") {
		t.Errorf("error = %q, want a domain-rule refusal naming the redirect host", err)
	}
}

func TestClientForIssuerFollowsARedirectUnderTheIssuerDomain(t *testing.T) {
	var hops int
	mux := http.NewServeMux()
	srv := httptest.NewServer(nil)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, srv.URL+"/end", http.StatusFound)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, _ *http.Request) {
		hops++
		w.WriteHeader(http.StatusNoContent)
	})
	srv.Config.Handler = mux

	// Issuer is the test server itself (loopback is admitted by CheckDerived).
	client := New(nil, true).ClientForIssuer(srv.URL, 5*time.Second)
	resp, err := client.Get(srv.URL + "/start")
	if err != nil {
		t.Fatalf("in-domain redirect refused: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if hops != 2 {
		t.Fatalf("hops = %d, want 2 (start + end)", hops)
	}
}
