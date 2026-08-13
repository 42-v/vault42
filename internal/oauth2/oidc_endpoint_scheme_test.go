package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recordingTransport forwards every request and remembers the URLs that left
// the client, so an endpoint that was refused can be told apart from one that
// was fetched first and judged afterwards. The difference is the whole point of
// the endpoint rule: by the time a response is in hand, whoever answered has
// already had their say.
type recordingTransport struct {
	next http.RoundTripper

	mu   sync.Mutex
	urls []string
}

func (t *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.urls = append(t.urls, r.URL.String())
	t.mu.Unlock()
	return t.next.RoundTrip(r)
}

func (t *recordingTransport) fetched() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.urls...)
}

func (t *recordingTransport) forget() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.urls = nil
}

// issuerAdvertising serves a discovery document naming jwksURI as the source of
// the issuer's signing keys, over plain http on the loopback interface.
func issuerAdvertising(t *testing.T, jwksURI string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               jwksURI,
		})
	})
	return srv
}

// TestDiscoveryAcceptsAPlaintextKeySetOnlyOnTheLoopbackInterface pins the shape
// of the plaintext exception rather than the fact that one exists.
//
// jwks_uri decides identity: it supplies the keys every id_token signature is
// checked against, so anyone who can answer for it mints a token for any
// subject at that issuer and the callback signs them in as that user. Plaintext
// is allowed there for exactly one reason, that a developer's own issuer and
// this package's tests run on the loopback interface where there is no segment
// for anyone to sit on, and the exception has to stay that narrow. A hostname
// is not a loopback address no matter what it resolves to today: that
// resolution belongs to whoever answers DNS, not to this process, so accepting
// it would hand the exception to anyone who can answer a query. A scheme this
// package never speaks is not a safe endpoint either, it is an endpoint whose
// safety was never considered.
func TestDiscoveryAcceptsAPlaintextKeySetOnlyOnTheLoopbackInterface(t *testing.T) {
	for _, tc := range []struct {
		name     string
		jwksURI  string
		accepted bool
	}{
		{"a loopback address literal is the case the exception exists for", "http://127.0.0.1:8443/jwks", true},
		{"the name localhost resolves nowhere else and is allowed", "http://localhost:8443/jwks", true},
		{"an IPv6 loopback literal is the same case", "http://[::1]:8443/jwks", true},
		{"a hostname that merely resolves to loopback is refused", "http://localhost.localdomain:8443/jwks", false},
		{"a scheme this package never speaks is refused", "ftp://keys.elsewhere.test/jwks", false},
		{"a URL naming no host at all is refused", "file:///etc/vault42/jwks.json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := issuerAdvertising(t, tc.jwksURI)
			rec := &recordingTransport{next: srv.Client().Transport}
			p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://vault.test/cb", "")
			p.client = &http.Client{Transport: rec}

			d, err := p.discover(context.Background())
			if tc.accepted {
				if err != nil {
					t.Fatalf("refused a key set on the loopback interface: %v", err)
				}
				if d.JWKSURI != tc.jwksURI {
					t.Fatalf("jwks_uri = %q, want %q", d.JWKSURI, tc.jwksURI)
				}
				return
			}

			if err == nil {
				t.Fatalf("accepted %q as the source of the keys every id_token signature is checked against", tc.jwksURI)
			}
			if !strings.Contains(err.Error(), "jwks_uri") {
				t.Errorf("error = %q, want it to name the field it refused", err)
			}
			// refreshJWKS is the call that would load those keys, so the refusal
			// has to hold there too and neither call may put the URL on the wire:
			// a refusal that arrives after the fetch has already let the answer in.
			if err := p.refreshJWKS(context.Background()); err == nil {
				t.Fatal("refreshJWKS loaded a key set that discovery had already refused")
			}
			for _, u := range rec.fetched() {
				if !strings.HasSuffix(u, "/.well-known/openid-configuration") {
					t.Errorf("a request went to %q; discovery is the only fetch a refused document may cause", u)
				}
			}
		})
	}
}

// TestDiscoveryAcceptsAnHTTPSIssuerAndTalksToIt is the counterweight the
// refusals need. Every deployed issuer is reached over https, and none of the
// other tests in this package use it: they all run against loopback plaintext,
// so a rule that accidentally refused https would take single sign-on down for
// every tenant with the whole suite still green.
func TestDiscoveryAcceptsAnHTTPSIssuerAndTalksToIt(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"userinfo_endpoint":      srv.URL + "/userinfo",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})

	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://vault.test/cb", "")
	p.client = srv.Client()

	d, err := p.discover(context.Background())
	if err != nil {
		t.Fatalf("refused an https issuer: %v", err)
	}
	for _, got := range []struct {
		field, endpoint string
	}{
		{"authorization_endpoint", d.AuthEndpoint},
		{"token_endpoint", d.TokenEndpoint},
		{"userinfo_endpoint", d.UserInfoEndp},
		{"jwks_uri", d.JWKSURI},
	} {
		if !strings.HasPrefix(got.endpoint, srv.URL+"/") {
			t.Errorf("%s = %q, want the https endpoint the issuer advertised", got.field, got.endpoint)
		}
	}
}
