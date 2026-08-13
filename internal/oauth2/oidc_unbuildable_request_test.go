package oauth2

import (
	"context"
	"net/http"
	"testing"
)

// TestACallWhoseRequestCannotBeBuiltFetchesNothingAndReturnsNoResult covers the
// last check standing between a request that could not be assembled and the
// HTTP client.
//
// http.Client.Do dereferences the request it is given, so a call site that
// dropped this error would hand it nil and panic the goroutine serving the
// login callback rather than fail the login. Each of these four also returns
// the zero value beside the error on that path, and a caller that read it would
// exchange a code at "", fetch a profile from "" or install an empty key set.
//
// Reaching the check takes a caller with no context. Discovery now refuses any
// endpoint it cannot fetch, and that check runs ahead of all four of these, so
// no URL an issuer can advertise arrives here in a state where the build fails:
// a URL that parses well enough to be judged https parses well enough to become
// a request. A nil context is held in a variable rather than written as a
// literal because the literal is what the vet-level checks forbid, and the
// mistake being modeled belongs to a caller, not to this test.
func TestACallWhoseRequestCannotBeBuiltFetchesNothingAndReturnsNoResult(t *testing.T) {
	var noContext context.Context

	for _, tc := range []struct {
		name string
		// warm says whether the call reads its endpoint out of the cached
		// discovery document, in which case discovery has to have succeeded
		// first or the failure under test is not the one that fires.
		warm bool
		call func(t *testing.T, p *OIDCProvider) error
	}{
		{
			name: "discovery",
			call: func(t *testing.T, p *OIDCProvider) error {
				d, err := p.discover(noContext)
				if d != nil {
					t.Errorf("discover returned a document alongside the error: %+v", d)
				}
				return err
			},
		},
		{
			name: "the token exchange",
			warm: true,
			call: func(t *testing.T, p *OIDCProvider) error {
				tok, err := p.Exchange(noContext, "auth-code", "verifier")
				if tok != nil {
					t.Errorf("Exchange returned tokens alongside the error: %+v", tok)
				}
				return err
			},
		},
		{
			name: "the userinfo fetch",
			warm: true,
			call: func(t *testing.T, p *OIDCProvider) error {
				info, err := p.UserInfo(noContext, "access-token")
				if info != nil {
					t.Errorf("UserInfo returned a profile alongside the error: %+v", info)
				}
				return err
			},
		},
		{
			name: "the key set refresh",
			warm: true,
			call: func(t *testing.T, p *OIDCProvider) error {
				err := p.refreshJWKS(noContext)
				if k := p.cachedKey("k1"); k != nil {
					t.Error("refreshJWKS replaced the cached key set on a path that failed")
				}
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeIssuer(t, "")
			rec := &recordingTransport{next: srv.Client().Transport}
			p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://vault.test/cb", "")
			p.client = &http.Client{Transport: rec}

			if tc.warm {
				if _, err := p.discover(context.Background()); err != nil {
					t.Fatalf("warming the discovery cache: %v", err)
				}
				rec.forget()
			}

			if err := tc.call(t, p); err == nil {
				t.Fatal("a call whose request could not be built reported success")
			}
			if got := rec.fetched(); len(got) != 0 {
				t.Errorf("%d request(s) left the client after the build failed: %v", len(got), got)
			}
		})
	}
}

// TestAuthURLReturnsNothingWhenTheAuthorizeEndpointDoesNotParse is the second
// lock on the door discovery's endpoint check already holds shut.
//
// What AuthURL returns is handed to the browser as a redirect. If the parse
// error were dropped, u would be nil and /authorize would panic in the middle
// of a login; if the endpoint were passed through unparsed instead of being
// rebuilt, the browser would be sent at a string carrying whatever the issuer
// put in it, with the client_id, the state and the nonce appended to it.
//
// Discovery refuses a document whose authorization_endpoint does not parse, so
// no issuer can put this value in the cache and the test seeds it directly.
// That is the point of the check: it holds whatever is in the cache to the
// contract that AuthURL returns a URL or nothing at all.
func TestAuthURLReturnsNothingWhenTheAuthorizeEndpointDoesNotParse(t *testing.T) {
	p := NewOIDCProvider("okta", "https://issuer.test", "cid", "sec", "https://vault.test/cb", "")
	p.discovered = &oidcDiscovery{
		Issuer:        "https://issuer.test",
		AuthEndpoint:  oauthgrpCtlURL,
		TokenEndpoint: "https://issuer.test/token",
	}

	if got := p.AuthURL("state-1", "nonce-1", "challenge-1"); got != "" {
		t.Fatalf("AuthURL = %q, want the empty string the redirect guard refuses", got)
	}
}
