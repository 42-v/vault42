package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// oauthgrpCtlURL carries a DEL control byte. url.Parse rejects any raw URL
// containing a control character, so a provider method that builds a request
// from it must fail before it reaches the network.
const oauthgrpCtlURL = "http://provider.invalid/\x7f"

// oauthgrpCountingTransport records how many requests actually left the client
// so a build-time failure can be told apart from a network round trip.
type oauthgrpCountingTransport struct{ calls atomic.Int32 }

func (t *oauthgrpCountingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
		Request:    r,
	}, nil
}

// A 200 from the token endpoint is not on its own proof of a grant. RFC 6749
// §5.1 makes access_token mandatory, and a provider (or an attacker able to
// answer for one) that returns a well-formed body without it must not yield a
// usable TokenResponse: the callback would go on to call userinfo with an empty
// bearer token and treat whatever came back as an authenticated identity.
func TestGoogleExchangeRejectsResponseWithoutAccessToken(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"no access_token field", `{"token_type":"Bearer","expires_in":3600}`},
		{"empty access_token", `{"access_token":"","id_token":"eyJhbGciOiJub25lIn0..","token_type":"Bearer"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			p := NewGoogleProvider("cid", "sec", "https://app.test/cb")
			p.tokenURL = srv.URL

			resp, err := p.Exchange(context.Background(), "auth-code", "verifier")
			if err == nil {
				t.Fatal("Exchange accepted a 200 response carrying no access token")
			}
			if resp != nil {
				t.Errorf("Exchange returned a TokenResponse alongside the error: %+v", resp)
			}
			if !strings.Contains(err.Error(), "access_token") {
				t.Errorf("error = %q, want it to name the missing access_token", err)
			}
		})
	}
}

// The userinfo endpoint is what turns an access token into an identity. If a
// misconfigured endpoint made request construction fail and the provider still
// returned a zero-valued UserInfo with a nil error, the callback would link the
// flow to an empty provider ID and an empty email. Every provider must return
// the error and nothing else, without touching the network.
func TestProviderUserInfoRejectsUnbuildableRequest(t *testing.T) {
	tests := []struct {
		name string
		call func(ctx context.Context, c *http.Client) (*UserInfo, error)
	}{
		{
			name: "google",
			call: func(ctx context.Context, c *http.Client) (*UserInfo, error) {
				p := NewGoogleProvider("cid", "sec", "https://app.test/cb")
				p.client = c
				p.userInfoURL = oauthgrpCtlURL
				return p.UserInfo(ctx, "access-token")
			},
		},
		{
			name: "facebook",
			call: func(ctx context.Context, c *http.Client) (*UserInfo, error) {
				p := NewFacebookProvider("cid", "sec", "https://app.test/cb")
				p.client = c
				p.userInfoURL = oauthgrpCtlURL
				return p.UserInfo(ctx, "access-token")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &oauthgrpCountingTransport{}
			info, err := tt.call(context.Background(), &http.Client{Transport: tr})
			if err == nil {
				t.Fatal("UserInfo returned no error for an unbuildable request")
			}
			if info != nil {
				t.Errorf("UserInfo returned a profile alongside the error: %+v", info)
			}
			if n := tr.calls.Load(); n != 0 {
				t.Errorf("%d request(s) left the client despite the build failure", n)
			}
		})
	}
}

// The OIDC userinfo endpoint comes from the issuer's discovery document, which
// is remote input. An issuer that advertises an unusable endpoint must produce
// an error, not a blank identity that the callback would then trust.
func TestOIDCUserInfoRejectsUnbuildableDiscoveredEndpoint(t *testing.T) {
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"userinfo_endpoint":      oauthgrpCtlURL,
			"jwks_uri":               issuer + "/jwks",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	issuer = srv.URL

	p := NewOIDCProvider("okta", issuer, "cid", "sec", "https://app.test/cb", "")

	info, err := p.UserInfo(context.Background(), "access-token")
	if err == nil {
		t.Fatal("UserInfo returned no error for a discovery document with an unusable userinfo endpoint")
	}
	if info != nil {
		t.Errorf("UserInfo returned a profile alongside the error: %+v", info)
	}
	if !strings.Contains(err.Error(), "userinfo") {
		t.Errorf("error = %q, want it to name the userinfo step", err)
	}
}
