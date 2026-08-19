package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/outbound"
)

// issuerAdvertisingSplit serves a discovery document whose named field points at
// value while every other endpoint stays on the issuer's own host, so a test
// names exactly one destination as the one under examination.
func issuerAdvertisingSplit(t *testing.T, field, value string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"userinfo_endpoint":      srv.URL + "/userinfo",
			"jwks_uri":               srv.URL + "/jwks",
		}
		doc[field] = value
		_ = json.NewEncoder(w).Encode(doc)
	})
	return srv
}

// The four endpoints a discovery document names are the only outbound
// destinations vault42 takes from data rather than from configuration or a
// compiled-in literal, and until this rule landed the only thing asked of them
// was their scheme. An issuer that is compromised, or merely wrong, could name
// any https host on the internet as its token endpoint and vault42 would post
// the client secret there, or as its jwks_uri and vault42 would check every
// id_token signature against keys that host chose.
//
// The trust boundary this asserts: configuring an issuer vouches for that
// issuer's own domain and for nothing beyond it. A host outside that domain has
// to be named by the operator, not by the document.
func TestOIDCDiscoveryRefusesAnEndpointOutsideTheIssuersDomain(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"the signing key endpoint", "jwks_uri"},
		{"the token endpoint", "token_endpoint"},
		{"the userinfo endpoint", "userinfo_endpoint"},
		{"the authorize endpoint", "authorization_endpoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := issuerAdvertisingSplit(t, tc.field, "https://keys.elsewhere.test/x")
			rec := &recordingTransport{next: srv.Client().Transport}
			p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://vault.test/cb", "")
			p.client = &http.Client{Transport: rec}

			_, err := p.discover(context.Background())
			if err == nil {
				t.Fatalf("accepted a discovery document naming %s on a host the operator never configured", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error = %q, want it to name the field it refused", err)
			}
			if !strings.Contains(err.Error(), "keys.elsewhere.test") {
				t.Errorf("error = %q, want it to name the host it refused", err)
			}
			// The refusal has to arrive before the fetch. A destination check
			// that runs after the response is in hand has already let whoever
			// answered have their say.
			for _, u := range rec.fetched() {
				if strings.Contains(u, "keys.elsewhere.test") {
					t.Errorf("fetched %q before refusing it", u)
				}
			}
		})
	}
}

// The refusal an operator sees has to tell them how to permit the host, because
// the legitimate case is common: Google's OIDC issuer is accounts.google.com
// while the keys it signs with are served from www.googleapis.com, a different
// registrable domain entirely. A provider like that is configuration, not an
// attack, and the operator needs to be told which variable makes it work.
func TestOIDCDiscoveryRefusalNamesTheVariableThatPermitsTheHost(t *testing.T) {
	srv := issuerAdvertisingSplit(t, "jwks_uri", "https://www.googleapis.com/oauth2/v3/certs")
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://vault.test/cb", "")

	_, err := p.discover(context.Background())
	if err == nil {
		t.Fatal("accepted a cross-domain jwks_uri")
	}
	if !strings.Contains(err.Error(), "VAULT_OUTBOUND_ALLOWED_HOSTS") {
		t.Errorf("error = %q, want it to name the variable that permits the host", err)
	}
}

// The escape hatch has to actually work, or the refusal above is a dead end
// rather than a decision the operator can make.
func TestOIDCDiscoveryAcceptsACrossDomainEndpointTheOperatorAllowed(t *testing.T) {
	srv := issuerAdvertisingSplit(t, "jwks_uri", "https://www.googleapis.com/oauth2/v3/certs")
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://vault.test/cb", "")
	p.SetGuard(outbound.New([]string{"www.googleapis.com"}, true))

	d, err := p.discover(context.Background())
	if err != nil {
		t.Fatalf("refused a host the operator listed: %v", err)
	}
	if d.JWKSURI != "https://www.googleapis.com/oauth2/v3/certs" {
		t.Fatalf("jwks_uri = %q, want the allowed host to survive discovery", d.JWKSURI)
	}
}

// A provider with no policy installed still enforces the domain rule. The rule
// costs no configuration and has no off switch, so a deployment that never
// heard of this feature gets it; the policy only ever widens what is permitted.
func TestOIDCDiscoveryEnforcesTheDomainRuleWithNoPolicyInstalled(t *testing.T) {
	srv := issuerAdvertisingSplit(t, "token_endpoint", "https://collector.elsewhere.test/token")
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://vault.test/cb", "")
	if p.guard != nil {
		t.Fatal("NewOIDCProvider installed a policy; this case is about the absence of one")
	}

	if _, err := p.discover(context.Background()); err == nil {
		t.Fatal("a provider with no policy accepted a foreign token endpoint, so the rule is opt-in")
	}
}
