package outbound

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// A redirect must not downgrade the connection.
//
// ClientForIssuer's CheckRedirect re-applied CheckDerived to every hop, which
// judges the destination HOST. It never judged the scheme, and CheckDerived
// cannot: it returns early for loopback and otherwise compares hosts.
//
// So an endpoint under the issuer's own domain answering 307 with
// `Location: http://<same host>/...` was followed with method and body intact.
// On a token_endpoint that POSTs the client secret in cleartext. On a jwks_uri
// it hands whoever is on that path the key set an id_token is verified against,
// and refreshJWKS replaces the whole cache with whatever it decodes.
//
// The host check was never the missing half -- the attacker here stays on the
// issuer's domain, which is exactly what CheckDerived admits by design.

func TestClientForIssuerRefusesARedirectToCleartext(t *testing.T) {
	// CheckRedirect is exercised directly rather than over a socket. A real
	// httptest server listens on loopback, and plaintext to loopback is
	// legitimately allowed -- so a live round trip cannot express the case at
	// all, and would be refused at dial time for the wrong reason.
	const issuer = "https://idp.example"
	client := (&Policy{}).ClientForIssuer(issuer, 5*time.Second)
	if client.CheckRedirect == nil {
		t.Fatal("ClientForIssuer installed no CheckRedirect")
	}

	hop := func(target string) error {
		req, err := http.NewRequest(http.MethodPost, target, nil)
		if err != nil {
			t.Fatalf("build request for %s: %v", target, err)
		}
		return client.CheckRedirect(req, nil)
	}

	// The downgrade: same host, same domain, plaintext. CheckDerived admits the
	// host by design, which is what made the scheme the only thing standing
	// between a client secret and the wire.
	err := hop("http://idp.example/token")
	if err == nil {
		t.Fatal("a redirect to a plaintext endpoint on the issuer's own domain was allowed. " +
			"On a token_endpoint that POSTs the client secret in cleartext; on a jwks_uri it " +
			"hands over the key set an id_token is verified against.")
	}
	if !strings.Contains(err.Error(), "not an https endpoint") {
		t.Errorf("err = %v, want a refusal naming the scheme so an operator can tell a "+
			"downgrade from a blocked host", err)
	}

	// And the ordinary hop still works, which is the half a fix like this
	// breaks.
	if err := hop("https://idp.example/token2"); err != nil {
		t.Errorf("an https redirect on the issuer's own domain was refused: %v", err)
	}
}

// The loopback exception has to survive, or every developer running an issuer on
// localhost is broken by this.
func TestFetchableEndpointKeepsTheLoopbackException(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://idp.example/token":   true,
		"http://idp.example/token":    false,
		"http://localhost:8080/token": true,
		"http://127.0.0.1:8080/token": true,
		"http://[::1]:8080/token":     true,
		// A name that merely resolves to loopback is not this process's to
		// trust, which is the narrowness the original comment insisted on.
		"http://localtest.me/token": false,
		"ftp://idp.example/token":   false,
		"":                          false,
		"https://":                  false,
	} {
		if got := FetchableEndpoint(raw); got != want {
			t.Errorf("FetchableEndpoint(%q) = %v, want %v", raw, got, want)
		}
	}
}
