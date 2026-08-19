package compliance

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/outbound"
)

// =============================================================================
// OWASP ASVS 5.0.0 V1.3.6 and OWASP API Security Top 10:2023 API7:2023 — SSRF
//
// Both rows were carried as accepted risk on the same argument: no request path
// lets a caller influence an outbound destination, so the forgery precondition
// is absent, and a protocol allowlist already existed. What was missing was the
// rest of what V1.3.6 names — domains, paths and ports.
//
// The inventory divides three ways and the control follows the division rather
// than treating every outbound call alike. Four destinations are compiled-in
// https literals (SendGrid, the HIBP range API, and the Google, GitHub and
// Facebook endpoints); two are operator configuration (the SMTP relay and the
// OIDC issuer); four are named by the issuer's own discovery document. Only the
// last four come from data, and an allowlist over the other six would ask an
// operator to permit constants the binary already fixes, or to permit a URL
// they wrote themselves.
//
// So the assertion is on those four. V1.3.6 turns on the *destination check*
// and API7:2023 on *what that check protects*, which is why they are two tests
// rather than one cited twice.
//
// Do not cite TestASVS_V10_5_3_ProviderMetadataIssuerIsPinned for either. It
// asserts the OIDC section 3.1.3.7 issuer match, which is a different control
// and is these rows' compensating control rather than the control itself.
// =============================================================================

// ssrfIssuer serves a discovery document naming endpoint under the given field
// and keeping every other endpoint on its own host, so exactly one destination
// is under examination.
func ssrfIssuer(t *testing.T, field, endpoint string) *httptest.Server {
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
		doc[field] = endpoint
		_ = json.NewEncoder(w).Encode(doc)
	})
	return srv
}

// --- V1.3.6 — validate untrusted data against an allowlist ---

// "Verify that the application protects against Server-side Request Forgery
// (SSRF) attacks, by validating untrusted data against an allowlist of
// protocols, domains, paths and ports and sanitizing potentially dangerous
// characters before using the data to call another service."
//
// The untrusted data is the discovery document. The allowlist is
// outbound.Policy: the issuer's own domain, a loopback destination, or a host
// the operator named, judged before the fetch and again at dial time against
// what the name resolved to.
func TestASVS_V1_3_6_DiscoverySuppliedDestinationsAreCheckedAgainstAnAllowlist(t *testing.T) {
	t.Run("every one of the four is judged, not only the one that signs", func(t *testing.T) {
		for _, field := range []string{"jwks_uri", "token_endpoint", "userinfo_endpoint", "authorization_endpoint"} {
			srv := ssrfIssuer(t, field, "https://attacker.elsewhere.test/x")

			err := ssrfProviderError(t, srv.URL, outbound.New(nil, true))
			if err == nil {
				t.Errorf("V1.3.6: %s named a host the operator never configured and was accepted", field)
				continue
			}
			if !strings.Contains(err.Error(), "attacker.elsewhere.test") {
				t.Errorf("V1.3.6: the refusal for %s does not name the host: %v", field, err)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("V1.3.6: the refusal does not name the field it refused: %v", err)
			}
		}
	})

	t.Run("the operator's own list is what widens it", func(t *testing.T) {
		srv := ssrfIssuer(t, "jwks_uri", "https://keys.partner.test/jwks")

		if err := ssrfProviderError(t, srv.URL, outbound.New(nil, true)); err == nil {
			t.Fatal("V1.3.6: a foreign host was accepted with no allowlist entry for it")
		}
		if !ssrfDiscoveryAccepted(t, srv.URL, outbound.New([]string{"keys.partner.test"}, true)) {
			t.Fatal("V1.3.6: the operator listed keys.partner.test and discovery still refused it")
		}
	})

	t.Run("the refusal names the variable an operator has to change", func(t *testing.T) {
		srv := ssrfIssuer(t, "jwks_uri", "https://www.googleapis.com/oauth2/v3/certs")
		err := ssrfProviderError(t, srv.URL, outbound.New(nil, true))
		if err == nil {
			t.Fatal("V1.3.6: a cross-domain jwks_uri was accepted")
		}
		if !strings.Contains(err.Error(), "VAULT_OUTBOUND_ALLOWED_HOSTS") {
			t.Errorf("V1.3.6: a refusal that costs an operator a working login has to say which "+
				"variable permits it; the error was %q", err)
		}
	})
}

// ssrfProvider builds a real generic OIDC provider with the deployment's policy
// installed, exactly as cmd/vault does.
func ssrfProvider(t *testing.T, issuer string, guard *outbound.Policy) *oauth2.OIDCProvider {
	t.Helper()
	p := oauth2.NewOIDCProvider("okta", issuer, "cid", "sec", "https://vault.test/cb", "")
	p.SetGuard(guard)
	return p
}

// ssrfProviderError drives discovery through the exported path that surfaces its
// error. Exchange calls discover first and returns what it says.
func ssrfProviderError(t *testing.T, issuer string, guard *outbound.Policy) error {
	t.Helper()
	_, err := ssrfProvider(t, issuer, guard).Exchange(context.Background(), "code", "verifier")
	return err
}

// ssrfDiscoveryAccepted reports whether discovery completed. AuthURL is empty
// when and only when discovery failed, so it is the acceptance probe that does
// not also need the fake issuer to implement a token endpoint.
func ssrfDiscoveryAccepted(t *testing.T, issuer string, guard *outbound.Policy) bool {
	t.Helper()
	return ssrfProvider(t, issuer, guard).AuthURL("state", "nonce", "challenge") != ""
}

// --- API7:2023 — Server Side Request Forgery ---

// The API7 half is about what the check buys rather than about its shape: the
// destinations a forged request would want are inside the deployment and in the
// range cloud instance metadata answers on, and neither a name that resolves
// there nor a redirect that lands there passed through the endpoint check.
func TestOWASP_API7_2023_AnOutboundCallCannotReachInsideTheDeployment(t *testing.T) {
	t.Run("the instance-metadata range is refused with no escape hatch", func(t *testing.T) {
		// allowPrivate is on, the widest posture an operator can configure, so
		// this refusal is not a side effect of the private-address rule.
		for _, addr := range []string{"169.254.169.254:80", "[fe80::1]:80"} {
			_, err := outbound.New(nil, true).DialContext(context.Background(), "tcp", addr)
			if err == nil {
				t.Errorf("API7:2023: %s was dialed at the widest configurable posture", addr)
				continue
			}
			if !strings.Contains(err.Error(), "refusing to connect") {
				t.Errorf("API7:2023: %s failed for some other reason than a refusal: %v", addr, err)
			}
		}
	})

	t.Run("a name that resolves inside the deployment is refused at dial time", func(t *testing.T) {
		// The name passes any check made on the string. What refuses it is the
		// address it resolved to, which is the only place a rebinding answer or
		// a provider hostname pointed inward can be caught.
		_, err := outbound.New(nil, false).DialContext(context.Background(), "tcp", "localhost:443")
		if err == nil {
			t.Fatal("API7:2023: a name resolving to loopback was dialed")
		}
		if !strings.Contains(err.Error(), "refusing to connect") {
			t.Errorf("API7:2023: the failure was not a refusal: %v", err)
		}
	})

	t.Run("a redirect is judged on the same terms as the endpoint it came from", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", http.StatusFound)
		}))
		t.Cleanup(srv.Close)

		start := time.Now()
		resp, err := outbound.New(nil, true).Client(5 * time.Second).Get(srv.URL) //nolint:bodyclose // the error path returns no body
		if err == nil {
			resp.Body.Close() //nolint:errcheck,gosec // unreachable on a passing run
			t.Fatal("API7:2023: a redirect into the instance-metadata range was followed")
		}
		if !strings.Contains(err.Error(), "refusing to connect") {
			t.Errorf("API7:2023: the redirect failed for some other reason than a refusal: %v", err)
		}
		// A dial that was attempted and timed out is not a refusal, and on a host
		// where 169.254.169.254 is unroutable it produces an error too.
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("API7:2023: the redirect took %s to fail, which is a dial that was attempted", elapsed)
		}
	})

	t.Run("an operator-configured private provider still works when the deployment says so", func(t *testing.T) {
		// Fail-closed has to be configurable or a self-hosted Keycloak in the
		// same cluster is unreachable, which is the availability cost this row's
		// closure is accountable for.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		conn, err := outbound.New(nil, true).DialContext(context.Background(), "tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("API7:2023: VAULT_OUTBOUND_ALLOW_PRIVATE=true did not restore an internal provider: %v", err)
		}
		_ = conn.Close()
	})
}
