package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- CheckDerived: the rule that closes the row --------------------------

func TestCheckDerivedAdmitsTheIssuerAndItsSubdomains(t *testing.T) {
	for _, tc := range []struct {
		name     string
		issuer   string
		endpoint string
	}{
		{"the issuer's own host", "https://okta.test", "https://okta.test/jwks"},
		{"a subdomain of the issuer", "https://okta.test", "https://keys.okta.test/jwks"},
		{"a deeper subdomain", "https://okta.test", "https://a.b.keys.okta.test/jwks"},
		{"the issuer written with a path and a port", "https://okta.test:8443/realms/x", "https://okta.test:8443/realms/x/jwks"},
		{"a case difference in the host", "https://OKTA.test", "https://okta.TEST/jwks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := New(nil, false).CheckDerived(tc.issuer, "jwks_uri", tc.endpoint); err != nil {
				t.Fatalf("refused %q under issuer %q: %v", tc.endpoint, tc.issuer, err)
			}
		})
	}
}

// The suffix test has to be a label boundary. "notokta.test" ends with
// "okta.test" as a string and is a different domain owned by someone else,
// which is precisely the registration an attacker makes.
func TestCheckDerivedRefusesAHostThatMerelyEndsWithTheIssuer(t *testing.T) {
	err := New(nil, false).CheckDerived("https://okta.test", "jwks_uri", "https://notokta.test/jwks")
	if err == nil {
		t.Fatal("admitted notokta.test under issuer okta.test; the suffix test is not on a label boundary")
	}
	if !strings.Contains(err.Error(), "notokta.test") || !strings.Contains(err.Error(), "okta.test") {
		t.Errorf("error = %q, want it to name both the refused host and the issuer it was judged against", err)
	}
	if !strings.Contains(err.Error(), "VAULT_OUTBOUND_ALLOWED_HOSTS") {
		t.Errorf("error = %q, want it to name the variable that permits the host", err)
	}
}

// A loopback destination is not a network destination: there is no segment for
// anyone to sit on and nothing for a forged request to reach that the process
// could not reach anyway. fetchableEndpoint already makes this exception for
// the scheme check, and the two exceptions have to agree or a developer's own
// issuer stops working on one of them.
func TestCheckDerivedAdmitsALoopbackDestinationUnderAnyIssuer(t *testing.T) {
	for _, endpoint := range []string{
		"http://127.0.0.1:8443/jwks",
		"http://localhost:8443/jwks",
		"http://[::1]:8443/jwks",
		"https://127.0.0.1/jwks",
	} {
		if err := New(nil, false).CheckDerived("https://okta.test", "jwks_uri", endpoint); err != nil {
			t.Errorf("refused loopback destination %q: %v", endpoint, err)
		}
	}
}

// A hostname that merely resolves to loopback is not a loopback destination:
// that resolution belongs to whoever answers DNS, not to this process.
func TestCheckDerivedRefusesAHostnameThatOnlyResolvesToLoopback(t *testing.T) {
	if err := New(nil, false).CheckDerived("https://okta.test", "jwks_uri", "https://localhost.localdomain/jwks"); err == nil {
		t.Fatal("admitted localhost.localdomain as a loopback destination")
	}
}

func TestCheckDerivedAdmitsAHostTheOperatorListed(t *testing.T) {
	p := New([]string{" WWW.googleapis.com ", ""}, false)
	if err := p.CheckDerived("https://accounts.google.com", "jwks_uri", "https://www.googleapis.com/oauth2/v3/certs"); err != nil {
		t.Fatalf("refused a listed host: %v", err)
	}
	if err := p.CheckDerived("https://accounts.google.com", "jwks_uri", "https://other.googleapis.com/certs"); err == nil {
		t.Fatal("the list is not exact-match: a host nobody listed was admitted")
	}
}

// The nil policy is what a caller with no operator configuration holds, and it
// has to mean "no extensions", not "no rule".
func TestTheNilPolicyStillEnforcesTheDomainRule(t *testing.T) {
	var p *Policy
	if err := p.CheckDerived("https://okta.test", "jwks_uri", "https://okta.test/jwks"); err != nil {
		t.Fatalf("the nil policy refused the issuer's own host: %v", err)
	}
	if err := p.CheckDerived("https://okta.test", "jwks_uri", "https://elsewhere.test/jwks"); err == nil {
		t.Fatal("the nil policy admitted a foreign host, so no policy means no rule")
	}
}

func TestCheckDerivedRefusesURLsItCannotJudge(t *testing.T) {
	p := New(nil, false)
	if err := p.CheckDerived("https://okta.test", "jwks_uri", "://nonsense"); err == nil {
		t.Error("admitted an endpoint that does not parse")
	}
	if err := p.CheckDerived("https://okta.test", "jwks_uri", "file:///etc/vault42/jwks.json"); err == nil {
		t.Error("admitted an endpoint that names no host")
	}
	if err := p.CheckDerived("://nonsense", "jwks_uri", "https://okta.test/jwks"); err == nil {
		t.Error("judged an endpoint against an issuer that does not parse")
	}
}

// --- the dial-time half --------------------------------------------------

func TestDialRefusesTheAddressRangesNoProviderLivesOn(t *testing.T) {
	for _, tc := range []struct {
		name string
		ip   string
		want string
	}{
		{"the IPv4 instance-metadata address", "169.254.169.254", "link-local"},
		{"an IPv6 link-local address", "fe80::1", "link-local"},
		{"the unspecified address", "0.0.0.0", "unspecified"},
		{"a multicast address", "239.1.2.3", "multicast"},
		{"an IPv6 multicast address", "ff02::1", "link-local"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// allowPrivate is on, so these are refused on their own account and
			// not as a side effect of the private-address rule.
			err := New(nil, true).refuseAddress(net.ParseIP(tc.ip))
			if err == nil {
				t.Fatalf("%s was admitted even with private addresses allowed", tc.ip)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to say why (%s)", err, tc.want)
			}
		})
	}
}

func TestDialRefusesPrivateAddressesUnlessTheDeploymentSaysOtherwise(t *testing.T) {
	for _, tc := range []struct {
		name string
		ip   string
	}{
		{"IPv4 loopback", "127.0.0.1"},
		{"IPv4 loopback behind an IPv4-mapped IPv6 address", "::ffff:127.0.0.1"},
		{"IPv6 loopback", "::1"},
		{"RFC 1918 ten-space", "10.1.2.3"},
		{"RFC 1918 the range a cluster service CIDR usually sits in", "172.20.0.1"},
		{"RFC 1918 one-ninety-two", "192.168.1.1"},
		{"an IPv6 unique local address", "fd00::1"},
		{"RFC 6598 carrier-grade NAT space", "100.64.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			err := New(nil, false).refuseAddress(ip)
			if err == nil {
				t.Fatalf("%s was admitted by default", tc.ip)
			}
			if !strings.Contains(err.Error(), "VAULT_OUTBOUND_ALLOW_PRIVATE") {
				t.Errorf("error = %q, want it to name the variable that permits it", err)
			}
			if err := New(nil, true).refuseAddress(ip); err != nil {
				t.Errorf("%s was still refused with private addresses allowed: %v", tc.ip, err)
			}
		})
	}
}

func TestDialAdmitsAPublicAddress(t *testing.T) {
	if err := New(nil, false).refuseAddress(net.ParseIP("93.184.216.34")); err != nil {
		t.Fatalf("refused a public address: %v", err)
	}
}

// The check has to happen at dial time against the address that was actually
// resolved, not at URL-parse time against the name. A name the domain rule
// admits can still resolve into the metadata range, and a redirect can name a
// destination that never passed through CheckDerived at all.
func TestDialContextRefusesANameThatResolvesInsideTheDeployment(t *testing.T) {
	_, err := New(nil, false).DialContext(context.Background(), "tcp", "localhost:1")
	if err == nil {
		t.Fatal("dialed a name that resolves to loopback with private addresses refused")
	}
	// "refusing to connect" and not merely "an error": port 1 is closed, so a
	// guard that judged nothing would also fail here, with connection refused.
	// The two have to be told apart or this test passes on the socket's
	// behavior rather than on the policy's.
	if !strings.Contains(err.Error(), "refusing to connect to localhost:1") {
		t.Errorf("error = %q, want a refusal naming the destination rather than a failed connection", err)
	}
}

func TestDialContextConnectsToAPermittedDestination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	client := New(nil, true).Client(5 * time.Second)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("a guarded client could not reach a permitted destination: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}

// A guarded client is the reason the redirect case is covered without a rule of
// its own: a 302 into the metadata range is dialed through the same guard, and
// the destination it names never passed through CheckDerived.
func TestAGuardedClientRefusesARedirectIntoTheMetadataRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	// Private addresses are allowed, so the loopback test server itself is
	// reachable and only the link-local hop is refused.
	client := New(nil, true).Client(5 * time.Second)
	start := time.Now()
	resp, err := client.Get(srv.URL) //nolint:bodyclose // the error path returns no body
	if err == nil {
		resp.Body.Close() //nolint:errcheck,gosec // unreachable on a passing run
		t.Fatal("followed a redirect into the instance-metadata range")
	}
	// A refusal, not a timeout. 169.254.169.254 is unroutable from most test
	// hosts, so a guard that judged nothing would also produce an error here
	// that names the address — after the dial timeout expired. The message and
	// the elapsed time are what tell the two apart.
	if !strings.Contains(err.Error(), "refusing to connect") || !strings.Contains(err.Error(), "169.254.169.254") {
		t.Errorf("error = %q, want a refusal naming the address rather than a failed connection", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the redirect took %s to fail, which is a dial that was attempted and timed out rather than one that was refused", elapsed)
	}
}

func TestDialContextRefusesADestinationItCannotResolve(t *testing.T) {
	if _, err := New(nil, true).DialContext(context.Background(), "tcp", "not-a-host-port"); err == nil {
		t.Error("dialed an address that is not host:port")
	}

	// A canceled context fails the lookup without depending on a resolver
	// answering, or on there being one.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(nil, true).DialContext(ctx, "tcp", "example.test:443"); err == nil {
		t.Error("dialed a destination whose lookup failed")
	} else if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "example.test") {
		t.Errorf("error = %q, want it to name the destination or the cause", err)
	}
}

func TestTransportKeepsTheBoundsAnUnattendedOutboundCallNeeds(t *testing.T) {
	tr := New(nil, true).Transport()
	if tr.DialContext == nil {
		t.Fatal("the transport does not dial through the policy, so the guard is decorative")
	}
	if tr.ResponseHeaderTimeout == 0 || tr.TLSHandshakeTimeout == 0 || tr.MaxConnsPerHost == 0 {
		t.Error("the transport drops a bound http.DefaultTransport also lacks")
	}
}
