package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// This file fuzzes CheckDerived against the property it claims rather than
// against a list of verdicts.
//
// docs/compliance-register.json retires CR-17 on this package: the four URLs an
// OIDC discovery document supplies -- authorization_endpoint, token_endpoint,
// userinfo_endpoint and jwks_uri -- are the only outbound destinations vault42
// takes from data rather than from configuration or a compiled-in literal, and
// CheckDerived is what holds them to the issuer's own domain, a loopback
// destination, or a host the operator named in VAULT_OUTBOUND_ALLOWED_HOSTS.
// The rule is written for this codebase rather than taken from a library, so a
// gap in it is a gap nobody else is fuzzing.
//
// A target that asserted a verdict -- that this URL is refused -- would close
// none of that, because it can only re-check the inputs somebody already
// thought of, and the input that matters is the one nobody thought of and
// CheckDerived ACCEPTED. A refusal is therefore always a correct answer here
// and can never fail the fuzzer: the rule's failure mode is a rejected
// legitimate provider, which costs availability and is what the refusal message
// exists to explain. The assertion runs only on the accept path.
//
// The property asserted is the sentence the package exists to hold:
//
//	if CheckDerived accepts a URL, then the host net/http would actually open
//	the connection to is a loopback destination, a host the operator listed, or
//	the issuer's own host or a subdomain of it on a label boundary.
//
// Two things keep the check an independent opinion rather than a second run of
// the code under test. The dialed host is read out of net/http itself instead
// of being recomputed here, so a disagreement between the name CheckDerived
// judged and the name that reaches the dialer is visible rather than
// reproduced: net/http feeds url.Hostname() through IDNA on its way to
// canonicalAddr, and hostOf feeds the same value through strings.ToLower, and
// those two are not the same function. And the membership tests below are
// written out again rather than calling allows, isLoopbackHost or underDomain,
// so that a rule which stops testing the suffix on a label boundary fails here
// instead of being confirmed by itself.
//
// Both places CheckDerived is applied are driven, because they hand it
// different strings. Discovery passes the endpoint exactly as the document
// spelled it (internal/oauth2/oidc.go), while ClientForIssuer's CheckRedirect
// passes req.URL.String() and then dials req.URL -- a check and a fetch that
// read a URL through two different code paths, which is the shape a
// parse-it-twice bypass takes.

// errOracleRecorded ends the round trip at the moment the destination is known.
// Nothing in this file may reach the network: a target that resolves names has
// a verdict that depends on whichever resolver answered, and one that connects
// spends its whole budget in syscalls instead of in inputs.
var errOracleRecorded = errors.New("outbound fuzz oracle: destination recorded, connection not attempted")

// dialTarget answers with the host net/http would open a connection to for u,
// and whether it would open one at all.
//
// The host is observed rather than computed, because net/http is the thing that
// decides it. It is not always url.Hostname(): canonicalAddr puts the hostname
// through IDNA first, so a Unicode host reaches the dialer in punycode, and a
// character that folds one way under strings.ToLower and another way under
// UTS-46 is exactly the divergence this target exists to find. Recomputing that
// rule here would only reproduce whichever reading the author of hostOf held,
// which is no second opinion at all.
//
// A URL net/http declines before dialing -- an unsupported scheme, an empty
// host -- returns false. That is not a gap in the invariant. internal/oauth2's
// fetchableEndpoint admits only https and plaintext loopback, so a URL no
// dialer is reached for is a URL no packet is sent for, and a property about
// the host that gets dialed has nothing to say about it.
func dialTarget(u *url.URL) (string, bool) {
	var (
		addr   string
		dialed bool
	)
	tr := &http.Transport{
		// Proxy is nil rather than ProxyFromEnvironment, which is what
		// Policy.Transport ships. With a proxy configured the address handed to
		// the dialer is the proxy's, so this oracle would read the proxy's host
		// for every input and the target's verdict would depend on whether the
		// machine running it happens to have HTTPS_PROXY set.
		Proxy: nil,
		DialContext: func(_ context.Context, _, dialAddr string) (net.Conn, error) {
			if !dialed {
				addr, dialed = dialAddr, true
			}
			return nil, errOracleRecorded
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	req := &http.Request{
		Method:     http.MethodGet,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Host:       u.Host,
	}
	// The request is built around the parsed URL rather than around a string,
	// so the redirect phase below can hand CheckDerived a re-serialized spelling
	// while this side still dials the object the transport would have dialed.
	resp, err := tr.RoundTrip(req.WithContext(context.Background()))
	if err == nil {
		resp.Body.Close() //nolint:errcheck,gosec // unreachable: the recorder never returns a connection
	}
	if !dialed {
		return "", false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", false
	}
	return strings.ToLower(host), true
}

// oracleIsLoopback reports whether a dialed host is the loopback interface.
//
// It is the loopback exception restated, not isLoopbackHost called: a name that
// merely resolves to 127.0.0.1 does not qualify, because that resolution
// belongs to whoever answers DNS. Writing it out again is what makes a future
// widening of the exception -- admitting a name because it looks local, say --
// fail this target rather than agree with it.
func oracleIsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// oracleUnderDomain reports whether host is base or sits beneath it on a label
// boundary. The boundary is the whole of the rule: "notokta.test" ends with
// "okta.test" as a string and is a domain somebody else registered, which is
// the registration an attacker makes.
func oracleUnderDomain(host, base string) bool {
	return host == base || strings.HasSuffix(host, "."+base)
}

// oracleAllowedHosts is the set of exact hosts the operator named, in every
// spelling the network can reach them under.
//
// Each entry contributes two: the entry as CheckDerived compares it, and the
// host net/http would dial for it. The second is a deliberate widening and it
// is what stops this target reporting an operator's own choice as a bypass. An
// entry written in Unicode reaches the wire in a mapped form, so a connection
// to "ss.test" for an entry the operator spelled with U+00DF LATIN SMALL LETTER
// SHARP S is the same destination the operator named and not a host nobody
// vouched for. A real bypass names a third domain and is under neither
// spelling, so the widening costs no detection.
func oracleAllowedHosts(entries []string) []string {
	hosts := make([]string, 0, 2*len(entries))
	for _, entry := range entries {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		hosts = append(hosts, entry)
		// The entry is a bare host, so it needs a scheme before net/http will
		// read it. The parsed hostname is required to be the entry itself,
		// which keeps an entry carrying a port or a path from contributing the
		// bare host it happens to contain: CheckDerived would never match such
		// an entry, and admitting the bare host here would forgive a hit this
		// target should report.
		u, err := url.Parse("https://" + entry + "/")
		if err != nil || strings.ToLower(u.Hostname()) != entry {
			continue
		}
		if host, ok := dialTarget(u); ok {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// oracleIssuerBases is the set of domains the operator vouched for by
// configuring an issuer, in the same two spellings and for the same reason.
//
// The dialed spelling is the one that matters and is listed first. The raw
// hostname is kept as well because net/http falls back to it when IDNA cannot
// convert a name: in that case the endpoint reaches the dialer under the same
// unconverted spelling that CheckDerived judged, which is a name no resolver
// can answer for rather than a destination an attacker steered.
func oracleIssuerBases(issuer string) []string {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil
	}
	raw := strings.ToLower(u.Hostname())
	if raw == "" {
		return nil
	}
	bases := make([]string, 0, 2)
	if host, ok := dialTarget(u); ok {
		bases = append(bases, host)
	}
	return append(bases, raw)
}

// oracleSeeds are the corpus. They are the real cases first -- the four fields
// a discovery document supplies, the loopback forms a developer's own issuer
// takes, and the operator list that exists because Google serves its keys from
// www.googleapis.com while its issuer is accounts.google.com -- and then every
// hostile vector the tests in this package already carry, plus the classes a
// host comparison is usually wrong about.
//
// The accepted cases matter at least as much as the refused ones. The assertion
// only has something to check once the fuzzer is mutating an input CheckDerived
// let through, so the corpus has to start inside the accepted set as well as
// outside it.
var oracleSeeds = []struct {
	issuer   string
	endpoint string
	allowed  string
}{
	// The four discovery fields under an issuer that owns them, which is the
	// accepted shape every deployment runs.
	{"https://okta.test", "https://okta.test/oauth2/v1/authorize", ""},
	{"https://okta.test", "https://okta.test/oauth2/v1/token", ""},
	{"https://okta.test", "https://okta.test/oauth2/v1/userinfo", ""},
	{"https://okta.test", "https://keys.okta.test/oauth2/v1/keys", ""},
	{"https://okta.test", "https://a.b.keys.okta.test/jwks", ""},
	{"https://okta.test:8443/realms/x", "https://okta.test:8443/realms/x/protocol/openid-connect/certs", ""},
	{"https://OKTA.test", "https://okta.TEST/jwks", ""},

	// The operator list, including the near miss that proves it is exact rather
	// than a subtree and the padded, upper-case entry New has to normalise.
	{"https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs", "www.googleapis.com"},
	{"https://accounts.google.com", "https://other.googleapis.com/certs", "www.googleapis.com"},
	{"https://accounts.google.com", "https://WWW.GOOGLEAPIS.COM/certs", "www.googleapis.com"},
	{"https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs", " WWW.googleapis.com ,"},
	{"https://accounts.google.com", "https://www.googleapis.com./certs", "www.googleapis.com"},
	{"https://okta.test", "https://sub.evil.test/jwks", "evil.test"},
	{"https://okta.test", "https://evil.test/jwks", ".okta.test"},
	{"https://okta.test", "https://evil.test:443/jwks", "evil.test:443"},
	{"https://okta.test", "https://\u00DF.test/jwks", "\u00DF.test"},

	// Loopback, which is admitted under any issuer, and the near misses that
	// must not be: a name that only resolves to loopback, a name that merely
	// starts with one, and the IP spellings net.ParseIP does not accept.
	{"https://okta.test", "http://127.0.0.1:8443/jwks", ""},
	{"https://okta.test", "http://localhost:8443/jwks", ""},
	{"https://okta.test", "http://[::1]:8443/jwks", ""},
	{"https://okta.test", "https://127.0.0.1/jwks", ""},
	{"https://okta.test", "http://LOCALHOST/jwks", ""},
	{"https://okta.test", "https://localhost.localdomain/jwks", ""},
	{"https://okta.test", "http://127.0.0.1.evil.test/jwks", ""},
	{"https://okta.test", "http://localhost.evil.test/jwks", ""},
	{"https://okta.test", "http://[::ffff:127.0.0.1]/jwks", ""},
	{"https://okta.test", "http://[0:0:0:0:0:0:0:1]/jwks", ""},
	{"https://okta.test", "http://127.1/jwks", ""},
	{"https://okta.test", "http://0177.0.0.1/jwks", ""},
	{"https://okta.test", "http://2130706433/jwks", ""},
	{"https://okta.test", "http://[::1%25eth0]/jwks", ""},
	{"https://okta.test", "http://localhost:8443@evil.test/jwks", ""},

	// The label boundary, and the empty labels a suffix test can be fooled by.
	{"https://okta.test", "https://notokta.test/jwks", ""},
	{"https://okta.test", "https://okta.test.evil.test/jwks", ""},
	{"https://okta.test", "https://evil.test/jwks?issuer=okta.test", ""},
	{"https://okta.test", "https://evil.test/okta.test/jwks", ""},
	{"https://okta.test", "https://.okta.test/jwks", ""},
	{"https://okta.test", "https://okta..test/jwks", ""},

	// Trailing dots, which name the same host to a resolver and a different
	// string to every comparison written with ==.
	{"https://okta.test", "https://okta.test./jwks", ""},
	{"https://okta.test.", "https://okta.test/jwks", ""},
	{"https://okta.test.", "https://sub.okta.test./jwks", ""},
	{"https://okta.test", "https://okta.test.evil.test./jwks", ""},

	// Userinfo and embedded credentials. The host is what follows the last '@'
	// in the authority, so a reading that takes the authority whole calls
	// https://allowed.test@evil.test/ a fetch of allowed.test.
	{"https://okta.test", "https://allowed.test@evil.test/", "allowed.test"},
	{"https://okta.test", "https://okta.test@evil.test/jwks", ""},
	{"https://okta.test", "https://evil.test@okta.test/jwks", ""},
	{"https://okta.test", "https://okta.test:hunter2@evil.test/jwks", ""},
	{"https://okta.test", "https://user:pass@okta.test/jwks", ""},
	{"https://okta.test", "https://okta.test%40evil.test/jwks", ""},
	{"https://okta.test", "https://evil.test#@okta.test/jwks", ""},
	{"https://okta.test", "https://okta.test\\@evil.test/jwks", ""},

	// Case and Unicode. strings.ToLower and UTS-46 disagree about several of
	// these: the Kelvin sign lowercases to "k", the ideographic and fullwidth
	// stops become label separators only under IDNA, the soft hyphen is deleted
	// only under IDNA, and the capital sharp s reaches the wire as "ss".
	{"https://okta.test", "https://o\u212Ata.test/jwks", ""},
	{"https://okta.test", "https://okta.test\u3002evil.test/jwks", ""},
	{"https://okta.test", "https://evil.test\uFF0Eokta.test/jwks", ""},
	{"https://okta.test", "https://ok\u00ADta.test/jwks", ""},
	{"https://okta.test", "https://okta.test\u200B.evil.test/jwks", ""},
	{"https://okta.test", "https://\u0131.okta.test/jwks", ""},
	{"https://okta.test", "https://xn--okta.test/jwks", ""},
	{"https://\u00F6kta.test", "https://sub.\u00D6KTA.test/jwks", ""},
	{"https://xn--kta-sna.test", "https://\u00F6kta.test/jwks", ""},
	// The four below WERE the finding. They pass now, and are kept as
	// regression seeds: each is a spelling that reached the wire as a
	// different host than the one the domain rule read. Closed by refusing a
	// non-ASCII host outright (hostOf / isASCIIHost in outbound.go) rather
	// than trying to agree with UTS-46 about what it folds to -- two
	// normalisations that are nearly the same map is the bug, having only one
	// is the fix.
	//
	// What they were: hostOf compared strings.ToLower(host)
	// while net/http connected to the host UTS-46 produced, and those two
	// normalisations are not the same map. U+1E9E lowercases to U+00DF but
	// reaches the wire as "ss", so an endpoint spelled with it is admitted as
	// the issuer's own host and dialed at another domain. U+0130 lowercases to
	// a plain ASCII "i", which makes an ASCII issuer enough: a document naming
	// login.microsoftonl<U+0130>ne.com reads as exactly login.microsoftonline.com
	// to the domain rule and to the operator list, and net/http opens the
	// connection to login.xn--microsoftonline-fqi.com, a .com anybody can
	// register. That host then serves the keys every id_token signature is
	// checked against, or receives the POST that carries client_secret.
	{"https://\u00DF.test", "https://\u1E9E.test/jwks", ""},
	{"https://login.microsoftonline.com", "https://login.microsoftonl\u0130ne.com/common/discovery/v2.0/keys", ""},
	{"https://pingidentity.test", "https://p\u0130ngidentity.test/jwks", ""},
	{"https://okta.test", "https://microsoftonl\u0130ne.com/jwks", "microsoftonline.com"},

	// Percent-encoding. url.Parse unescapes the host, so a spelling that hides
	// a delimiter behind an escape either decodes into a different host or is
	// refused outright, and both answers have to hold.
	{"https://okta.test", "https://%6Fkta.test/jwks", ""},
	{"https://okta.test", "https://okta.test%2Fevil.test/jwks", ""},
	{"https://okta.test", "https://okta.test%2Eevil.test/jwks", ""},
	{"https://okta.test", "https://okta.test%25evil.test/jwks", ""},
	{"https://okta.test", "https://okta.test%00.evil.test/jwks", ""},
	{"https://okta.test", "https://evil.test/%2E%2E/okta.test", ""},

	// The destinations a forged server-side request actually wants, and the
	// rebinding shape: a name inside the issuer's own domain whose answer
	// points into the deployment.
	{"https://okta.test", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ""},
	{"https://okta.test", "http://[::ffff:169.254.169.254]/latest/meta-data/", ""},
	{"https://okta.test", "http://metadata.google.internal/computeMetadata/v1/", ""},
	{"https://okta.test", "http://rebind.okta.test/jwks", ""},
	{"https://okta.test", "http://100.64.0.1/jwks", ""},
	{"https://okta.test", "http://[fe80::1%25eth0]/jwks", ""},
	{"https://okta.test", "http://10.0.0.1/jwks", ""},
	{"https://okta.test", "http://[::]/jwks", ""},

	// Inputs one side or the other cannot read at all, including the issuers a
	// broken configuration produces. A URL that names no host and an issuer
	// that does not parse both have to fail closed.
	{"https://okta.test", "://nonsense", ""},
	{"https://okta.test", "file:///etc/vault42/jwks.json", ""},
	{"https://okta.test", "gopher://okta.test:70/_jwks", ""},
	{"https://okta.test", "//evil.test/jwks", ""},
	{"https://okta.test", "/oauth2/v1/keys", ""},
	{"https://okta.test", "", ""},
	{"://nonsense", "https://okta.test/jwks", ""},
	{"", "https://okta.test/jwks", ""},
	{"https://", "https://okta.test/jwks", ""},
	{"https://okta.test", "https:okta.test/jwks", ""},
	{"https://okta.test", "https://okta.test:99999999/jwks", ""},
	{"https://okta.test", "https://[okta.test]/jwks", ""},
}

// FuzzCheckDerivedAdmitsOnlyPermittedDestinations drives the whole destination
// rule: the parse, the loopback exception, the operator list, the issuer domain
// test, and the re-serialization ClientForIssuer performs before it re-applies
// the rule to a redirect hop.
func FuzzCheckDerivedAdmitsOnlyPermittedDestinations(f *testing.F) {
	for _, seed := range oracleSeeds {
		f.Add(seed.issuer, seed.endpoint, seed.allowed)
	}

	f.Fuzz(func(t *testing.T, issuer, endpoint, allowedCSV string) {
		// An empty list builds the nil *Policy rather than an empty one,
		// because that is what a deployment with no VAULT_OUTBOUND_ALLOWED_HOSTS
		// holds and the two travel different code paths: allows returns early on
		// nil, and the domain rule has to be in force anyway. Fuzzing only the
		// configured policy would leave the strict case, which is the default
		// case, untested by this target.
		var (
			p       *Policy
			allowed []string
		)
		if allowedCSV != "" {
			allowed = strings.Split(allowedCSV, ",")
			p = New(allowed, false)
		}

		// url.Parse failing means hostOf failed too, so CheckDerived refused and
		// there is no accept path to judge. The parsed URL is needed either way:
		// it is what the transport dials.
		u, err := url.Parse(endpoint)
		if err != nil {
			return
		}

		// The discovery path. oidc.go hands CheckDerived the endpoint exactly as
		// the document spelled it and, on success, fetches that same string.
		if p.CheckDerived(issuer, "jwks_uri", endpoint) == nil {
			assertDialedHostIsPermitted(t, "the discovery path", issuer, endpoint, endpoint, allowed, p, u)
		}

		// The redirect path. ClientForIssuer's CheckRedirect judges
		// req.URL.String() while the transport dials req.URL, so the string that
		// is checked and the object that is fetched have been through two
		// different code paths. A URL whose host does not survive that round
		// trip is checked as one destination and connected to as another, which
		// is how a 302 carrying a client_secret leaves the issuer's domain.
		if reserialized := u.String(); reserialized != endpoint {
			if p.CheckDerived(issuer, "redirect", reserialized) == nil {
				assertDialedHostIsPermitted(t, "the redirect path", issuer, endpoint, reserialized, allowed, p, u)
			}
		}
	})
}

// assertDialedHostIsPermitted is the invariant. It runs only where CheckDerived
// has already said yes, and it asks the one question the refusal message
// promises an answer to: whose host is about to be connected to.
func assertDialedHostIsPermitted(t *testing.T, phase, issuer, endpoint, checked string, allowed []string, p *Policy, u *url.URL) {
	t.Helper()

	host, ok := dialTarget(u)
	if !ok {
		// net/http would not dial this URL at all, so no destination is reached
		// and the property is vacuous. internal/oauth2 refuses the same URLs one
		// step earlier, at fetchableEndpoint's scheme check.
		return
	}
	if oracleIsLoopback(host) {
		return
	}
	for _, permitted := range oracleAllowedHosts(allowed) {
		if host == permitted {
			return
		}
	}
	for _, base := range oracleIssuerBases(issuer) {
		if oracleUnderDomain(host, base) {
			return
		}
	}

	// Reaching here means a discovery document has steered vault42 at a host
	// nobody vouched for: not the issuer's, not the operator's, and not the
	// local process. Depending on which field carried it, that is the id_token
	// signing keys served by a stranger, or a client_secret posted to one.
	t.Fatalf("CheckDerived ACCEPTED %q on %s under issuer %q, but net/http would open the "+
		"connection to host %q, which is not a loopback destination, is not one of the hosts "+
		"the operator listed (%q), and is neither the issuer's host nor a subdomain of it on a "+
		"label boundary (%q).\nchecked string: %q\nparsed hostname: %q\nallowPrivate: %t",
		endpoint, phase, issuer, host, oracleAllowedHosts(allowed), oracleIssuerBases(issuer),
		checked, u.Hostname(), p.privateAllowed())
}
