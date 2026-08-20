// Package outbound decides which destinations vault42 may open a connection to.
//
// The decision is not uniform across vault42's outbound calls, because the
// calls are not alike. Most destinations are settled before the process starts:
// SendGrid, the HIBP range API and the Google, GitHub and Facebook endpoints are
// compiled-in https literals that no input reaches, and the SMTP relay and the
// OIDC issuer are operator configuration. An allowlist over those buys nothing.
// A literal in the binary cannot be pointed anywhere, and an operator who can
// set a URL can already reach whatever the pod can reach — a list they also
// write is a list they can also widen.
//
// Four destinations are different. authorization_endpoint, token_endpoint,
// userinfo_endpoint and jwks_uri come from the issuer's discovery document,
// which is data fetched over the network rather than configuration. They are
// the whole of vault42's server-side request forgery surface, and they are what
// this package exists for.
//
// The trust boundary it draws: an operator who configures an issuer has vouched
// for that issuer's own domain and for nothing beyond it. So a discovery
// document may name hosts under the issuer's domain, and any other host has to
// be named by the operator in VAULT_OUTBOUND_ALLOWED_HOSTS. That boundary is
// where an operator's trust actually stops — they chose the provider, not the
// provider's opinion about where its keys live — and it is enforceable without
// a public suffix list, which is a dependency and a data file that goes stale.
//
// It costs availability in one real case, and the refusal says so: an issuer
// whose endpoints legitimately span domains needs a list entry. Google's OIDC
// issuer is accounts.google.com while its keys are served from
// www.googleapis.com, which is not even the same registrable domain.
package outbound

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dialTimeout bounds the TCP connect. It matches internal/oauth2's fallback
// client rather than introducing a second number for the same thing.
const dialTimeout = 5 * time.Second

// sharedAddressSpace is RFC 6598 carrier-grade NAT space. net.IP.IsPrivate does
// not cover it and a cloud provider's internal fabric frequently does, so a
// destination in it is inside somebody's network even though it is not RFC 1918.
var sharedAddressSpace = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// Policy holds the operator's widenings of two rules that hold without any
// configuration at all: a discovery-supplied endpoint stays inside the issuer's
// domain, and an outbound connection does not land inside the deployment.
//
// The nil *Policy is usable and means "no widenings". A caller that has no
// operator configuration to apply therefore gets the strict behavior rather
// than none, which is why the domain rule has no off switch and needs no wiring
// to be in force.
type Policy struct {
	allowedHosts map[string]struct{}
	allowPrivate bool
}

// New builds a policy. allowedHosts are the destinations an operator has
// declared beyond the issuer's own domain, compared case-insensitively and
// exactly — a listed host admits that host and not its subdomains, because the
// entry exists precisely for the provider that put its keys somewhere the
// domain rule cannot reach, and widening it to a subtree would hand that
// provider the subtree.
//
// allowPrivate permits destinations that resolve inside the deployment:
// loopback, RFC 1918, IPv6 unique-local and RFC 6598. A deployment whose
// identity provider is a pod in the same cluster needs it; one whose providers
// are on the internet does not, and leaving it off is what makes a name that
// resolves into the cluster a refusal rather than a request.
func New(allowedHosts []string, allowPrivate bool) *Policy {
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, h := range allowedHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		allowed[h] = struct{}{}
	}
	return &Policy{allowedHosts: allowed, allowPrivate: allowPrivate}
}

// ValidateAllowedHosts reports an operator entry that no destination can match.
//
// hostOf refuses a URL whose host carries non-ASCII bytes, because the name
// this package reads and the name net/http dials are normalized differently.
// An allowlist entry written in that same non-ASCII form is therefore dead: a
// discovery document names the punycode, the entry names the Unicode, and the
// two never compare equal. What the operator is left with is their host sitting
// in the configuration and a refusal naming it at request time, which is the
// most confusing pair of facts this package could hand them.
//
// So the entry is refused where it is written rather than where it fails, and
// the message says which spelling to write instead.
func ValidateAllowedHosts(hosts []string) error {
	for _, h := range hosts {
		trimmed := strings.TrimSpace(h)
		if trimmed == "" {
			continue
		}
		if !isASCIIHost(trimmed) {
			return fmt.Errorf("VAULT_OUTBOUND_ALLOWED_HOSTS names %q, which carries bytes "+
				"outside the printable ASCII range; a discovery document reaches this check "+
				"in punycode, so the entry as written can never match and the destination "+
				"stays refused; write the punycode form of the name instead", trimmed)
		}
	}
	return nil
}

// CheckDerived reports whether vault42 may fetch endpoint, a URL that a
// provider's own document named rather than one an operator configured. field
// is the document key it arrived under, so a refusal says which one.
//
// This runs before the fetch, not after. A destination check that judges a
// response has already let whoever answered have their say.
func (p *Policy) CheckDerived(issuer, field, endpoint string) error {
	host, err := hostOf(endpoint)
	if err != nil {
		return fmt.Errorf("%s %q: %w", field, endpoint, err)
	}
	if isLoopbackHost(host) {
		// Not a network destination: there is no segment for anyone to sit on,
		// and nothing reachable that this process could not reach directly.
		// internal/oauth2's scheme check makes the same exception for the same
		// reason, and the two have to agree or a developer's own issuer stops
		// working on one of them.
		return nil
	}
	if p.allows(host) {
		return nil
	}
	issuerHost, err := hostOf(issuer)
	if err != nil {
		return fmt.Errorf("%s %q: issuer %q: %w", field, endpoint, issuer, err)
	}
	if underDomain(host, issuerHost) {
		return nil
	}
	return fmt.Errorf("%s %q names host %q, which is neither %q nor a subdomain of it; "+
		"the issuer's discovery document is data, not configuration, so a host outside "+
		"the issuer's own domain has to be one the operator named: add %q to "+
		"VAULT_OUTBOUND_ALLOWED_HOSTS to permit it",
		field, endpoint, host, issuerHost, host)
}

// allows reports whether the operator listed this host. A nil policy has no
// list, which is the whole of what a nil policy means.
func (p *Policy) allows(host string) bool {
	if p == nil {
		return false
	}
	_, ok := p.allowedHosts[host]
	return ok
}

func (p *Policy) privateAllowed() bool { return p != nil && p.allowPrivate }

// DialContext resolves the destination, judges every address it resolved to,
// and connects to one it judged.
//
// Judging at dial time rather than at URL-parse time is the point. A name the
// domain rule admits can still resolve into the deployment, either because DNS
// changed between the check and the connection or because whoever answers for
// that name chose to point it there; and a redirect names a destination that
// never passed through CheckDerived at all. Both arrive here.
//
// It connects to the address it checked rather than to the name, so there is no
// second resolution for a rebinding answer to win.
func (p *Policy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("outbound: destination %q is not host:port: %w", addr, err)
	}
	ips, err := p.resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("outbound: destination %q: %w", addr, err)
	}
	// Every answer has to pass, not merely one. A name that resolves to both a
	// routable address and an address inside the deployment is the shape of a
	// rebinding answer, and picking the one that passes is picking the answer
	// the attacker also expected to be discarded.
	for _, ip := range ips {
		if err := p.refuseAddress(ip); err != nil {
			return nil, fmt.Errorf("outbound: refusing to connect to %s: %w", addr, err)
		}
	}
	d := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

// Transport is an http.Transport that dials through this policy, with the same
// bounds internal/oauth2's fallback client sets and http.DefaultTransport does
// not.
//
// Proxy stays on ProxyFromEnvironment: a deployment behind an egress proxy is
// operator configuration, and when one is set this dials the proxy rather than
// the destination, so the guard judges the proxy's address. That is the correct
// answer for a deployment that has one — the proxy is then the thing enforcing
// where the request may go — but it is worth knowing rather than discovering.
func (p *Policy) Transport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           p.DialContext,
		MaxConnsPerHost:       64,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSHandshakeTimeout:   dialTimeout,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// Client is Transport wrapped in an http.Client with an end-to-end timeout.
//
// Redirects are followed, and DialContext still refuses private/link-local
// hop targets. Domain continuity on a redirect is not this method's job:
// CheckDerived needs the issuer, which a bare Client does not have. Callers
// that fetch discovery-derived endpoints (OIDC token, userinfo, JWKS) must
// use ClientForIssuer so a 302 off the issuer's domain cannot carry a
// client_secret to a host the operator never named.
func (p *Policy) Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: p.Transport()}
}

// ClientForIssuer is Client with CheckRedirect re-applying CheckDerived to
// every hop under issuer. Without it, an in-domain token_endpoint that 302s
// to an arbitrary public host would bypass the trust boundary DialContext
// cannot see: dial-time only judges address class, not whose host it is.
func (p *Policy) ClientForIssuer(issuer string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: p.Transport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("outbound: stopped after 10 redirects")
			}
			if err := p.CheckDerived(issuer, "redirect", req.URL.String()); err != nil {
				return fmt.Errorf("outbound: refusing redirect: %w", err)
			}
			return nil
		},
	}
}

// resolve answers with the addresses a destination names. An address literal
// names itself and is not handed to a resolver.
func (p *Policy) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// refuseAddress judges one resolved address.
func (p *Policy) refuseAddress(ip net.IP) error {
	switch {
	case ip.IsUnspecified():
		return fmt.Errorf("%s is the unspecified address", ip)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		// 169.254.0.0/16 is where every major cloud answers instance metadata,
		// including the credentials attached to the node. It is the single most
		// valuable destination a forged server-side request has, and no
		// identity provider or breach-check API is ever on it, so this one has
		// no escape hatch.
		return fmt.Errorf("%s is link-local, the range cloud instance metadata answers on", ip)
	case ip.IsMulticast():
		return fmt.Errorf("%s is a multicast address", ip)
	}
	if p.privateAllowed() {
		return nil
	}
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("%s is a loopback address; set VAULT_OUTBOUND_ALLOW_PRIVATE=true if this deployment's providers run on the local host", ip)
	case ip.IsPrivate(), sharedAddressSpace.Contains(ip):
		return fmt.Errorf("%s is inside a private network; set VAULT_OUTBOUND_ALLOW_PRIVATE=true if this deployment's providers are on the internal network", ip)
	}
	return nil
}

// hostOf extracts the host this allowlist will judge, and refuses any host that
// would not reach the wire unchanged.
//
// The refusal is the security control, not tidiness. This function used to
// return strings.ToLower(u.Hostname()), and every caller then compared that
// against the issuer or the operator's list -- while the connection is opened to
// the host net/http produces, which runs the same string through UTS-46/IDNA in
// canonicalAddr. strings.ToLower and IDNA are not the same map, so the check and
// the dial could disagree about which host a URL names.
//
// One rune made that exploitable against a plain ASCII issuer. U+0130, the Turkish
// dotted capital I, lowercases to an ordinary ASCII "i", so a discovery document
// advertising
//
//	https://login.microsoftonlİne.com/common/discovery/v2.0/keys
//
// read as login.microsoftonline.com here, passed underDomain against an issuer of
// https://login.microsoftonline.com, and was dialed as
// login.xn--microsoftonline-fqi.com -- a .com anybody can register. Any issuer
// whose registrable domain contains the letter "i" was reachable that way, and
// the reachable fields are the whole CR-17 boundary: jwks_uri hands an attacker
// the keys every id_token signature is verified against, and token_endpoint posts
// the client secret to a stranger. A rune sweep confirms U+0130 is the only rune
// that lands in the ASCII tail, so that was the exhaustive list rather than one
// example of many.
//
// Two lesser variants of the same gap: U+1E9E lowercases to U+00DF and reaches the
// wire as "ss", and strings.ToLower collapses every byte of invalid UTF-8 to
// U+FFFD, so two different hosts compare equal.
//
// Refusing a non-ASCII host closes all three without a new dependency and costs a
// caller nothing that is legitimate: a discovery document is machine-generated,
// and an internationalized domain name is spelled in punycode by every issuer
// that serves one. Comparing idna.Lookup.ToASCII forms would be the thorough
// alternative and would add golang.org/x/net as a direct dependency, which the
// dependency policy treats as a security decision rather than a convenience.
func hostOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("is not a URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("names no host")
	}
	if !isASCIIHost(host) {
		return "", fmt.Errorf("names a host with non-ASCII bytes (%q); an internationalized "+
			"domain must be given in punycode, because the name this check reads and the name "+
			"the connection is opened to would otherwise be normalized differently", host)
	}
	// Safe now that every byte is ASCII: on ASCII, ToLower is exactly the
	// case-folding IDNA applies, and it cannot change the length or the rune
	// count.
	return strings.ToLower(host), nil
}

// isASCIIHost reports whether every byte of host is printable ASCII.
//
// Byte-wise on purpose. A rune-wise check would decode invalid UTF-8 to U+FFFD
// and report the replacement character as the offending rune, which is the same
// lossy step that made two different hosts compare equal in the first place.
func isASCIIHost(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] < 0x21 || host[i] > 0x7e {
			return false
		}
	}
	return true
}

// isLoopbackHost reports whether a host is the loopback interface by name, not
// by what it resolves to. A hostname that merely resolves to loopback today
// does not qualify: that resolution belongs to whoever answers DNS.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// underDomain reports whether host is base or a subdomain of it, on a label
// boundary. "notokta.test" ends with "okta.test" as a string and is a domain
// somebody else registered, which is exactly the registration this refuses.
func underDomain(host, base string) bool {
	return host == base || strings.HasSuffix(host, "."+base)
}
