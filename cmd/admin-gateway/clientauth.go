package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/42-v/vault42/internal/audit"
)

// clientIdentityPolicy is the second half of the admin gateway's mTLS gate.
//
// The first half is the TLS stack's own: ClientAuth: RequireAndVerifyClientCert
// with a ClientCAs pool built from ADMIN_GW_CLIENT_CA_FILE. That answers one
// question — was this certificate signed by our CA — and nothing looked at the
// peer certificate afterwards. Every operator identity therefore came from the
// Bearer session token in adminapi.SessionAuth, and mTLS was a coarse gate that
// any certificate the CA ever issued passed: a decommissioned operator's, a
// service certificate, one minted for a different component. All of them reached
// POST /admin/login and, from there, AR-8's effectively-global per-IP limiter.
//
// docs/security.md AR-9 accepts that on the grounds that the CA is
// single-purpose. That is sound for one operator and degrades with every
// additional certificate the CA signs, which is exactly the direction a
// long-lived admin CA travels.
//
// This adds the two checks the accepted risk names as missing:
//
//   - identity pinning, against ADMIN_GW_CLIENT_CN_ALLOWLIST;
//   - revocation, against ADMIN_GW_CLIENT_CRL_FILE.
//
// Both are configurable and both fail closed once configured. Neither is
// mandatory, because refusing to start without them would break every existing
// deployment on upgrade; an unset allowlist logs a warning naming the
// consequence, the same shape cmd/vault uses for its key-retention warning.
type clientIdentityPolicy struct {
	// allowed is the set of acceptable client identities. Empty pins nothing.
	allowed []allowEntry
	// crlFiles are the paths to PEM or DER revocation lists, one per CA that
	// publishes one. Empty checks nothing.
	crlFiles []string
	// issuers are the CAs in ADMIN_GW_CLIENT_CA_FILE. A list this gateway
	// cannot attribute to one of its own authorities is an attacker-supplied
	// file that could revoke every operator, so the signature is checked before
	// the contents are believed. All of them, not just the first: a bundle with
	// two CAs is the ordinary shape of a rotation, and only being able to
	// authenticate a list from the first one left the second one's operators
	// unrevokable.
	issuers []*x509.Certificate
	// seen remembers the newest revocation list accepted from each issuer, so a
	// list cannot be rolled back to an older revision. Shared by pointer because
	// verifyConnection is installed as a method value on a copy of the policy.
	seen *crlHighWater
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

// allowKind names the certificate field an allowlist entry pins.
//
// The list used to be untyped: one flat set of strings compared against the
// common name, then the DNS SANs, then the email SANs, then the URI SANs. An
// operator who wrote ADMIN_GW_CLIENT_CN_ALLOWLIST=admin-operator meaning "the
// common name" got a pin whose field the certificate holder chose — a
// certificate with CN=some-service and DNSNames=["admin-operator"] passed it,
// and so did the email and URI spellings.
//
// That is worse than untidy. Go applies X.509 name constraints to SANs only, so
// a name-constrained sub-CA in the bundle — one added precisely to bound what it
// may issue — can still mint a certificate carrying an allowlisted common name
// and no SANs at all.
type allowKind string

const (
	// allowAny is an entry written with no prefix. See allowEntry.matches for
	// what it means and why it deliberately means so little.
	allowAny allowKind = ""

	allowCN    allowKind = "cn"
	allowDNS   allowKind = "dns"
	allowEmail allowKind = "email"
	allowURI   allowKind = "uri"
)

// allowEntry is one parsed ADMIN_GW_CLIENT_CN_ALLOWLIST entry.
type allowEntry struct {
	kind  allowKind
	value string
	// raw is the entry as the operator wrote it, for the startup log.
	raw string
}

// parseAllowlist types the configured entries.
//
// The prefix is matched case-insensitively because the four scheme names belong
// to this gateway rather than to the certificate, and `CN:ops` is a spelling an
// operator will reach for. The value after it is left exactly as written: that
// half is compared against a certificate and must stay case-sensitive, or
// "OPS.VAULT.INTERNAL" starts admitting "ops.vault.internal".
//
// An entry whose prefix is not one of the four is untyped, which is what keeps
// `spiffe://...` — a value that contains a colon — parsing as it always did.
func parseAllowlist(entries []string) []allowEntry {
	out := make([]allowEntry, 0, len(entries))
	for _, raw := range entries {
		entry := allowEntry{kind: allowAny, value: raw, raw: raw}
		if prefix, rest, found := strings.Cut(raw, ":"); found {
			switch kind := allowKind(strings.ToLower(prefix)); kind {
			case allowCN, allowDNS, allowEmail, allowURI:
				entry.kind, entry.value = kind, rest
			case allowAny:
			}
		}
		out = append(out, entry)
	}
	return out
}

// matches reports whether leaf satisfies this entry. sanPresent is passed in
// rather than recomputed because it is the same answer for every entry and it
// costs a scan of the certificate's extensions.
//
// The common name is honored only on a certificate that carries no subject
// alternative name at all. That is the CA/Browser Forum rule, and RFC 5280 has
// called the CN deprecated for identity for twenty years, but the reason it
// belongs in a gateway is narrower: the CN is the one name field X.509 name
// constraints do not cover, so honoring it beside a SAN hands the pin to
// whoever holds a constrained sub-CA key.
//
// An untyped entry matches a DNS SAN, plus that SAN-less common name. Not the
// email or URI SANs: those are pinnable with email: and uri:, which say so, and
// widening the untyped form to reach them is precisely what let the certificate
// holder pick the field. An empty value matches nothing, so a malformed `cn:`
// entry fails closed instead of matching every certificate with no common name.
func (e allowEntry) matches(leaf *x509.Certificate, sanPresent bool) bool {
	if e.value == "" {
		return false
	}
	switch e.kind {
	case allowCN:
		return !sanPresent && leaf.Subject.CommonName == e.value
	case allowDNS:
		return slices.Contains(leaf.DNSNames, e.value)
	case allowEmail:
		return slices.Contains(leaf.EmailAddresses, e.value)
	case allowURI:
		return slices.ContainsFunc(leaf.URIs, func(u *url.URL) bool { return u.String() == e.value })
	case allowAny:
		return slices.Contains(leaf.DNSNames, e.value) ||
			(!sanPresent && leaf.Subject.CommonName == e.value)
	}
	return false
}

// oidSubjectAltName is RFC 5280 §4.2.1.6. The parsed DNSNames, EmailAddresses,
// IPAddresses and URIs fields cover every SAN type crypto/x509 understands, and
// the extension OID covers the ones it does not — a certificate carrying only an
// otherName has four empty slices and a subjectAltName extension, and it must
// still count as carrying a SAN or its common name becomes live again.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// hasSAN reports whether leaf carries any subject alternative name.
func hasSAN(leaf *x509.Certificate) bool {
	if len(leaf.DNSNames) > 0 || len(leaf.EmailAddresses) > 0 ||
		len(leaf.IPAddresses) > 0 || len(leaf.URIs) > 0 {
		return true
	}
	return slices.ContainsFunc(leaf.Extensions, func(ext pkix.Extension) bool {
		return ext.Id.Equal(oidSubjectAltName)
	})
}

// checkIdentity refuses a leaf that satisfies no allowlist entry.
//
// Matching is an exact string comparison within the field the entry names.
// Exact rather than prefix or suffix, because an admin plane's allowlist is
// short, operator-written and reviewed: a substring rule would let "ops" admit
// "ops-decommissioned" and nobody would notice until it mattered.
func (p clientIdentityPolicy) checkIdentity(leaf *x509.Certificate) error {
	if len(p.allowed) == 0 {
		return nil
	}
	sanPresent := hasSAN(leaf)
	for _, entry := range p.allowed {
		if entry.matches(leaf, sanPresent) {
			return nil
		}
	}
	return fmt.Errorf("admin-gateway: client certificate identity (%s) is not in ADMIN_GW_CLIENT_CN_ALLOWLIST",
		describeIdentity(leaf))
}

// identityNamesInError caps how many of a certificate's names reach the refusal
// message. A certificate may carry hundreds of SANs, all chosen by whoever holds
// it, and the message is a log line.
const identityNamesInError = 8

// describeIdentity renders the names a certificate offers. Every one of them is
// attacker-chosen and reaches a log, so each goes through %q (CWE-117).
func describeIdentity(leaf *x509.Certificate) string {
	total := len(leaf.DNSNames) + len(leaf.EmailAddresses) + len(leaf.URIs)
	if leaf.Subject.CommonName != "" {
		total++
	}

	names := make([]string, 0, identityNamesInError+1)
	add := func(kind allowKind, value string) {
		if len(names) < identityNamesInError {
			names = append(names, fmt.Sprintf("%s:%q", kind, value))
		}
	}
	if leaf.Subject.CommonName != "" {
		add(allowCN, leaf.Subject.CommonName)
	}
	for _, name := range leaf.DNSNames {
		add(allowDNS, name)
	}
	for _, addr := range leaf.EmailAddresses {
		add(allowEmail, addr)
	}
	for _, u := range leaf.URIs {
		add(allowURI, u.String())
	}

	if len(names) == 0 {
		return "no common name and no SANs"
	}
	if total > len(names) {
		names = append(names, fmt.Sprintf("and %d more", total-len(names)))
	}
	return strings.Join(names, ", ")
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

// crlClockSkew is how far ahead of this gateway's clock a revocation list may be
// dated before it is refused. A list whose own issuance date has not happened
// yet is not evidence about anything; a few minutes of allowance is the ordinary
// spread between two hosts that both believe they are synchronized.
const crlClockSkew = 5 * time.Minute

// crlHighWater remembers the newest revocation list accepted from each issuer.
//
// The list is re-read on every handshake, which is what lets a revocation take
// effect without restarting the admin plane. It also means whoever can write the
// file chooses which revision the gateway believes — and an older revision of a
// genuine, CA-signed, still-in-window list un-revokes everyone revoked since.
// That attack needs no CA key: it needs one file write, over a file an operator
// is expected to rewrite.
//
// The mark lives for the lifetime of the process and is seeded at startup from
// whatever is on disk. It is not written down anywhere, because the gateway runs
// with a read-only root filesystem whose only writable mount is a tmpfs that
// does not survive a restart either; a restart therefore re-seeds from the file.
// An attacker who can both write the CRL and restart the pod can still roll it
// back, and that is a strictly larger capability than this defect required.
type crlHighWater struct {
	mu    sync.Mutex
	marks map[string]crlMark
}

// crlMark is the newest (number, thisUpdate) pair seen from one issuer.
type crlMark struct {
	number     *big.Int
	thisUpdate time.Time
}

func newCRLHighWater() *crlHighWater {
	return &crlHighWater{marks: make(map[string]crlMark)}
}

// admit refuses a revocation list older than one already accepted from the same
// issuer, and records it otherwise.
//
// Both fields are compared because either may be absent or equal: crlNumber is a
// MUST in RFC 5280 that not every generator honors, and two lists issued in the
// same second are indistinguishable by date. A nil receiver admits everything,
// which is what an in-process test constructing a bare policy gets.
func (h *crlHighWater) admit(crl *x509.RevocationList) error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	key := string(crl.RawIssuer)
	mark, seen := h.marks[key]
	if seen {
		if err := mark.refuseRollback(crl); err != nil {
			return err
		}
	}
	if crl.Number != nil && (mark.number == nil || crl.Number.Cmp(mark.number) > 0) {
		mark.number = crl.Number
	}
	if crl.ThisUpdate.After(mark.thisUpdate) {
		mark.thisUpdate = crl.ThisUpdate
	}
	h.marks[key] = mark
	return nil
}

// refuseRollback reports why crl is older than the mark, or nil if it is not.
func (m crlMark) refuseRollback(crl *x509.RevocationList) error {
	const why = "an earlier list un-revokes every certificate revoked since it was issued, " +
		"and replacing the file needs no CA key"
	// The issuer is quoted because it reaches a log (CWE-117).
	issuer := crl.Issuer.String()
	if crl.Number != nil && m.number != nil && crl.Number.Cmp(m.number) < 0 {
		return fmt.Errorf("CRL number %s is older than number %s, already accepted from %q: %s",
			crl.Number, m.number, issuer, why)
	}
	if crl.ThisUpdate.Before(m.thisUpdate) {
		return fmt.Errorf("CRL thisUpdate %s is older than %s, already accepted from %q: %s",
			crl.ThisUpdate.Format(time.RFC3339), m.thisUpdate.Format(time.RFC3339), issuer, why)
	}
	return nil
}

// checkRevocation refuses a chain any of whose certificates appears on a
// configured revocation list.
//
// The whole chain, not just the leaf. Everything above the leaf — the sub-CA an
// operator delegated issuance to, and whose key is the one worth stealing — was
// otherwise unrevokable: publishing its serial changed nothing and it went on
// minting leaves that verified and passed.
//
// A serial only counts against a certificate its own issuer revoked. Serial
// numbers are unique within one issuer and nowhere else, and CAs that hand out
// sequential ones collide by construction: comparing serials alone meant CA-A's
// CRL refused CA-B's live operators.
//
// Every failure here refuses the handshake. A CRL that cannot be read, cannot be
// parsed, is not signed by any configured CA, carries no nextUpdate, is dated in
// the future, is past its nextUpdate or has gone backwards is not evidence that
// a certificate is unrevoked; carrying on would turn a revocation the operator
// published into one the gateway silently ignores.
func (p clientIdentityPolicy) checkRevocation(chain []*x509.Certificate) error {
	if len(p.crlFiles) == 0 {
		return nil
	}
	crls, err := p.loadCRLs()
	if err != nil {
		return err
	}
	for _, cert := range chain {
		for _, crl := range crls {
			if !bytes.Equal(crl.RawIssuer, cert.RawIssuer) {
				continue
			}
			for i := range crl.RevokedCertificateEntries {
				if crl.RevokedCertificateEntries[i].SerialNumber.Cmp(cert.SerialNumber) == 0 {
					// The issuer is quoted because it reaches a log (CWE-117)
					// and is chosen by whoever holds the certificate.
					return fmt.Errorf("admin-gateway: certificate serial %s issued by %q is revoked",
						cert.SerialNumber, cert.Issuer.String())
				}
			}
		}
	}
	return nil
}

// loadCRLs reads, authenticates and freshness-checks every configured list.
//
// They are re-read on every handshake rather than cached from startup. A
// revocation is published precisely when an operator has just lost a key, and a
// gateway that only reads its CRL at boot answers that with "restart the admin
// plane" — which is the same operational cost as rotating the CA, i.e. the cost
// AR-9 says makes revocation impractical. Handshakes against a loopback admin
// plane are rare enough that one file read each is not a budget worth saving.
func (p clientIdentityPolicy) loadCRLs() ([]*x509.RevocationList, error) {
	crls := make([]*x509.RevocationList, 0, len(p.crlFiles))
	from := make(map[string]string, len(p.crlFiles))
	for _, path := range p.crlFiles {
		crl, err := loadCRL(path, p.issuers)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		// One list per CA, and not two. Two lists from the same issuer load in
		// ascending order and then fail on the next handshake, because by then
		// the older of the two is a rollback against the mark the newer one set
		// — a gateway that boots reporting revocation as configured and refuses
		// every login from the first handshake onwards.
		if other, duplicate := from[string(crl.RawIssuer)]; duplicate {
			return nil, fmt.Errorf("%s: a revocation list from the same issuer is already configured at "+
				"%s, and only one of the two can decide which serials are revoked", path, other)
		}
		from[string(crl.RawIssuer)] = path
		if err := p.seen.admit(crl); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		crls = append(crls, crl)
	}
	return crls, nil
}

// loadCRL reads, parses and authenticates one revocation list. Accepts PEM or
// raw DER, because both spellings come out of the usual CA tooling.
func loadCRL(path string, issuers []*x509.Certificate) (*x509.RevocationList, error) {
	raw, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 — path from operator-controlled env var
	if err != nil {
		return nil, fmt.Errorf("read CRL: %w", err)
	}
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}
	if len(issuers) == 0 {
		return nil, errors.New("no client CA certificate to authenticate the CRL against")
	}
	if !signedByAny(crl, issuers) {
		return nil, errors.New("CRL is not signed by any CA in the configured client CA bundle")
	}
	return crl, checkCRLWindow(crl)
}

// signedByAny reports whether any configured CA signed this list.
//
// CheckSignatureFrom additionally enforces that the signer is a CA carrying the
// cRLSign key usage, so a leaf certificate that happens to be in the bundle
// cannot authenticate a revocation list.
func signedByAny(crl *x509.RevocationList, issuers []*x509.Certificate) bool {
	return slices.ContainsFunc(issuers, func(ca *x509.Certificate) bool {
		return crl.CheckSignatureFrom(ca) == nil
	})
}

// checkCRLWindow refuses a list whose validity cannot be established.
//
// nextUpdate is OPTIONAL in RFC 5280, and the freshness guard used to skip the
// check when it was absent — so a CA-signed list dated 2020 was accepted
// forever. It has to be a refusal rather than a warning because of the loop it
// closes: an expired list refuses every handshake and locks the operator out,
// and the shortest command that regenerates one (`openssl ca -gencrl` with no
// -crldays) omits nextUpdate. The lockout would then be recovered by
// permanently freezing revocation checking, with nothing saying so.
func checkCRLWindow(crl *x509.RevocationList) error {
	now := time.Now()
	if crl.ThisUpdate.After(now.Add(crlClockSkew)) {
		return fmt.Errorf("CRL thisUpdate is %s, which is in the future: it was issued against a clock this "+
			"gateway does not share, and a list that has not been issued yet is not evidence about anything",
			crl.ThisUpdate.Format(time.RFC3339))
	}
	if crl.NextUpdate.IsZero() {
		return errors.New("CRL carries no nextUpdate, so it can never go stale and its freshness cannot be " +
			"checked at all; regenerate it with an expiry, e.g. `openssl ca -gencrl -crldays 7 -out client.crl`")
	}
	if now.After(crl.NextUpdate) {
		return fmt.Errorf("CRL expired at %s; it cannot list a certificate revoked since",
			crl.NextUpdate.Format(time.RFC3339))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

// newClientIdentityPolicy builds the peer policy from configuration and reports
// what it will enforce.
//
// A CRL path is validated here as well as on every handshake: a path that is
// wrong must be a boot failure the operator sees immediately, not a gateway that
// comes up reporting revocation checking as configured and then refuses every
// operator at the first login.
//
// An unset allowlist is permitted, because refusing to start on it would break
// every existing deployment on upgrade, but it is never silent: the whole content
// of AR-9 is that the CA is then the only boundary, and an operator has to be
// able to read that off the startup log.
func newClientIdentityPolicy(ctx context.Context, auditLogger *audit.Logger, cfg *Config, clientCA []byte) clientIdentityPolicy {
	policy := clientIdentityPolicy{
		allowed:  parseAllowlist(cfg.ClientCNAllowlist),
		crlFiles: cfg.ClientCRLFiles,
		issuers:  allCertificates(clientCA),
		seen:     newCRLHighWater(),
	}
	if len(policy.crlFiles) > 0 {
		crls, err := policy.loadCRLs()
		if err != nil {
			fatalAfterDrain(ctx, auditLogger, "admin-gateway: failed to load client CRL: %v", err)
		}
		log.Printf("admin-gateway: client certificate chains checked on every handshake against %d revocation list(s): %s",
			len(policy.crlFiles), strings.Join(policy.crlFiles, ", "))
		warnUnrevokableCAs(policy.issuers, crls)
	}
	logAllowlistPosture(policy.allowed)
	return policy
}

// warnUnrevokableCAs names every CA in the bundle that publishes no list.
//
// One CRL cannot speak for two authorities: it revokes serials issued by its own
// issuer and says nothing about anyone else's. A bundle with a second CA and one
// CRL is therefore a gateway that cannot revoke half its operators, and that has
// to be readable off the startup log rather than discovered the day a revocation
// does not take.
func warnUnrevokableCAs(issuers []*x509.Certificate, crls []*x509.RevocationList) {
	for _, ca := range issuers {
		covered := slices.ContainsFunc(crls, func(crl *x509.RevocationList) bool {
			return bytes.Equal(crl.RawIssuer, ca.RawSubject)
		})
		if !covered {
			log.Printf("SECURITY WARNING: no revocation list is configured for client CA %q — nothing it has "+
				"signed can be revoked, so a decommissioned operator holding one of its certificates still "+
				"reaches the admin plane (AR-9)", ca.Subject.String())
		}
	}
}

// logAllowlistPosture reports what the allowlist pins, and what it is guessing.
func logAllowlistPosture(allowed []allowEntry) {
	if len(allowed) == 0 {
		log.Printf("SECURITY WARNING: ADMIN_GW_CLIENT_CN_ALLOWLIST is unset — every certificate this CA has ever " +
			"signed reaches the admin plane, including one issued for a decommissioned operator or another component (AR-9)")
		return
	}
	log.Printf("admin-gateway: client certificate identity pinned to %d allowed subject(s)", len(allowed))

	var untyped []string
	for _, entry := range allowed {
		if entry.value == "" {
			log.Printf("admin-gateway: ADMIN_GW_CLIENT_CN_ALLOWLIST entry %q has no value after its prefix "+
				"and therefore matches nothing", entry.raw)
			continue
		}
		if entry.kind == allowAny {
			untyped = append(untyped, strconv.Quote(entry.raw))
		}
	}
	if len(untyped) > 0 {
		log.Printf("admin-gateway: %d ADMIN_GW_CLIENT_CN_ALLOWLIST entries carry no field prefix (%s): each "+
			"matches a DNS SAN, and the subject common name only on a certificate that carries no SAN at all. "+
			"Write cn:, dns:, email: or uri: to pin the field yourself — an untyped entry leaves part of that "+
			"choice to whoever holds the certificate", len(untyped), strings.Join(untyped, ", "))
	}
}

// enabled reports whether the policy has anything to enforce. A policy with
// neither an allowlist nor a CRL is the pre-existing behavior and is not wired
// into the TLS config at all, so the handshake path stays exactly as it was.
func (p clientIdentityPolicy) enabled() bool {
	return len(p.allowed) > 0 || len(p.crlFiles) > 0
}

// verifyConnection is the tls.Config.VerifyConnection callback. It runs after
// the standard chain verification, so state.VerifiedChains is populated and the
// leaf is already known to chain to ClientCAs.
func (p clientIdentityPolicy) verifyConnection(state tls.ConnectionState) error {
	chain := verifiedChain(state)
	if len(chain) == 0 {
		// Unreachable behind RequireAndVerifyClientCert, which refuses the
		// handshake before any callback when the peer sends no certificate.
		// Refusing here anyway keeps the failure a handshake error rather than a
		// nil dereference inside the TLS goroutine if that ever changes.
		return errors.New("admin-gateway: client presented no certificate")
	}
	if err := p.checkIdentity(chain[0]); err != nil {
		return err
	}
	return p.checkRevocation(chain)
}

// verifiedChain returns the chain revocation has to cover: the one the verifier
// built, which carries the intermediates, with the raw peer chain as a fallback
// so a state without VerifiedChains checks the leaf rather than nothing.
func verifiedChain(state tls.ConnectionState) []*x509.Certificate {
	if len(state.VerifiedChains) > 0 && len(state.VerifiedChains[0]) > 0 {
		return state.VerifiedChains[0]
	}
	return state.PeerCertificates
}

// allCertificates returns every certificate in a PEM bundle — the CAs a CRL may
// be signed by, and the issuers a revoked serial is attributed to. Empty when
// the bundle holds none: unreachable in main, where AppendCertsFromPEM has
// already refused a bundle with no parseable certificate, and handled anyway
// because loadCRL must never treat "no issuer to check against" as "the
// signature is fine".
func allCertificates(pemBundle []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for rest := pemBundle; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return certs
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}
