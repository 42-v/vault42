package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
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
	allowed []string
	// crlFile is the path to a PEM or DER revocation list. Empty checks nothing.
	crlFile string
	// issuer is the CA whose signature a CRL must carry. A list this gateway
	// cannot attribute to its own authority is an attacker-supplied file that
	// could revoke every operator, so the signature is checked before the
	// contents are believed.
	issuer *x509.Certificate
}

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
		allowed: cfg.ClientCNAllowlist,
		crlFile: cfg.ClientCRLFile,
		issuer:  firstCertificate(clientCA),
	}
	if policy.crlFile != "" {
		if _, err := loadCRL(policy.crlFile, policy.issuer); err != nil {
			fatalAfterDrain(ctx, auditLogger, "admin-gateway: failed to load client CRL: %v", err)
		}
		log.Printf("admin-gateway: client certificates checked against the revocation list at %s on every handshake", policy.crlFile)
	}
	if len(policy.allowed) > 0 {
		log.Printf("admin-gateway: client certificate identity pinned to %d allowed subject(s)", len(policy.allowed))
	} else {
		log.Printf("SECURITY WARNING: ADMIN_GW_CLIENT_CN_ALLOWLIST is unset — every certificate this CA has ever " +
			"signed reaches the admin plane, including one issued for a decommissioned operator or another component (AR-9)")
	}
	return policy
}

// enabled reports whether the policy has anything to enforce. A policy with
// neither an allowlist nor a CRL is the pre-existing behavior and is not wired
// into the TLS config at all, so the handshake path stays exactly as it was.
func (p clientIdentityPolicy) enabled() bool {
	return len(p.allowed) > 0 || p.crlFile != ""
}

// verifyConnection is the tls.Config.VerifyConnection callback. It runs after
// the standard chain verification, so state.VerifiedChains is populated and the
// leaf is already known to chain to ClientCAs.
func (p clientIdentityPolicy) verifyConnection(state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 {
		// Unreachable behind RequireAndVerifyClientCert, which refuses the
		// handshake before any callback when the peer sends no certificate.
		// Refusing here anyway keeps the failure a handshake error rather than a
		// nil dereference inside the TLS goroutine if that ever changes.
		return errors.New("admin-gateway: client presented no certificate")
	}
	leaf := state.PeerCertificates[0]
	if err := p.checkIdentity(leaf); err != nil {
		return err
	}
	return p.checkRevocation(leaf)
}

// checkIdentity refuses a leaf whose subject common name and SANs are all absent
// from the allowlist.
//
// Matching is an exact string comparison against the CN, the DNS SANs, the email
// SANs and the URI SANs. Exact rather than prefix or suffix, because an admin
// plane's allowlist is short, operator-written and reviewed: a substring rule
// would let "ops" admit "ops-decommissioned" and nobody would notice until it
// mattered.
func (p clientIdentityPolicy) checkIdentity(leaf *x509.Certificate) error {
	if len(p.allowed) == 0 {
		return nil
	}
	if slices.Contains(p.allowed, leaf.Subject.CommonName) {
		return nil
	}
	for _, name := range leaf.DNSNames {
		if slices.Contains(p.allowed, name) {
			return nil
		}
	}
	for _, addr := range leaf.EmailAddresses {
		if slices.Contains(p.allowed, addr) {
			return nil
		}
	}
	for _, u := range leaf.URIs {
		if slices.Contains(p.allowed, u.String()) {
			return nil
		}
	}
	// The subject is quoted because it reaches a log (CWE-117) and is chosen by
	// whoever holds the certificate.
	return fmt.Errorf("admin-gateway: client certificate subject %q is not in ADMIN_GW_CLIENT_CN_ALLOWLIST", leaf.Subject.CommonName)
}

// checkRevocation refuses a leaf whose serial appears on the configured CRL.
//
// The list is re-read on every handshake rather than cached from startup. A
// revocation is published precisely when an operator has just lost a key, and a
// gateway that only reads its CRL at boot answers that with "restart the admin
// plane" — which is the same operational cost as rotating the CA, i.e. the cost
// AR-9 says makes revocation impractical. Handshakes against a loopback admin
// plane are rare enough that one file read each is not a budget worth saving.
//
// Every failure here refuses the handshake. A CRL that cannot be read, cannot be
// parsed, is not signed by this gateway's client CA, or is past its nextUpdate
// is not evidence that a certificate is unrevoked; carrying on would turn a
// revocation the operator published into one the gateway silently ignores.
func (p clientIdentityPolicy) checkRevocation(leaf *x509.Certificate) error {
	if p.crlFile == "" {
		return nil
	}
	crl, err := loadCRL(p.crlFile, p.issuer)
	if err != nil {
		return err
	}
	for i := range crl.RevokedCertificateEntries {
		if crl.RevokedCertificateEntries[i].SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return fmt.Errorf("admin-gateway: client certificate serial %s is revoked", leaf.SerialNumber)
		}
	}
	return nil
}

// firstCertificate returns the first certificate in a PEM bundle, which is the
// CA a CRL must be signed by. Nil when the bundle holds none — unreachable in
// main, where AppendCertsFromPEM has already refused a bundle with no parseable
// certificate, and handled anyway because loadCRL must never treat "no issuer to
// check against" as "the signature is fine".
func firstCertificate(pemBundle []byte) *x509.Certificate {
	for rest := pemBundle; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			return cert
		}
	}
	return nil
}

// loadCRL reads, parses and authenticates a revocation list. Accepts PEM or raw
// DER, because both spellings come out of the usual CA tooling.
func loadCRL(path string, issuer *x509.Certificate) (*x509.RevocationList, error) {
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
	if issuer == nil {
		return nil, errors.New("no client CA certificate to authenticate the CRL against")
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil, fmt.Errorf("CRL is not signed by the configured client CA: %w", err)
	}
	if !crl.NextUpdate.IsZero() && time.Now().After(crl.NextUpdate) {
		return nil, fmt.Errorf("CRL expired at %s; it cannot list a certificate revoked since", crl.NextUpdate.Format(time.RFC3339))
	}
	return crl, nil
}
