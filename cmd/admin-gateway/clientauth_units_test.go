package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The handshake tests drive the real binary as a child process, which is the
// right shape for a policy installed on a TLS config. These cover the arms that
// no handshake reaches: a matcher whose kind is unknown, a diagnostic truncating
// a certificate with more names than a log line should carry, a high-water mark
// that has not been constructed, a revocation list dated before one already
// accepted, and an allowlist entry that is all prefix and no value.

// A kind outside the four the parser produces matches nothing. It cannot arise
// from configuration today; the arm exists so that adding a kind and forgetting
// to handle it fails closed rather than matching every certificate.
func TestAnUnknownAllowKindMatchesNothing(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "admin-operator"},
		DNSNames: []string{"admin-operator"},
	}
	e := allowEntry{kind: allowKind("mystery"), value: "admin-operator", raw: "mystery:admin-operator"}

	if e.matches(leaf, true) {
		t.Error("an entry of an unrecognised kind matched a certificate")
	}
	if e.matches(leaf, false) {
		t.Error("an entry of an unrecognised kind matched a certificate with no SANs")
	}
}

// Every name in the refusal message is chosen by whoever holds the certificate,
// and the message is a log line, so the list is capped and the remainder counted.
func TestTheIdentityDescriptionCountsTheNamesItDropped(t *testing.T) {
	dns := make([]string, 0, identityNamesInError+3)
	for i := range identityNamesInError + 3 {
		dns = append(dns, string(rune('a'+i))+".example.test")
	}
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "operator"}, DNSNames: dns}

	got := describeIdentity(leaf)
	if !strings.Contains(got, "and 4 more") {
		t.Errorf("describeIdentity did not report the names it dropped: %q", got)
	}
	if strings.Count(got, ", ") != identityNamesInError {
		t.Errorf("describeIdentity rendered %d separators, want %d: %q",
			strings.Count(got, ", "), identityNamesInError, got)
	}
}

// A nil high-water mark admits everything. That is what an in-process test
// constructing a bare policy gets, and it must not panic or refuse.
func TestANilHighWaterMarkAdmitsEverything(t *testing.T) {
	var h *crlHighWater
	crl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now()}
	if err := h.admit(crl); err != nil {
		t.Errorf("a nil high-water mark refused a revocation list: %v", err)
	}
}

// The rollback this guards is a file write, not a CA key: an attacker who can
// overwrite the CRL path replaces a current list with an older one that no
// longer names their revoked certificate. Number and thisUpdate are both
// compared because either may be absent or equal.
func TestAnOlderRevocationListIsRefusedByItsDate(t *testing.T) {
	h := newCRLHighWater()
	issuer := pkix.Name{CommonName: "vault42 admin CA"}
	now := time.Now().Truncate(time.Second)
	current := &x509.RevocationList{
		Number: big.NewInt(7), ThisUpdate: now,
		Issuer: issuer,
	}
	if err := h.admit(current); err != nil {
		t.Fatalf("the first list from an issuer was refused: %v", err)
	}

	// Same number so the number comparison cannot decide it, an earlier date so
	// only the thisUpdate arm can.
	rolled := &x509.RevocationList{
		Number: big.NewInt(7), ThisUpdate: now.Add(-20 * 24 * time.Hour),
		Issuer: issuer,
	}
	err := h.admit(rolled)
	if err == nil {
		t.Fatal("a revocation list dated twenty days before the one already accepted was admitted")
	}
	if !strings.Contains(err.Error(), "older than") {
		t.Errorf("the refusal does not say the list is stale: %v", err)
	}
}

// `cn:` with nothing after it matches nothing, and an operator who typed it
// meant to pin something. Saying so at startup is the only chance to catch it:
// the entry is silent afterwards, because matching nothing looks exactly like
// matching a certificate that never connects.
func TestAnAllowlistEntryWithNoValueIsNamedAtStartup(t *testing.T) {
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	logAllowlistPosture([]allowEntry{
		{kind: allowCN, value: "", raw: "cn:"},
		{kind: allowDNS, value: "admin-operator", raw: "dns:admin-operator"},
	})

	out := buf.String()
	if !strings.Contains(out, `"cn:"`) {
		t.Errorf("the empty entry was not named at startup:\n%s", out)
	}
	if !strings.Contains(out, "matches nothing") {
		t.Errorf("the warning does not say what the entry does:\n%s", out)
	}
}
