package main

import (
	"crypto/x509"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// nextUpdate is OPTIONAL in RFC 5280, and `openssl ca -gencrl` without -crldays
// emits a list without one. The freshness guard used to be written
// `!crl.NextUpdate.IsZero() && time.Now().After(crl.NextUpdate)`, so a list with
// no nextUpdate skipped it entirely: a CA-signed CRL dated 2020 was accepted
// forever.
//
// The loop that makes it worse is operational. An expired CRL refuses every
// handshake, which locks the operator out of the admin plane. The obvious
// recovery is to regenerate the list -- and the shortest command that does so
// omits nextUpdate, which turns the lockout into a gateway whose revocation
// checking is permanently frozen at whatever the file said that day.
func TestACRLWithNoNextUpdateIsRefused(t *testing.T) {
	f := newFixture(t)
	crlFile := f.pki.writeCRLSpec(t, crlSpec{
		omitNextUpdate: true,
		number:         7,
		thisUpdate:     time.Date(2020, 8, 19, 0, 0, 0, 0, time.UTC),
		serials:        []*big.Int{big.NewInt(101)},
	})

	c := launch(t, childRoleRun, f.workDir, f.env("ADMIN_GW_CLIENT_CRL_FILE="+crlFile)...)
	if code := c.waitForExit(t); code != 1 {
		t.Fatalf("exit code = %d, want 1: a CRL with no nextUpdate never expires\nstderr:\n%s",
			code, c.stderr.String())
	}

	out := c.stderr.String()
	for _, want := range []string{"nextUpdate", "-crldays"} {
		if !strings.Contains(out, want) {
			t.Errorf("startup refusal does not mention %q, so the operator cannot tell what to "+
				"regenerate or how:\n%s", want, out)
		}
	}
}

// thisUpdate was never looked at, so a CRL dated a year from now was accepted:
// its nextUpdate is further away still, which is what the expiry check reads.
// A list whose own issuance date has not happened yet is not evidence about
// anything, and a clock that far out is a configuration error the operator
// should be told about at boot rather than at the first refused login.
func TestACRLDatedInTheFutureIsRefused(t *testing.T) {
	f := newFixture(t)
	crlFile := f.pki.writeCRLSpec(t, crlSpec{
		number:     2,
		thisUpdate: time.Now().Add(365 * 24 * time.Hour),
		nextUpdate: time.Now().Add(730 * 24 * time.Hour),
	})

	c := launch(t, childRoleRun, f.workDir, f.env("ADMIN_GW_CLIENT_CRL_FILE="+crlFile)...)
	if code := c.waitForExit(t); code != 1 {
		t.Fatalf("exit code = %d, want 1: a CRL issued in the future was accepted\nstderr:\n%s",
			code, c.stderr.String())
	}
	if out := c.stderr.String(); !strings.Contains(out, "thisUpdate") {
		t.Errorf("startup refusal does not mention thisUpdate:\n%s", out)
	}
}

// A serial number is only unique within one issuer. Revocation compared serials
// and nothing else, and the issuer a CRL had to be signed by was whichever
// certificate came first in ADMIN_GW_CLIENT_CA_FILE. A two-CA bundle -- the
// ordinary shape of a CA rotation -- therefore had three faults at once, and
// sequential serials make the first of them a certainty rather than a
// coincidence.
func TestRevocationIsScopedToTheIssuingCA(t *testing.T) {
	t.Run("one CA's CRL does not revoke another CA's serial", func(t *testing.T) {
		f := newFixture(t)
		caB := f.pki.addClientCA(t, "vault42 admin gateway test CA B")

		crlA := f.pki.writeCRLSpec(t, crlSpec{
			path:    filepath.Join(f.pki.dir, "ca-a.crl"),
			serials: []*big.Int{big.NewInt(101)},
		})
		liveB := f.pki.issueClientSpec(t, clientSpec{ca: &caB, cn: "operator-b", serial: 101})

		c := f.start(t, "ADMIN_GW_CLIENT_CRL_FILE="+crlA)
		f.mustReach(t, liveB, "a live CA-B operator whose serial CA-A's CRL happens to list")
		c.stopCleanly(t)
	})

	t.Run("a CRL signed by the second CA in the bundle is honored", func(t *testing.T) {
		f := newFixture(t)
		caB := f.pki.addClientCA(t, "vault42 admin gateway test CA B")

		revokedB := f.pki.issueClientSpec(t, clientSpec{ca: &caB, cn: "decommissioned-b", serial: 202})
		crlB := f.pki.writeCRLSpec(t, crlSpec{
			signer:  &caB,
			path:    filepath.Join(f.pki.dir, "ca-b.crl"),
			serials: []*big.Int{big.NewInt(202)},
		})

		c := f.start(t, "ADMIN_GW_CLIENT_CRL_FILE="+crlB)
		f.mustBeRefused(t, revokedB, "an operator CA-B revoked")
		f.mustReach(t, f.pki.clientCert, "the CA-A operator, whose CA publishes no list")

		// A CA in the bundle with no list of its own cannot revoke anybody, and
		// that is exactly the state the operator has to be able to see.
		c.waitForLog(t, "no revocation list is configured for client CA")

		c.stopCleanly(t)
	})

	t.Run("one list per CA in the bundle", func(t *testing.T) {
		f := newFixture(t)
		caB := f.pki.addClientCA(t, "vault42 admin gateway test CA B")

		revokedA := f.pki.issueClientSpec(t, clientSpec{cn: "decommissioned-a", serial: 301})
		revokedB := f.pki.issueClientSpec(t, clientSpec{ca: &caB, cn: "decommissioned-b", serial: 302})
		liveB := f.pki.issueClientSpec(t, clientSpec{ca: &caB, cn: "operator-b"})

		crlA := f.pki.writeCRLSpec(t, crlSpec{
			path:    filepath.Join(f.pki.dir, "ca-a.crl"),
			serials: []*big.Int{big.NewInt(301)},
		})
		crlB := f.pki.writeCRLSpec(t, crlSpec{
			signer:  &caB,
			path:    filepath.Join(f.pki.dir, "ca-b.crl"),
			serials: []*big.Int{big.NewInt(302)},
		})

		c := f.start(t, "ADMIN_GW_CLIENT_CRL_FILE="+crlA+","+crlB)
		f.mustBeRefused(t, revokedA, "an operator CA-A revoked")
		f.mustBeRefused(t, revokedB, "an operator CA-B revoked")
		f.mustReach(t, liveB, "a live CA-B operator")
		f.mustReach(t, f.pki.clientCert, "the live CA-A operator")
		c.stopCleanly(t)
	})
}

// The CRL is re-read on every handshake, which is what makes a revocation take
// effect without restarting the admin plane. It also means whoever can write the
// file chooses which revision the gateway believes -- and an older revision of a
// genuine, CA-signed, still-in-window list un-revokes everyone revoked since.
//
// This attack needs no CA key at all. It needs one file write, and the file is
// one an operator is expected to rewrite.
func TestARolledBackCRLIsRefused(t *testing.T) {
	f := newFixture(t)
	crlFile := filepath.Join(f.pki.dir, "client.crl")
	revoked := f.pki.issueClientSpec(t, clientSpec{cn: "decommissioned-operator", serial: 401})

	f.pki.writeCRLSpec(t, crlSpec{path: crlFile, number: 7, serials: []*big.Int{big.NewInt(401)}})
	c := f.start(t, "ADMIN_GW_CLIENT_CRL_FILE="+crlFile)
	f.mustBeRefused(t, revoked, "the operator CRL #7 revokes")

	// CRL #1: older, genuine, correctly signed, and still inside its own
	// validity window. Nothing about it is malformed; it simply predates the
	// revocation.
	f.pki.writeCRLSpec(t, crlSpec{
		path:       crlFile,
		number:     1,
		thisUpdate: time.Now().Add(-20 * 24 * time.Hour),
		nextUpdate: time.Now().Add(10 * 24 * time.Hour),
	})

	f.mustBeRefused(t, revoked, "the operator CRL #7 revokes, after CRL #1 was written over the path")

	// And the refusal is the whole handshake, not just that one certificate: a
	// list that has gone backwards is not evidence about anybody.
	f.mustBeRefused(t, f.pki.clientCert, "the live operator while the CRL has gone backwards")

	c.stopCleanly(t)
}

// Revocation looked at PeerCertificates[0] and stopped. Everything above the
// leaf in the chain -- the sub-CA an operator delegated issuance to, and whose
// key is the one worth stealing -- was unrevokable: publishing its serial
// changed nothing, and it kept minting leaves that verified and passed.
func TestARevokedIntermediateRevokesTheLeavesItSigned(t *testing.T) {
	f := newFixture(t)
	intermediate := f.pki.issueIntermediateCA(t, "vault42 admin gateway test sub-CA", 501)
	leaf := f.pki.issueClientUnder(t, intermediate, "operator-under-sub-ca")

	// Signed by the root, which is the CA that issued the intermediate and so
	// the only one that can revoke it.
	crlFile := f.pki.writeCRLSpec(t, crlSpec{serials: []*big.Int{big.NewInt(501)}})

	c := f.start(t, "ADMIN_GW_CLIENT_CRL_FILE="+crlFile)
	f.mustBeRefused(t, leaf, "a leaf minted by a revoked intermediate")
	f.mustReach(t, f.pki.clientCert, "an operator issued directly by the root")
	c.stopCleanly(t)
}

// One list per CA, and not two.
//
// Multiple paths are what let a two-CA bundle revoke on both sides, and they
// introduce a rollback of their own: two lists from the same issuer load in
// ascending order and then fail on the next handshake, because by then the
// older of the two is a rollback against the mark the newer one set. That is a
// gateway that boots reporting revocation as configured and refuses every login
// from the first handshake onwards, which is the worst shape a misconfiguration
// can take. It has to be a boot failure naming both paths.
func TestTwoRevocationListsFromOneCAAreRefused(t *testing.T) {
	f := newFixture(t)
	older := f.pki.writeCRLSpec(t, crlSpec{
		path:       filepath.Join(f.pki.dir, "older.crl"),
		number:     1,
		thisUpdate: time.Now().Add(-48 * time.Hour),
	})
	newer := f.pki.writeCRLSpec(t, crlSpec{
		path:    filepath.Join(f.pki.dir, "newer.crl"),
		number:  7,
		serials: []*big.Int{big.NewInt(601)},
	})

	p := clientIdentityPolicy{
		crlFiles: []string{older, newer},
		issuers:  []*x509.Certificate{f.pki.ca.cert},
		seen:     newCRLHighWater(),
	}
	if _, err := p.loadCRLs(); err == nil {
		t.Fatal("two revocation lists from one CA were accepted. The gateway boots, and on the " +
			"second read the older of the two is a rollback, so every handshake after the first is " +
			"refused with nothing on the startup log to explain it")
	} else if !strings.Contains(err.Error(), older) {
		t.Fatalf("loadCRLs error = %q, want it to name the other path so the operator can tell "+
			"which two lists collide", err)
	}
}
