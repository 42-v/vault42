package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The listener sets ClientAuth: RequireAndVerifyClientCert against a CA pool and
// then never looks at the peer certificate again, so mTLS was a coarse "was this
// signed by our CA" gate. Any certificate that CA ever issued — a decommissioned
// operator's, a service certificate, one minted for a different component —
// completed the handshake and reached POST /admin/login. AR-9 accepts that on a
// single-purpose CA, which is sound for one operator and degrades with each one
// added.
//
// These two subtests are the accept and the reject: the same CA, the same
// handshake, two different subjects, and only the pinned one gets through.
func TestClientCertificateIdentityIsPinned(t *testing.T) {
	t.Run("a pinned CN reaches the router", func(t *testing.T) {
		f := newFixture(t)
		c := f.start(t, "ADMIN_GW_CLIENT_CN_ALLOWLIST=admin-operator")

		resp, err := f.httpClient().Get("https://" + f.addr + "/admin/status")
		if err != nil {
			t.Fatalf("pinned operator certificate was refused: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			t.Errorf("GET /admin/status = %s, want 401 from the session middleware (body: %s)", resp.Status, body)
		}

		c.signal(t, syscall.SIGTERM)
		if code := c.waitForExit(t); code != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
		}
	})

	t.Run("a certificate from the same CA with an unpinned CN is refused", func(t *testing.T) {
		f := newFixture(t)
		c := f.start(t, "ADMIN_GW_CLIENT_CN_ALLOWLIST=admin-operator")

		other := f.pki.issueClient(t, "decommissioned-operator")
		cfg := f.pki.tlsClientConfig()
		cfg.Certificates = []tls.Certificate{other}
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}

		resp, err := client.Get("https://" + f.addr + "/admin/status")
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("a certificate the CA signed for another subject returned %s, want the handshake refused", resp.Status)
		}

		c.signal(t, syscall.SIGTERM)
		if code := c.waitForExit(t); code != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
		}
	})
}

// An unset allowlist keeps the old behavior, because refusing to start would
// break every existing deployment on upgrade. It must not be silent: the whole
// point of AR-9 is that the operator knows the CA is the only boundary.
func TestUnpinnedClientIdentityWarnsAtStartup(t *testing.T) {
	f := newFixture(t)
	c := f.start(t)
	c.waitForLog(t, "ADMIN_GW_CLIENT_CN_ALLOWLIST is unset")

	c.signal(t, syscall.SIGTERM)
	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
	}
}

// A revoked operator certificate is the case AR-9 says is only answerable by
// rotating the CA. With a CRL configured, it is answerable by publishing one
// file.
func TestRevokedClientCertificateIsRefused(t *testing.T) {
	f := newFixture(t)
	revoked := f.pki.issueClient(t, "revoked-operator")
	leaf, err := x509.ParseCertificate(revoked.Certificate[0])
	if err != nil {
		t.Fatalf("parse issued leaf: %v", err)
	}
	crlFile := f.pki.writeCRL(t, leaf.SerialNumber)

	c := f.start(t, "ADMIN_GW_CLIENT_CRL_FILE="+crlFile)

	cfg := f.pki.tlsClientConfig()
	cfg.Certificates = []tls.Certificate{revoked}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := client.Get("https://" + f.addr + "/admin/status")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("revoked certificate returned %s, want the handshake refused", resp.Status)
	}

	// The unrevoked operator still gets through, so the CRL refuses a serial
	// rather than refusing everyone.
	resp, err = f.httpClient().Get("https://" + f.addr + "/admin/status")
	if err != nil {
		t.Fatalf("unrevoked operator certificate was refused while a CRL was loaded: %v", err)
	}
	_ = resp.Body.Close()

	c.signal(t, syscall.SIGTERM)
	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
	}
}

// A CRL path that cannot be read or parsed at startup is fatal. Booting without
// it would present the operator with a gateway that reports revocation checking
// as configured while checking nothing.
func TestUnusableCRLIsFatalAtStartup(t *testing.T) {
	tests := []struct {
		name    string
		file    func(t *testing.T, f *fixture) string
		wantLog string
	}{
		{
			name:    "missing file",
			file:    func(t *testing.T, _ *fixture) string { return filepath.Join(t.TempDir(), "absent.crl") },
			wantLog: "admin-gateway: failed to load client CRL:",
		},
		{
			name: "not a revocation list",
			file: func(t *testing.T, _ *fixture) string {
				return writeSecret(t, "client.crl", []byte("not a CRL"))
			},
			wantLog: "admin-gateway: failed to load client CRL:",
		},
		{
			name: "signed by a different CA",
			file: func(t *testing.T, _ *fixture) string {
				return newPKI(t).writeCRL(t, big.NewInt(99))
			},
			wantLog: "admin-gateway: failed to load client CRL:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			c := launch(t, childRoleRun, f.workDir, f.env("ADMIN_GW_CLIENT_CRL_FILE="+tt.file(t, f))...)
			if code := c.waitForExit(t); code != 1 {
				t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, c.stderr.String())
			}
			if out := c.stderr.String(); !strings.Contains(out, tt.wantLog) {
				t.Errorf("stderr does not contain %q:\n%s", tt.wantLog, out)
			}
		})
	}
}

// The policy itself, exercised in-process because the handshake path can only
// report "refused" and these distinctions matter to whoever debugs a refusal.
func TestClientIdentityPolicyMatching(t *testing.T) {
	leaf := func(cn string, dns, emails []string) *x509.Certificate {
		return &x509.Certificate{
			Subject:        pkix.Name{CommonName: cn},
			DNSNames:       dns,
			EmailAddresses: emails,
			SerialNumber:   big.NewInt(7),
		}
	}

	tests := []struct {
		name    string
		allowed []string
		cert    *x509.Certificate
		wantErr bool
	}{
		{"empty allowlist pins nothing", nil, leaf("anyone", nil, nil), false},
		{"common name matches", []string{"ops"}, leaf("ops", nil, nil), false},
		{"dns SAN matches", []string{"ops.vault.internal"}, leaf("ops", []string{"ops.vault.internal"}, nil), false},
		{"email SAN matches", []string{"ops@vault.test"}, leaf("ops", nil, []string{"ops@vault.test"}), false},
		{"second entry matches", []string{"a", "ops"}, leaf("ops", nil, nil), false},
		{"no identity matches", []string{"ops"}, leaf("intruder", []string{"other"}, nil), true},
		{"a prefix is not a match", []string{"operator"}, leaf("oper", nil, nil), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := clientIdentityPolicy{allowed: tt.allowed}
			err := p.checkIdentity(tt.cert)
			if tt.wantErr != (err != nil) {
				t.Fatalf("checkIdentity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// verifyConnection is what the TLS stack calls. A state with no peer
// certificate and no verified chain cannot happen behind
// RequireAndVerifyClientCert, and it must refuse rather than fall through to a
// nil dereference if it ever does.
func TestVerifyConnectionRefusesAnEmptyPeerChain(t *testing.T) {
	p := clientIdentityPolicy{allowed: []string{"ops"}}
	if err := p.verifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("verifyConnection with no peer certificate must refuse")
	}
}

// A CRL that stopped being readable between startup and a handshake fails the
// handshake. The alternative — carrying on with the copy loaded at boot — turns
// a revocation the operator published into one the gateway silently ignores.
func TestCRLThatBecomesUnreadableFailsTheHandshake(t *testing.T) {
	f := newFixture(t)
	crlFile := filepath.Join(t.TempDir(), "gone.crl")
	p := clientIdentityPolicy{crlFile: crlFile, issuer: f.pki.ca.cert}

	if err := p.checkRevocation(&x509.Certificate{SerialNumber: big.NewInt(3)}); err == nil {
		t.Fatal("an unreadable CRL must fail the handshake, not be ignored")
	}
}

// An expired CRL is stale evidence: it cannot list a certificate revoked after
// its nextUpdate, so trusting it is trusting a snapshot of unknown age.
func TestStaleCRLFailsTheHandshake(t *testing.T) {
	f := newFixture(t)
	crlFile := f.pki.writeCRLAt(t, time.Now().Add(-48*time.Hour), big.NewInt(99))
	p := clientIdentityPolicy{crlFile: crlFile, issuer: f.pki.ca.cert}

	if err := p.checkRevocation(&x509.Certificate{SerialNumber: big.NewInt(3)}); err == nil {
		t.Fatal("a CRL past its nextUpdate must fail the handshake")
	}
}

// An operator identity does not have to be a common name. SPIFFE and every
// service mesh that issues from one put it in a URI SAN and leave the CN
// decorative, and RFC 5280 has treated the CN as deprecated for identity for
// twenty years. A gateway that pinned only the CN and the DNS names would force
// such a deployment to leave ADMIN_GW_CLIENT_CN_ALLOWLIST empty, which is
// precisely the "the CA is the only boundary" state AR-9 describes.
//
// The reject half is what makes it a pin rather than a lookup: the second
// certificate carries a well-formed URI SAN from the same CA, and it must not
// complete the handshake.
func TestAURISANIdentityCanBePinned(t *testing.T) {
	const allowed = "spiffe://vault42.test/ns/admin/sa/operator"
	const decommissioned = "spiffe://vault42.test/ns/admin/sa/decommissioned"

	f := newFixture(t)
	c := f.start(t, "ADMIN_GW_CLIENT_CN_ALLOWLIST="+allowed)

	dial := func(cert tls.Certificate) (*http.Response, error) {
		cfg := f.pki.tlsClientConfig()
		cfg.Certificates = []tls.Certificate{cert}
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
		return client.Get("https://" + f.addr + "/admin/status")
	}

	// The CN is deliberately not in the allowlist, so only the URI SAN can let
	// this certificate through.
	resp, err := dial(f.pki.issueClientWithURI(t, "mesh-issued", allowed))
	if err != nil {
		t.Fatalf("a certificate pinned by its URI SAN was refused: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Errorf("GET /admin/status = %s, want 401 from the session middleware (body: %s)", resp.Status, body)
	}

	other, err := dial(f.pki.issueClientWithURI(t, "mesh-issued", decommissioned))
	if err == nil {
		_ = other.Body.Close()
		t.Fatalf("a URI SAN outside the allowlist returned %s, want the handshake refused", other.Status)
	}

	c.signal(t, syscall.SIGTERM)
	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
	}
}

// A CRL is a file that says which operators are no longer operators, and
// believing one that this gateway's own CA did not sign hands that decision to
// whoever can write the file. The signature check is therefore not optional, and
// "there is no certificate to check the signature against" is not a reason to
// skip it — it is the one case where skipping it would be silent.
//
// firstCertificate is where the issuer comes from, and every way it can come
// back empty ends at the same refusal. The CRL in each case is real, current and
// correctly signed by the fixture's CA, so nothing but the missing issuer can
// produce the error.
func TestARevocationListIsRefusedWithNoIssuerToAuthenticateItAgainst(t *testing.T) {
	f := newFixture(t)
	crlFile := f.pki.writeCRL(t, big.NewInt(4242))
	keyOnly := keyPEM(t, f.pki.ca.key)

	bundles := []struct {
		name   string
		bundle []byte
	}{
		// pem.Decode finds no block at all and hands back the input untouched.
		// Reading on would loop forever on the same bytes.
		{"a file that is not PEM at all", []byte("this is a note the operator left in the config directory\n")},
		// Well-formed PEM carrying no certificate. An operator who points
		// ADMIN_GW_CLIENT_CA_FILE at the CA's key instead of the CA's
		// certificate lands here.
		{"PEM blocks that are not certificates", keyOnly},
		// Two non-certificate blocks, so the skip has to keep going rather than
		// stop at the first one.
		{"several non-certificate blocks", append(append([]byte{}, keyOnly...), keyOnly...)},
		{"an empty bundle", nil},
	}

	for _, tt := range bundles {
		t.Run(tt.name, func(t *testing.T) {
			issuer := firstCertificate(tt.bundle)
			if issuer != nil {
				t.Fatalf("firstCertificate returned a certificate (subject %q) for %s; loadCRL would "+
					"then authenticate the revocation list against it", issuer.Subject, tt.name)
			}

			if _, err := loadCRL(crlFile, issuer); err == nil {
				t.Fatal("loadCRL accepted a revocation list with nothing to authenticate it against; " +
					"an attacker-supplied file could revoke every operator, or unrevoke one")
			} else if !strings.Contains(err.Error(), "no client CA certificate") {
				t.Fatalf("loadCRL error = %q, want it to name the missing issuer", err)
			}

			// The handshake is what the refusal has to reach. The leaf here is
			// NOT on the list, so a policy that returned nil on an
			// unauthenticated CRL would let it straight through.
			p := clientIdentityPolicy{crlFile: crlFile, issuer: issuer}
			if err := p.checkRevocation(&x509.Certificate{SerialNumber: big.NewInt(7)}); err == nil {
				t.Fatal("checkRevocation admitted a client while the CRL could not be authenticated")
			}
		})
	}
}

// The bundle an operator actually has on disk is often a key and a certificate
// concatenated, in whichever order the tooling emitted them. The certificate has
// to be found regardless, or a gateway configured with a perfectly good CA file
// would refuse every handshake once a CRL was added.
func TestTheIssuerIsFoundPastNonCertificateBlocks(t *testing.T) {
	f := newFixture(t)
	bundle := append(keyPEM(t, f.pki.ca.key), certPEM(f.pki.ca.der)...)

	issuer := firstCertificate(bundle)
	if issuer == nil {
		t.Fatal("firstCertificate stopped at the leading key block; a key-then-certificate bundle is " +
			"what most CA tooling emits, and a gateway reading one would authenticate no CRL at all")
	}
	if !issuer.Equal(f.pki.ca.cert) {
		t.Fatalf("firstCertificate returned %q, want the CA %q", issuer.Subject, f.pki.ca.cert.Subject)
	}

	// And it is the issuer the CRL is checked against, so a correctly signed
	// list now loads.
	if _, err := loadCRL(f.pki.writeCRL(t, big.NewInt(4242)), issuer); err != nil {
		t.Fatalf("loadCRL with the issuer recovered from a key-first bundle: %v", err)
	}
}
