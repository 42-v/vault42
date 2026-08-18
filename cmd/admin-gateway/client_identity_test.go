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
