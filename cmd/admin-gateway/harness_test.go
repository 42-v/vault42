package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// childRoleEnv marks a process as a gateway child. The test binary re-executes
// itself with this set, and TestMain hands control straight to main() instead of
// running tests.
//
// Running main() in a child rather than in the test process is not a stylistic
// choice. main() calls log.Fatalf on eight distinct failures and blocks on a
// signal channel on success, so in-process invocation would either kill the test
// run or hang it. The child is the same coverage-instrumented binary and
// inherits GOCOVERDIR, so every statement it executes, including the ones
// reached immediately before os.Exit(1), lands in the same coverage profile as
// the in-process tests.
//
// The value is the child's argv after the program name: "run" means no
// arguments, "run --version" means main() sees --version.
const childRoleEnv = "VAULT42_ADMIN_GW_TEST_CHILD"

// childBootTimeout bounds how long a test waits for a child to log something or
// to exit. It is generous because the child is built with -race.
const childBootTimeout = 60 * time.Second

// gatewayEnvPrefixes are the environment prefixes a child must never inherit
// from the process that launched it. Every input to LoadConfig arrives through
// the environment, so a stray variable in the developer's shell, or one left by
// an earlier in-process t.Setenv, would silently change what a child is testing.
// Children are built from a filtered copy of the environment plus an explicit
// allow-list of variables the test set on purpose.
var gatewayEnvPrefixes = []string{
	"ADMIN_GW_",
	"DB_",
	"MASTER_KEY",
	"HMAC_SECRET",
	"VAULT_",
}

// syncBuffer collects a child's output. The io.Writer is called from the
// os/exec copy goroutine while tests poll String from the test goroutine, so
// both sides take the mutex.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// child is a running admin-gateway process under test.
type child struct {
	cmd    *exec.Cmd
	stdout *syncBuffer
	stderr *syncBuffer

	waitOnce sync.Once
	waitErr  error
}

// launch starts the gateway in a child process.
//
// dir becomes the child's working directory, which matters because main()
// resolves the migrations directory relative to it. env entries are appended
// last and therefore win over anything inherited.
func launch(t *testing.T, role, dir string, env ...string) *child {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}

	c := &child{
		cmd:    exec.Command(exe),
		stdout: &syncBuffer{},
		stderr: &syncBuffer{},
	}
	c.cmd.Dir = dir
	c.cmd.Stdout = c.stdout
	c.cmd.Stderr = c.stderr
	c.cmd.Env = append(childEnv(), append([]string{childRoleEnv + "=" + role}, env...)...)

	if err := c.cmd.Start(); err != nil {
		t.Fatalf("start gateway child: %v", err)
	}

	t.Cleanup(func() {
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		_ = c.wait()
		if t.Failed() {
			t.Logf("child stdout:\n%s", c.stdout.String())
			t.Logf("child stderr:\n%s", c.stderr.String())
		}
	})

	return c
}

// childEnv returns the ambient environment with every gateway-controlling
// variable removed. GOCOVERDIR, PATH and the rest of the toolchain's variables
// survive, which is what keeps the child's coverage counters flowing into the
// parent's profile.
func childEnv() []string {
	ambient := os.Environ()
	out := make([]string, 0, len(ambient))
outer:
	for _, kv := range ambient {
		name, _, _ := strings.Cut(kv, "=")
		for _, p := range gatewayEnvPrefixes {
			if strings.HasPrefix(name, p) {
				continue outer
			}
		}
		out = append(out, kv)
	}
	return out
}

// wait reaps the child once and caches the result so several helpers can ask
// for the exit status.
func (c *child) wait() error {
	c.waitOnce.Do(func() { c.waitErr = c.cmd.Wait() })
	return c.waitErr
}

// waitForExit fails the test if the child is still running after
// childBootTimeout, and otherwise returns its exit code.
func (c *child) waitForExit(t *testing.T) int {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- c.wait() }()

	select {
	case err := <-done:
		var ee *exec.ExitError
		switch {
		case err == nil:
			return 0
		case errors.As(err, &ee):
			return ee.ExitCode()
		default:
			t.Fatalf("wait for gateway child: %v", err)
			return -1
		}
	case <-time.After(childBootTimeout):
		_ = c.cmd.Process.Kill()
		t.Fatalf("gateway child did not exit within %s\nstderr:\n%s", childBootTimeout, c.stderr.String())
		return -1
	}
}

// waitForLog blocks until the child's stderr contains substr. Every log line
// main() writes goes to stderr through the standard logger, so this doubles as
// the readiness and progress signal.
func (c *child) waitForLog(t *testing.T, substr string) {
	t.Helper()

	deadline := time.Now().Add(childBootTimeout)
	for time.Now().Before(deadline) {
		if strings.Contains(c.stderr.String(), substr) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in child stderr\nstderr:\n%s", substr, c.stderr.String())
}

// waitForListener blocks until the child accepts TCP connections on addr. The
// "listening on" log line is written before ListenAndServeTLS binds, so it is
// not by itself proof that the socket is up.
func (c *child) waitForListener(t *testing.T, addr string) {
	t.Helper()

	deadline := time.Now().Add(childBootTimeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("gateway never accepted connections on %s\nstderr:\n%s", addr, c.stderr.String())
}

// signal delivers sig to the child.
func (c *child) signal(t *testing.T, sig os.Signal) {
	t.Helper()
	if err := c.cmd.Process.Signal(sig); err != nil {
		t.Fatalf("signal child: %v", err)
	}
}

// pki is a throwaway certificate authority plus the server and client
// certificates the gateway's mTLS listener needs.
type pki struct {
	dir string

	serverCertFile string
	serverKeyFile  string
	clientCAFile   string

	roots      *x509.CertPool
	clientCert tls.Certificate

	// ca is retained so a test can issue a second client certificate from the
	// same authority, which is the whole shape of the CN-pinning defect: a
	// certificate that verifies against ClientCAs and still must not be let in.
	ca issued
	// nextSerial hands out unique serial numbers for certificates issued after
	// newPKI. A CRL names a serial, so two certificates sharing one would make a
	// revocation test pass for the wrong reason.
	nextSerial int64
}

// issueClient mints another client certificate from the same CA, with cn as its
// subject common name.
func (p *pki) issueClient(t *testing.T, cn string) tls.Certificate {
	t.Helper()

	p.nextSerial++
	c := issueCert(t, p.ca, &x509.Certificate{
		SerialNumber: big.NewInt(100 + p.nextSerial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return tls.Certificate{Certificate: [][]byte{c.der}, PrivateKey: c.key}
}

// issueClientWithURI mints a client certificate whose identity lives in a URI
// SAN rather than in the common name.
//
// This is what SPIFFE-issued and mesh-issued operator certificates look like:
// the CN is decorative or absent and spiffe://... is the name anything
// downstream is expected to pin on. A gateway that only reads the CN and the DNS
// names cannot pin such a deployment at all, so its allowlist would have to be
// left empty and the CA would go back to being the only boundary.
func (p *pki) issueClientWithURI(t *testing.T, cn string, uri string) tls.Certificate {
	t.Helper()

	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse SAN URI %q: %v", uri, err)
	}
	p.nextSerial++
	c := issueCert(t, p.ca, &x509.Certificate{
		SerialNumber: big.NewInt(100 + p.nextSerial),
		Subject:      pkix.Name{CommonName: cn},
		URIs:         []*url.URL{u},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return tls.Certificate{Certificate: [][]byte{c.der}, PrivateKey: c.key}
}

// writeCRL signs a current revocation list naming serials and returns its path.
func (p *pki) writeCRL(t *testing.T, serials ...*big.Int) string {
	t.Helper()
	return p.writeCRLAt(t, time.Now().Add(24*time.Hour), serials...)
}

// writeCRLAt is writeCRL with an explicit nextUpdate, so a test can produce a
// list that is already stale.
//
// thisUpdate is an hour ago, not an hour before nextUpdate. It used to be the
// latter, which meant every "current" list this helper wrote was dated 23 hours
// in the future -- and nothing noticed, because thisUpdate was not checked at
// all. It is pushed back further than an hour only when nextUpdate is itself in
// the past, which is the stale case and needs a thisUpdate before it.
func (p *pki) writeCRLAt(t *testing.T, nextUpdate time.Time, serials ...*big.Int) string {
	t.Helper()

	thisUpdate := time.Now().Add(-time.Hour)
	if !nextUpdate.After(thisUpdate) {
		thisUpdate = nextUpdate.Add(-time.Hour)
	}

	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   s,
			RevocationTime: thisUpdate,
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, p.ca.cert, p.ca.key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return writeFile(t, filepath.Join(p.dir, "client.crl"),
		pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
}

// issued is a certificate together with the key that signed for it.
type issued struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

// newPKI mints an ECDSA CA and issues a loopback server certificate and a
// client certificate from it. Certificates are generated rather than checked in
// so the suite never depends on fixtures that expire.
func newPKI(t *testing.T) *pki {
	t.Helper()

	dir := t.TempDir()
	ca := issueCert(t, issued{}, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vault42 admin gateway test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})

	server := issueCert(t, ca, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "admin-gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	})

	operator := issueCert(t, ca, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "admin-operator"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	p := &pki{
		dir:            dir,
		serverCertFile: filepath.Join(dir, "server.crt"),
		serverKeyFile:  filepath.Join(dir, "server.key"),
		clientCAFile:   filepath.Join(dir, "client-ca.crt"),
		roots:          x509.NewCertPool(),
		ca:             ca,
	}
	p.roots.AddCert(ca.cert)

	writeFile(t, p.serverCertFile, certPEM(server.der))
	writeFile(t, p.serverKeyFile, keyPEM(t, server.key))
	writeFile(t, p.clientCAFile, certPEM(ca.der))

	p.clientCert = tls.Certificate{
		Certificate: [][]byte{operator.der},
		PrivateKey:  operator.key,
	}
	return p
}

// issueCert signs tmpl with the given issuer. A zero issuer produces a
// self-signed certificate.
func issueCert(t *testing.T, issuer issued, tmpl *x509.Certificate) issued {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	parent, parentKey := issuer.cert, issuer.key
	if parent == nil {
		parent, parentKey = tmpl, key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return issued{cert: cert, der: der, key: key}
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// tlsClientConfig dials the gateway as a trusted operator.
func (p *pki) tlsClientConfig() *tls.Config {
	return &tls.Config{
		RootCAs:      p.roots,
		Certificates: []tls.Certificate{p.clientCert},
		ServerName:   "127.0.0.1",
		MinVersion:   tls.VersionTLS13,
	}
}

func writeFile(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G703 -- path is always under t.TempDir()
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// writeSecret writes a secret file into a fresh temp directory and returns its
// path, for use with the _FILE convention.
func writeSecret(t *testing.T, name string, data []byte) string {
	t.Helper()
	return writeFile(t, filepath.Join(t.TempDir(), name), data)
}

// testMasterKey is 32 ASCII bytes, which is what LoadConfig demands for
// AES-256. It carries no leading or trailing whitespace, because loadSecret
// trims the file contents and a trimmed key is no longer 32 bytes.
const testMasterKey = "0123456789abcdef0123456789abcdef"

// freeAddr reserves and immediately releases a loopback port, returning the
// address a child should bind. There is a race between release and rebind, but
// ephemeral ports are handed out round-robin so a collision inside one test run
// is remote, and a collision surfaces as an explicit bind failure rather than as
// a silent pass.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// rsaPublicKeyPEM returns a PKIX-encoded RSA public key, the format
// crypto.LoadRSAPublicKeyPEM expects for the account-erasure escrow key.
func rsaPublicKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// ---------------------------------------------------------------------------
// Certificate and revocation-list shapes the hardening tests need
// ---------------------------------------------------------------------------

// clientSpec describes a client certificate a test wants issued. The zero value
// asks for a certificate from the fixture's own CA, with no subject alternative
// names and the next free serial.
//
// The fields exist separately rather than as one x509.Certificate template
// because which name field an identity lives in is the whole subject of the
// allowlist tests: a certificate holder chooses that field, and a test has to be
// able to move one string between the CN, a DNS SAN, an email SAN and a URI SAN
// without anything else about the certificate changing.
type clientSpec struct {
	// ca signs the certificate. Nil means the fixture's own CA.
	ca *issued
	// cn is the subject common name.
	cn string
	// dns, emails and uris are the subject alternative names.
	dns    []string
	emails []string
	uris   []string
	// serial pins the certificate serial. Zero takes the next free one. A test
	// that revokes a certificate needs to know its serial in advance, and a test
	// that shows two CAs colliding needs both CAs to issue the same one.
	serial int64
}

// issueClientSpec mints a client certificate matching spec.
func (p *pki) issueClientSpec(t *testing.T, spec clientSpec) tls.Certificate {
	t.Helper()

	ca := p.ca
	if spec.ca != nil {
		ca = *spec.ca
	}

	uris := make([]*url.URL, 0, len(spec.uris))
	for _, raw := range spec.uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse SAN URI %q: %v", raw, err)
		}
		uris = append(uris, u)
	}

	c := issueCert(t, ca, &x509.Certificate{
		SerialNumber:   big.NewInt(p.serial(spec.serial)),
		Subject:        pkix.Name{CommonName: spec.cn},
		DNSNames:       spec.dns,
		EmailAddresses: spec.emails,
		URIs:           uris,
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return tls.Certificate{Certificate: [][]byte{c.der}, PrivateKey: c.key}
}

// serial returns want, or the next free serial when want is zero.
func (p *pki) serial(want int64) int64 {
	if want != 0 {
		return want
	}
	p.nextSerial++
	return 100 + p.nextSerial
}

// addClientCA mints a second, independent certificate authority and appends it
// to the bundle the gateway loads as ADMIN_GW_CLIENT_CA_FILE.
//
// A bundle with two CAs is the ordinary shape of a rotation and of a deployment
// whose operators are issued from more than one authority, and it is the shape
// in which "the CRL" stops being a single well-defined thing.
func (p *pki) addClientCA(t *testing.T, cn string) issued {
	t.Helper()

	ca := issueCert(t, issued{}, &x509.Certificate{
		SerialNumber:          big.NewInt(p.serial(0)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})

	existing, err := os.ReadFile(p.clientCAFile)
	if err != nil {
		t.Fatalf("read client CA bundle: %v", err)
	}
	writeFile(t, p.clientCAFile, append(existing, certPEM(ca.der)...))
	return ca
}

// issueIntermediateCA mints a CA signed by the fixture's CA. Its own
// certificate is not added to the client CA bundle: a client presents it
// alongside its leaf, which is how an intermediate reaches the verifier in a
// real handshake and what puts it in VerifiedChains rather than in ClientCAs.
func (p *pki) issueIntermediateCA(t *testing.T, cn string, serial int64) issued {
	t.Helper()

	return issueCert(t, p.ca, &x509.Certificate{
		SerialNumber:          big.NewInt(p.serial(serial)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	})
}

// issueClientUnder mints a leaf from intermediate and returns it together with
// the intermediate, in the order a TLS client sends them.
func (p *pki) issueClientUnder(t *testing.T, intermediate issued, cn string) tls.Certificate {
	t.Helper()

	c := issueCert(t, intermediate, &x509.Certificate{
		SerialNumber: big.NewInt(p.serial(0)),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return tls.Certificate{
		Certificate: [][]byte{c.der, intermediate.der},
		PrivateKey:  c.key,
	}
}

// crlSpec describes a revocation list a test wants written. The zero value is a
// current, correctly signed, empty list from the fixture's own CA at the
// fixture's default path.
type crlSpec struct {
	// signer signs the list. Nil means the fixture's own CA.
	signer *issued
	// path is where the list is written. Empty means <fixture dir>/client.crl.
	path string
	// number is the CRL number. Zero means 1.
	number int64
	// thisUpdate and nextUpdate are the validity window. Zero values mean an
	// hour ago and a day from now.
	thisUpdate time.Time
	nextUpdate time.Time
	// omitNextUpdate drops the nextUpdate field entirely. nextUpdate is OPTIONAL
	// in RFC 5280 and `openssl ca -gencrl` without -crldays emits exactly this,
	// so it is a shape a gateway meets in the field. x509.CreateRevocationList
	// refuses to produce it, which is why writeCRLSpec hand-builds the DER.
	omitNextUpdate bool
	// serials are the revoked certificate serials.
	serials []*big.Int
}

// writeCRLSpec signs and writes a revocation list, returning its path.
func (p *pki) writeCRLSpec(t *testing.T, spec crlSpec) string {
	t.Helper()

	signer := p.ca
	if spec.signer != nil {
		signer = *spec.signer
	}
	path := spec.path
	if path == "" {
		path = filepath.Join(p.dir, "client.crl")
	}
	number := spec.number
	if number == 0 {
		number = 1
	}
	thisUpdate := spec.thisUpdate
	if thisUpdate.IsZero() {
		thisUpdate = time.Now().Add(-time.Hour)
	}
	nextUpdate := spec.nextUpdate
	if nextUpdate.IsZero() {
		nextUpdate = time.Now().Add(24 * time.Hour)
	}

	entries := make([]x509.RevocationListEntry, 0, len(spec.serials))
	for _, s := range spec.serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   s,
			RevocationTime: thisUpdate,
		})
	}

	var der []byte
	if spec.omitNextUpdate {
		der = crlWithoutNextUpdate(t, signer, big.NewInt(number), thisUpdate, entries)
	} else {
		var err error
		der, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:                    big.NewInt(number),
			ThisUpdate:                thisUpdate,
			NextUpdate:                nextUpdate,
			RevokedCertificateEntries: entries,
		}, signer.cert, signer.key)
		if err != nil {
			t.Fatalf("create CRL: %v", err)
		}
	}
	return writeFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
}

// oidECDSAWithSHA256 and oidCRLNumber are the two object identifiers
// crlWithoutNextUpdate has to name for itself, because it builds a CertificateList
// rather than asking crypto/x509 for one.
var (
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidCRLNumber       = asn1.ObjectIdentifier{2, 5, 29, 20}
)

// tbsCertList is RFC 5280's TBSCertList. crypto/x509/pkix has this type and it
// is deprecated, so it is spelled out here rather than borrowed.
//
// nextUpdate is `optional` with no default, which encoding/asn1 renders as
// "omit when zero" — exactly the certificate this repository could not otherwise
// produce.
type tbsCertList struct {
	Version             int `asn1:"optional,default:0"`
	Signature           pkix.AlgorithmIdentifier
	Issuer              asn1.RawValue
	ThisUpdate          time.Time
	NextUpdate          time.Time                 `asn1:"optional"`
	RevokedCertificates []pkix.RevokedCertificate `asn1:"optional"`
	Extensions          []pkix.Extension          `asn1:"tag:0,optional,explicit"`
}

// certificateList is RFC 5280's CertificateList, the outer signed wrapper.
type certificateList struct {
	TBSCertList        asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// crlWithoutNextUpdate builds and signs a v2 CRL with the nextUpdate field
// absent.
func crlWithoutNextUpdate(t *testing.T, signer issued, number *big.Int, thisUpdate time.Time, entries []x509.RevocationListEntry) []byte {
	t.Helper()

	revoked := make([]pkix.RevokedCertificate, 0, len(entries))
	for _, e := range entries {
		revoked = append(revoked, pkix.RevokedCertificate{
			SerialNumber:   e.SerialNumber,
			RevocationTime: e.RevocationTime.UTC(),
		})
	}

	numberDER, err := asn1.Marshal(number)
	if err != nil {
		t.Fatalf("marshal CRL number: %v", err)
	}

	algo := pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}
	tbsDER, err := asn1.Marshal(tbsCertList{
		Version:             1, // v2
		Signature:           algo,
		Issuer:              asn1.RawValue{FullBytes: signer.cert.RawSubject},
		ThisUpdate:          thisUpdate.UTC(),
		RevokedCertificates: revoked,
		Extensions:          []pkix.Extension{{Id: oidCRLNumber, Value: numberDER}},
	})
	if err != nil {
		t.Fatalf("marshal TBSCertList: %v", err)
	}

	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, signer.key, digest[:])
	if err != nil {
		t.Fatalf("sign CRL: %v", err)
	}

	der, err := asn1.Marshal(certificateList{
		TBSCertList:        asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algo,
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatalf("marshal CertificateList: %v", err)
	}
	return der
}

// dial sends one request to the gateway presenting cert, with the fixture's CA
// as the trust root.
func (f *fixture) dial(cert tls.Certificate) (*http.Response, error) {
	cfg := f.pki.tlsClientConfig()
	cfg.Certificates = []tls.Certificate{cert}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	return client.Get("https://" + f.addr + "/admin/status")
}

// mustReach fails unless cert completes the handshake and reaches the router,
// which answers 401 because no session token was sent.
func (f *fixture) mustReach(t *testing.T, cert tls.Certificate, why string) {
	t.Helper()
	resp, err := f.dial(cert)
	if err != nil {
		t.Fatalf("%s: handshake refused: %v", why, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Errorf("%s: GET /admin/status = %s, want 401 from the session middleware (body: %s)", why, resp.Status, body)
	}
}

// mustBeRefused fails unless the handshake is refused.
func (f *fixture) mustBeRefused(t *testing.T, cert tls.Certificate, why string) {
	t.Helper()
	resp, err := f.dial(cert)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("%s: reached the router with %s, want the handshake refused", why, resp.Status)
	}
}

// stopCleanly signals the child and fails the test unless it exits zero.
func (c *child) stopCleanly(t *testing.T) {
	t.Helper()
	c.signal(t, syscall.SIGTERM)
	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
	}
}
