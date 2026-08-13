package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
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
	if err := os.WriteFile(path, data, 0o600); err != nil {
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
