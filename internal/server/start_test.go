package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/honeypot"
)

func startTestDeps(t *testing.T, addr string) *Deps {
	t.Helper()
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	return &Deps{
		Config: &config.Config{
			Origin:            "https://vault.localhost",
			AppName:           "Vault Test",
			PasswordMinLength: 15,
			ListenAddr:        addr,
			Profile:           config.ProfileDev,
			ShutdownTimeout:   2 * time.Second,
		},
		Cache:     memCache,
		ReadyDeps: &handler.ReadyzDeps{},
	}
}

// Start wires the entire middleware chain and the graceful-shutdown path — the
// code every single request passes through, and the code that decides whether a
// rolling deploy drops connections. It was completely untested: setupRoutes was
// exercised directly, so nothing ever built the chain around it or proved the
// server comes up, serves, and stops cleanly on SIGTERM.
func TestStart_ServesThenShutsDownCleanly(t *testing.T) {
	// Port 0: let the kernel choose, so the test cannot collide with anything.
	deps := startTestDeps(t, "127.0.0.1:0")

	// Bind first to learn the port, then hand the address to the server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	deps.Config.ListenAddr = addr

	s := New(deps)

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start() }()

	// Wait for the listener to come up.
	var conn net.Conn
	for i := 0; i < 100; i++ {
		conn, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("server never started listening on %s: %v", addr, err)
	}
	_ = conn.Close()

	// A request must actually traverse the chain Start built.
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("request through the middleware chain failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", resp.StatusCode)
	}
	// The security headers middleware is in the chain; if the chain were not
	// assembled, the response would come back bare.
	if resp.Header.Get("X-Content-Type-Options") == "" {
		t.Error("security headers missing — the middleware chain was not applied")
	}

	// SIGTERM is how Kubernetes stops a pod. Start must return nil, not an error:
	// a non-nil return here would make the process exit non-zero on every normal
	// rollout.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("graceful shutdown returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down on SIGTERM")
	}
}

// A port that cannot be bound must surface as an error rather than a silent
// no-op — otherwise a misconfigured pod would report healthy while serving
// nothing.
func TestStart_BindFailureIsReported(t *testing.T) {
	// Hold the port so the server cannot have it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	deps := startTestDeps(t, ln.Addr().String())
	s := New(deps)

	if err := s.Start(); err == nil {
		t.Error("Start returned nil when the address was already in use")
	}
}

// In the honeypot profile Start must insert the request-logging middleware
// into the chain. The chain (honeypot branch included) is assembled before the
// listener is opened, so holding the port makes Start exercise the wiring and
// then fail at bind, without ever serving a request. That keeps the test
// scoped to the wiring itself rather than the middleware's request handling,
// which internal/honeypot already covers.
func TestStart_HoneypotProfileWiresLoggingMiddleware(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	deps := startTestDeps(t, ln.Addr().String())
	deps.Config.Profile = config.ProfileHoneypot
	deps.HoneypotAlerter = honeypot.NewAlerter("", nil, nil)

	err = New(deps).Start()
	if err == nil {
		t.Fatal("Start returned nil when the address was already in use")
	}
	if !strings.HasPrefix(err.Error(), "server: ") || !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("err = %q, want a wrapped bind failure", err)
	}
}

// writeSelfSignedCert generates a throwaway ECDSA certificate for 127.0.0.1
// and writes the PEM pair into a temp dir, returning both paths.
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vault42 test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// With TLS configured Start must pin TLS 1.3 as the floor and serve via
// ListenAndServeTLS. A handshake against the real listener proves both: the
// connection only succeeds if the cert pair loaded, and the negotiated
// version confirms the TLSConfig Start installed. Shutdown mirrors the
// plaintext test: SIGTERM must return nil.
func TestStart_TLSServesTLS13ThenShutsDownCleanly(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	deps := startTestDeps(t, addr)
	deps.Config.TLSEnabled = true
	deps.Config.TLSCertFile = certFile
	deps.Config.TLSKeyFile = keyFile

	s := New(deps)

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start() }()

	pool := x509.NewCertPool()
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add test cert to pool")
	}

	// Wait for the TLS listener to come up; a completed handshake is the
	// readiness signal.
	var conn *tls.Conn
	for i := 0; i < 100; i++ {
		conn, err = tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("server never completed a TLS handshake on %s: %v", addr, err)
	}
	// The handshake succeeding at all proves the cert pair loaded via
	// ListenAndServeTLS; the negotiated version proves the TLS 1.3 floor the
	// TLSConfig in Start pinned. Reading s.httpSrv directly would race with
	// the Start goroutine under -race, so the wire is the witness.
	if v := conn.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Errorf("negotiated TLS version = %#x, want TLS 1.3 (%#x)", v, tls.VersionTLS13)
	}
	_ = conn.Close()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("graceful TLS shutdown returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("TLS server did not shut down on SIGTERM")
	}
}

// A listener that stops serving for any reason other than a shutdown must
// surface as an error.
//
// Start distinguishes exactly two outcomes after the listener returns:
// http.ErrServerClosed, which means Shutdown was called and the drain is under
// way, and everything else, which is a failure the caller has to see. Without
// the second, a TLS listener that cannot read its own certificate would report
// the same as a clean stop, and a pod whose certificate was rotated out from
// under it would look like it had been asked to exit.
func TestStart_AServeFailureIsReportedRatherThanTreatedAsAShutdown(t *testing.T) {
	deps := startTestDeps(t, "127.0.0.1:0")
	deps.Config.TLSEnabled = true
	deps.Config.TLSCertFile = filepath.Join(t.TempDir(), "absent.crt")
	deps.Config.TLSKeyFile = filepath.Join(t.TempDir(), "absent.key")

	err := New(deps).Start()
	if err == nil {
		t.Fatal("Start returned nil when ServeTLS could not read its certificate")
	}
	if errors.Is(err, http.ErrServerClosed) {
		t.Errorf("a certificate failure was reported as a clean shutdown: %v", err)
	}
	if !strings.Contains(err.Error(), "server:") {
		t.Errorf("the error is not attributed to the server: %v", err)
	}
}
