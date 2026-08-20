package redis

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// The TLS branch of dial() was unreachable for as long as it existed: nothing
// in the tree ever set Options.TLS, so no test could tell the difference
// between a branch that encrypts the link and a branch that is syntactically
// valid. These tests drive a real handshake against a real TLS listener and
// read the bytes that went over the socket, because the property that matters
// is not "the flag was accepted" but "the AUTH password left this process
// encrypted".

// tlsRedis is a RESP2 server behind a TLS listener that keeps the raw bytes it
// read off the socket, before crypto/tls decrypted any of them. Those bytes are
// the evidence: a client that negotiated nothing, or negotiated and then fell
// back, puts the AUTH password in them in the clear.
type tlsRedis struct {
	addr  string
	roots *x509.CertPool

	mu       sync.Mutex
	wire     []byte
	commands [][]string
	states   []tls.ConnectionState
}

func (f *tlsRedis) record(b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wire = append(f.wire, b...)
}

func (f *tlsRedis) wireBytes() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return bytes.Clone(f.wire)
}

func (f *tlsRedis) sawCommand(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, args := range f.commands {
		if len(args) > 0 && strings.EqualFold(args[0], name) {
			return args
		}
	}
	return nil
}

func (f *tlsRedis) handshakes() []tls.ConnectionState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tls.ConnectionState(nil), f.states...)
}

// wireListener and wireConn tee everything read from the peer into the
// recorder. They sit *under* tls.NewListener, so what they see is what a tap on
// the network would see.
type wireListener struct {
	net.Listener
	rec *tlsRedis
}

func (l *wireListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &wireConn{Conn: c, rec: l.rec}, nil
}

type wireConn struct {
	net.Conn
	rec *tlsRedis
}

func (c *wireConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.rec.record(b[:n])
	}
	return n, err
}

// startTLSRedis mints a throwaway CA, issues a leaf naming serverName and
// nothing else, and serves RESP over TLS on loopback. The leaf carries no IP
// SAN on purpose: the handshake can only verify if the client sent serverName,
// so a client that ignores Options.TLSServerName fails rather than passes
// quietly.
func startTLSRedis(t *testing.T, serverName string, handle func(args []string) string) *tlsRedis {
	t.Helper()

	ca := issueTestCert(t, testCert{}, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vault42 redis test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
	leaf := issueTestCert(t, ca, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{serverName},
	})

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	f := &tlsRedis{addr: raw.Addr().String(), roots: x509.NewCertPool()}
	f.roots.AddCert(ca.cert)

	ln := tls.NewListener(&wireListener{Listener: raw, rec: f}, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.der}, PrivateKey: leaf.key}},
	})
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c, handle)
		}
	}()
	return f
}

func (f *tlsRedis) serve(c net.Conn, handle func(args []string) string) {
	defer c.Close()

	tc, ok := c.(*tls.Conn)
	if !ok {
		return
	}
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return
	}
	f.mu.Lock()
	f.states = append(f.states, tc.ConnectionState())
	f.mu.Unlock()

	rd := bufio.NewReader(tc)
	for {
		args, err := readRESPCommand(rd)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.commands = append(f.commands, args)
		f.mu.Unlock()

		reply := handle(args)
		if reply == "" {
			return
		}
		if _, err := tc.Write([]byte(reply)); err != nil {
			return
		}
	}
}

// testCert is a certificate together with the key that signed for it.
type testCert struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

// issueTestCert signs tmpl with the given issuer. A zero issuer self-signs.
// Certificates are minted per run rather than checked in so the suite never
// depends on a fixture that expires.
func issueTestCert(t *testing.T, issuer testCert, tmpl *x509.Certificate) testCert {
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
	return testCert{cert: cert, der: der, key: key}
}

// The whole point of the option: the AUTH password and everything after it
// leave this process encrypted, under a certificate that was actually verified
// against the configured roots and the configured name.
func TestPool_TLSDialCompletesAVerifiedHandshakeAndHidesTheAUTHPassword(t *testing.T) {
	const (
		serverName = "redis.vault42.test"
		password   = "correct-horse-battery-staple"
	)

	f := startTLSRedis(t, serverName, func(args []string) string {
		return "+OK\r\n"
	})

	c := NewClient(&Options{
		Addr:          f.addr,
		Password:      password,
		TLS:           true,
		TLSRootCAs:    f.roots,
		TLSServerName: serverName,
		DialTimeout:   5 * time.Second,
		IOTimeout:     5 * time.Second,
	})
	t.Cleanup(func() { _ = c.Close() })

	// PING is answered with +OK by the handler above, which Ping rejects; the
	// AUTH that precedes it is what this test is about, so the reply is checked
	// through the recorded commands instead.
	_ = c.Ping(context.Background())

	states := f.handshakes()
	if len(states) == 0 {
		t.Fatal("the server completed no TLS handshake; the connection was not encrypted")
	}
	st := states[0]
	if !st.HandshakeComplete {
		t.Error("the recorded connection state reports an incomplete handshake")
	}
	if st.Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version 0x%04x, below the TLS 1.2 floor dial() pins", st.Version)
	}
	if st.ServerName != serverName {
		t.Errorf("the server saw ServerName %q, want %q; TLSServerName is what the certificate is verified against, and an empty one falls back to the host of Addr, which here is an IP the certificate does not name", st.ServerName, serverName)
	}

	// Without this the byte assertion below is vacuous: a client that never
	// authenticated also never puts the password on the wire.
	auth := f.sawCommand("AUTH")
	if auth == nil {
		t.Fatal("the server never received AUTH, so nothing was proven about how it traveled")
	}
	if len(auth) < 2 || auth[1] != password {
		t.Fatalf("AUTH carried %v, want the configured password", auth[1:])
	}

	if wire := f.wireBytes(); bytes.Contains(wire, []byte(password)) {
		t.Errorf("the Redis AUTH password appears verbatim in the %d raw bytes the listener read; the link was not encrypted", len(wire))
	}
}

// A flag that is accepted, stored in a struct and never read looks exactly like
// a working one until somebody watches the wire. Pointed at a server that
// speaks no TLS, a client with TLS enabled must fail: falling back to plaintext
// is the outcome an operator configured this option to prevent.
func TestPool_TLSAgainstAPlaintextServerFailsRatherThanDowngrading(t *testing.T) {
	addr := startFakeRedis(t, func(args []string) string {
		return "+PONG\r\n"
	})

	c := NewClient(&Options{
		Addr:        addr,
		TLS:         true,
		DialTimeout: 2 * time.Second,
		IOTimeout:   2 * time.Second,
	})
	t.Cleanup(func() { _ = c.Close() })

	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("a TLS client connected to a plaintext server and reported success; the cache link silently downgraded")
	}
}

// RootCAs has to be consulted, not merely stored. A server whose certificate
// this client cannot chain must be refused: the alternative is an encrypted
// link to whoever answered on that address, which is the failure verification
// exists to prevent.
func TestPool_TLSWithoutTheIssuingCAIsRefused(t *testing.T) {
	const serverName = "redis.vault42.test"

	f := startTLSRedis(t, serverName, func(args []string) string {
		return "+PONG\r\n"
	})

	// A well-formed pool that simply does not contain the issuer, rather than a
	// nil one: nil means the host trust store, and a test that passed only
	// because the host trusts nothing would prove nothing about RootCAs.
	stranger := issueTestCert(t, testCert{}, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "some other CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
	pool := x509.NewCertPool()
	pool.AddCert(stranger.cert)

	c := NewClient(&Options{
		Addr:          f.addr,
		TLS:           true,
		TLSRootCAs:    pool,
		TLSServerName: serverName,
		DialTimeout:   2 * time.Second,
		IOTimeout:     2 * time.Second,
	})
	t.Cleanup(func() { _ = c.Close() })

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("a certificate signed by an unknown CA was accepted; RootCAs is not being verified against")
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Errorf("dial failed with %v, want an unknown-authority error; anything else means it failed for some reason other than verification", err)
	}
}

// The TLS handshake is a second round trip after the TCP connect, and a peer
// that accepts the connection and then says nothing is the ordinary shape of a
// half-configured TLS proxy in front of Redis. Every request that reaches one
// holds a connection out of a pool of ten, so a caller who has given up has to
// be able to take its slot back.
func TestPool_TLSDialHonorsContextCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// The accepted connections are held, not closed: closing them would fail
	// the handshake on its own and the test would pass without cancellation
	// doing anything.
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()

	c := NewClient(&Options{
		Addr:        ln.Addr().String(),
		TLS:         true,
		DialTimeout: 30 * time.Second,
		IOTimeout:   time.Second,
	})
	t.Cleanup(func() { _ = c.Close() })

	// Cancellation, not a deadline: dial() already shortens its own timeout to a
	// context deadline, so a deadline would be honored even by a dialer that
	// ignores the context entirely.
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	err = c.Ping(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a dial into a stalled handshake reported success")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("dial failed with %v, want context.Canceled; the handshake is not running under the caller's context", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("the canceled dial took %v to return; it waited out DialTimeout instead of the context", elapsed)
	}
}
