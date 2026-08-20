package cache

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
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// The Redis backend is where the transport setting stops being a config field
// and becomes a socket. A setting that is parsed, carried through a struct and
// dropped one call short of vredis.Options looks identical from the outside to
// one that works, so these tests watch the wire rather than the struct.

// tlsFakeRedis answers PING and AUTH over TLS and keeps the raw bytes it read
// off the socket before crypto/tls decrypted them.
type tlsFakeRedis struct {
	addr  string
	roots *x509.CertPool

	mu         sync.Mutex
	wire       []byte
	handshakes []tls.ConnectionState
}

func (f *tlsFakeRedis) wireBytes() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return bytes.Clone(f.wire)
}

func (f *tlsFakeRedis) states() []tls.ConnectionState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tls.ConnectionState(nil), f.handshakes...)
}

// tlsWireListener and tlsWireConn sit under tls.NewListener, so what they
// record is what a tap on the network would see.
type tlsWireListener struct {
	net.Listener
	rec *tlsFakeRedis
}

func (l *tlsWireListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tlsWireConn{Conn: c, rec: l.rec}, nil
}

type tlsWireConn struct {
	net.Conn
	rec *tlsFakeRedis
}

func (c *tlsWireConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.rec.mu.Lock()
		c.rec.wire = append(c.rec.wire, b[:n]...)
		c.rec.mu.Unlock()
	}
	return n, err
}

// newTLSFakeRedis serves RESP over TLS on loopback under a throwaway CA. The
// leaf names serverName and carries no IP SAN, so the handshake verifies only
// if the client sent the configured name.
func newTLSFakeRedis(t *testing.T, serverName string) *tlsFakeRedis {
	t.Helper()

	ca := issueCacheTestCert(t, cacheTestCert{}, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vault42 cache test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
	leaf := issueCacheTestCert(t, ca, &x509.Certificate{
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

	f := &tlsFakeRedis{addr: raw.Addr().String(), roots: x509.NewCertPool()}
	f.roots.AddCert(ca.cert)

	ln := tls.NewListener(&tlsWireListener{Listener: raw, rec: f}, &tls.Config{
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
			go f.serve(c)
		}
	}()
	return f
}

func (f *tlsFakeRedis) serve(c net.Conn) {
	defer c.Close() //nolint:errcheck // test peer teardown

	tc, ok := c.(*tls.Conn)
	if !ok {
		return
	}
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return
	}
	f.mu.Lock()
	f.handshakes = append(f.handshakes, tc.ConnectionState())
	f.mu.Unlock()

	rd := bufio.NewReader(tc)
	for {
		args, err := readArray(rd)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		reply := "+OK\r\n"
		if strings.EqualFold(args[0], "PING") {
			reply = "+PONG\r\n"
		}
		if _, err := tc.Write([]byte(reply)); err != nil {
			return
		}
	}
}

// cacheTestCert is a certificate together with the key that signed for it.
type cacheTestCert struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

// issueCacheTestCert signs tmpl with the given issuer. A zero issuer self-signs.
func issueCacheTestCert(t *testing.T, issuer cacheTestCert, tmpl *x509.Certificate) cacheTestCert {
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
	return cacheTestCert{cert: cert, der: der, key: key}
}

// Every field of RedisTLS has to arrive at the dialer. The certificate is
// verifiable only against the supplied roots and only under the supplied name,
// so a constructor that drops either one fails the handshake rather than
// connecting anyway.
func TestNewRedisCache_TLSOptionsReachTheDialer(t *testing.T) {
	const serverName = "redis.vault42.test"
	const password = "correct-horse-battery-staple"

	f := newTLSFakeRedis(t, serverName)

	c, err := NewRedisCache(f.addr, password, 0, RedisTLS{
		Enabled:    true,
		RootCAs:    f.roots,
		ServerName: serverName,
	})
	if err != nil {
		t.Fatalf("NewRedisCache over TLS: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	states := f.states()
	if len(states) == 0 {
		t.Fatal("the cache connected without completing a TLS handshake")
	}
	if states[0].Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version 0x%04x, below the TLS 1.2 floor", states[0].Version)
	}
	if states[0].ServerName != serverName {
		t.Errorf("the server saw ServerName %q, want %q", states[0].ServerName, serverName)
	}
	if wire := f.wireBytes(); bytes.Contains(wire, []byte(password)) {
		t.Errorf("the Redis AUTH password appears verbatim in the %d raw bytes the listener read", len(wire))
	}
}

// The factory is a second place the setting can be dropped, and dropping it
// there is invisible: NewCache would return a working cache on a cleartext
// link. Driving the same handshake through NewCache pins the forwarding.
func TestNewCache_ForwardsRedisTLSToTheRedisBackend(t *testing.T) {
	const serverName = "redis.vault42.test"

	f := newTLSFakeRedis(t, serverName)

	c, err := NewCache("redis", f.addr, "", nil, RedisTLS{
		Enabled:    true,
		RootCAs:    f.roots,
		ServerName: serverName,
	})
	if err != nil {
		t.Fatalf("NewCache(redis) over TLS: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if len(f.states()) == 0 {
		t.Fatal("NewCache built a Redis cache that completed no TLS handshake; the options did not reach the backend")
	}
}

// A flag that is accepted, stored and never read looks exactly like one that
// works. Pointed at a server that speaks no TLS, an operator who asked for TLS
// must get a failure: a silent downgrade is the outcome the setting exists to
// prevent, and the cache would come up carrying the AUTH password in cleartext.
func TestNewRedisCache_TLSAgainstAPlaintextServerFails(t *testing.T) {
	f := newFakeRedis(t)

	c, err := NewRedisCache(f.addr(), "", 0, RedisTLS{Enabled: true})
	if err == nil {
		_ = c.Close()
		t.Fatal("a TLS cache connected to a plaintext Redis and reported success")
	}
}

// Two option structs would leave the second silently deciding whether the link
// is encrypted. The caller hears about it instead.
func TestNewRedisCache_MoreThanOneRedisTLSIsRefused(t *testing.T) {
	_, err := NewRedisCache("127.0.0.1:1", "", 0, RedisTLS{}, RedisTLS{Enabled: true})
	if err == nil {
		t.Fatal("two RedisTLS values were accepted; one of them was silently ignored")
	}
	if !strings.Contains(err.Error(), "at most one") {
		t.Errorf("error %q does not say which call is wrong", err)
	}
}
