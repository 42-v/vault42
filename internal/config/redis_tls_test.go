package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REDIS_TLS_CA_FILE is read here rather than on the first cache dial, so this
// is where a bundle the process cannot use has to be caught. The failure the
// startup read prevents is not a crash: cmd/vault answers a failed cache
// connection by logging one line and substituting a per-process memory cache,
// where the login limiter, the OAuth state and the TOTP replay guard silently
// stop being shared between replicas.

// mintRedisTestCA writes a PEM CA bundle to a temp file and returns the path
// together with a leaf it signed, so a test can ask whether the pool Load built
// actually chains a server certificate.
func mintRedisTestCA(t *testing.T, dnsName string) (caFile string, leaf *x509.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vault42 redis config test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	caFile = filepath.Join(t.TempDir(), "redis-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}
	return caFile, leaf
}

// The pool has to be usable, not merely non-nil. An empty or wrongly parsed
// pool verifies nothing, and the dial that discovers it is the one this read
// exists to keep off the critical path.
func TestLoadParsesTheRedisCAFileIntoAPoolThatChainsTheServerCertificate(t *testing.T) {
	const serverName = "redis.vault42.test"
	caFile, leaf := mintRedisTestCA(t, serverName)

	t.Setenv("VAULT_PROFILE", "embedded")
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CA_FILE", caFile)
	t.Setenv("REDIS_TLS_SERVER_NAME", serverName)

	c, err := Load()
	if err != nil {
		t.Fatalf("Load rejected a valid CA bundle: %v", err)
	}
	if !c.RedisTLS {
		t.Fatal("RedisTLS = false after REDIS_TLS=true")
	}
	if c.RedisTLSServerName != serverName {
		t.Errorf("RedisTLSServerName = %q, want %q", c.RedisTLSServerName, serverName)
	}
	if c.RedisTLSRootCAs == nil {
		t.Fatal("RedisTLSRootCAs is nil, so the dialer would fall back to the host trust store, which on the runtime image holds public roots only")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       c.RedisTLSRootCAs,
		DNSName:     serverName,
		CurrentTime: time.Now(),
	}); err != nil {
		t.Errorf("a certificate issued by the configured CA does not verify against the pool Load built: %v", err)
	}
}

// A file that holds no certificate produces an empty pool, which verifies
// nothing and fails every dial. Refused at startup, it is one clear error;
// accepted, it is a healthy process with a degraded cache.
func TestLoadRefusesARedisCAFileThatIsNotAPEMBundle(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "not-a-ca.pem")
	if err := os.WriteFile(caFile, []byte("-----BEGIN CERTIFICATE-----\nnot base64 at all\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	t.Setenv("VAULT_PROFILE", "embedded")
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CA_FILE", caFile)

	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted a CA file with no certificate in it")
	}
	if !strings.Contains(err.Error(), "REDIS_TLS_CA_FILE") {
		t.Errorf("error %q does not name REDIS_TLS_CA_FILE, which is what the operator has to fix", err)
	}
}

// An absent mount is the common shape of this mistake: the manifest names the
// path, the volume is missing, and the value looks configured from every angle
// except the filesystem.
func TestLoadRefusesARedisCAFileItCannotRead(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "embedded")
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CA_FILE", filepath.Join(t.TempDir(), "absent", "ca.pem"))

	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted a CA path that does not exist")
	}
	if !strings.Contains(err.Error(), "REDIS_TLS_CA_FILE") {
		t.Errorf("error %q does not name REDIS_TLS_CA_FILE", err)
	}
}

// An operator who mounts a CA bundle or pins a server name believes the cache
// link is encrypted. Without REDIS_TLS it is not, and neither setting is read,
// so the deployment looks configured and ships the AUTH password in cleartext.
// That is the case envcheck.go's second rule refuses: a value that is set but
// cannot be honored must not be indistinguishable from nothing being set.
func TestLoadRefusesRedisTLSSettingsWithoutRedisTLS(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"REDIS_TLS_CA_FILE", "/etc/redis/ca.pem"},
		{"REDIS_TLS_SERVER_NAME", "redis.vault42.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "embedded")
			t.Setenv(tc.name, tc.value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted %s with REDIS_TLS unset; the cache link would still be cleartext", tc.name)
			}
			if !strings.Contains(err.Error(), tc.name) || !strings.Contains(err.Error(), "REDIS_TLS") {
				t.Errorf("error %q names neither the setting nor the switch that would honor it", err)
			}
		})
	}
}

// The managed-Redis case: a publicly rooted server certificate needs no bundle,
// and a nil pool is how crypto/tls is told to use the host trust store. It has
// to stay reachable, or the option only works for operators who run their own
// CA.
func TestLoadAcceptsRedisTLSWithNoCAFile(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "embedded")
	t.Setenv("REDIS_TLS", "true")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.RedisTLS {
		t.Fatal("RedisTLS = false after REDIS_TLS=true")
	}
	if c.RedisTLSRootCAs != nil {
		t.Error("RedisTLSRootCAs is set although no bundle was named; nil is what selects the host trust store")
	}
}

// The default has to stay off. Turning it on for a deployment whose Redis does
// not terminate TLS would break the cache on upgrade, which is the trade the
// warning below exists to make instead.
func TestLoadLeavesRedisTLSOffByDefault(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "embedded")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.RedisTLS {
		t.Fatal("RedisTLS defaulted to true")
	}
}

// The shipped chart addresses Redis as "redis:6379", a service name, which is a
// routed connection to another pod. Left in cleartext it carries the AUTH
// password, the lockout and rate-limit keys with the client addresses they are
// keyed on, and password-confirmation jtis, and nothing said so anywhere.
func TestANonLoopbackRedisAddrWithoutTLSWarns(t *testing.T) {
	c := &Config{CacheBackend: "redis", RedisAddr: "redis:6379"}
	out := cliconfigCaptureLog(t, c.warnOnDegradedControls)

	if !strings.Contains(out, "REDIS_ADDR") {
		t.Errorf("a cleartext cache link to another pod logged no warning about it:\n%s", out)
	}
	if !strings.Contains(out, "REDIS_TLS") {
		t.Errorf("the warning does not name the setting that fixes it:\n%s", out)
	}
}

// A hop that never leaves the machine is the one case where cleartext is a
// deliberate, defensible choice -- the same exemption VAULT_SMTP_ALLOW_PLAINTEXT
// is scoped to. Warning there would train operators to ignore the line.
func TestALoopbackRedisAddrDoesNotWarn(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:6379", "[::1]:6379", "localhost:6379", "localhost"} {
		t.Run(addr, func(t *testing.T) {
			c := &Config{CacheBackend: "redis", RedisAddr: addr}
			out := cliconfigCaptureLog(t, c.warnOnDegradedControls)

			if strings.Contains(out, "REDIS_ADDR") {
				t.Errorf("a loopback cache link warned about being cleartext:\n%s", out)
			}
		})
	}
}

// And the configured case is silent, which is what makes the warning worth
// reading.
func TestARemoteRedisAddrWithTLSDoesNotWarn(t *testing.T) {
	c := &Config{CacheBackend: "redis", RedisAddr: "redis:6379", RedisTLS: true}
	out := cliconfigCaptureLog(t, c.warnOnDegradedControls)

	if strings.Contains(out, "REDIS_ADDR") {
		t.Errorf("an encrypted cache link still warned:\n%s", out)
	}
}

// A deployment that is not using Redis at all has no cache link to warn about,
// and a warning naming a variable that is doing nothing is noise.
func TestANonRedisCacheBackendDoesNotWarnAboutRedis(t *testing.T) {
	c := &Config{CacheBackend: "memory", RedisAddr: "redis:6379"}
	out := cliconfigCaptureLog(t, c.warnOnDegradedControls)

	if strings.Contains(out, "REDIS_ADDR") {
		t.Errorf("the memory backend warned about a Redis address it never dials:\n%s", out)
	}
}
