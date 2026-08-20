package compliance

import (
	"go/ast"
	"strings"
	"testing"
)

// =============================================================================
// OWASP Application Security Verification Standard (ASVS) 5.0.0
// V12: Secure Communication
// https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0
//
// Also evidences NIST SP 800-53 Rev 5 (Release 5.2.0) SC-8 and SC-23.
//
// These are structural assertions. A unit test can prove that the server that
// exists today negotiates TLS 1.3; it cannot prove that the tls.Config someone
// adds next month sets MinVersion at all. Scanning every tls.Config in the
// production tree is the only form of this test that keeps working.
// =============================================================================

// tlsVersionRank orders the crypto/tls version constants. Anything not listed
// is unknown and treated as a failure rather than as "probably fine".
var tlsVersionRank = map[string]int{
	"tls.VersionSSL30": 0,
	"tls.VersionTLS10": 1,
	"tls.VersionTLS11": 2,
	"tls.VersionTLS12": 3,
	"tls.VersionTLS13": 4,
}

// --- V12.1.1: Only current TLS versions are enabled ---

// "Verify that only the latest recommended versions of the TLS protocol are
// enabled, such as TLS 1.2 and TLS 1.3."
//
// The floor asserted here is TLS 1.2, which is what ASVS 5.0.0 permits. The
// stronger TLS 1.3 claim is scoped to inbound listeners and asserted
// separately, because that is the only place vault42 controls both ends.
func TestASVS_V12_1_1_EveryTLSConfigDeclaresAMinimumVersion(t *testing.T) {
	files := productionGoFiles(t)
	configs := compositeLiteralsOfType(files, "tls.Config")
	if len(configs) == 0 {
		t.Fatal("V12.1.1: no tls.Config literal found in the production tree; the scan is broken")
	}

	for _, c := range configs {
		where := c.pos(c.Lit)
		value, ok := litField(c.Lit, "MinVersion")
		if !ok {
			t.Errorf("V12.1.1: %s declares a tls.Config with no MinVersion; it inherits the Go default and silently accepts whatever that becomes", where)
			continue
		}
		name := selectorName(value)
		rank, known := tlsVersionRank[name]
		if !known {
			t.Errorf("V12.1.1: %s sets MinVersion to %q, which is not a recognized crypto/tls version constant", where, name)
			continue
		}
		if rank < tlsVersionRank["tls.VersionTLS12"] {
			t.Errorf("V12.1.1: %s sets MinVersion to %s, below the TLS 1.2 floor", where, name)
		}
	}
}

// The two listeners vault42 itself terminates are held to TLS 1.3. Outbound
// clients (Redis) are not, because the peer's capability is the operator's
// choice; that difference is recorded in the compliance register rather than
// asserted away here.
func TestASVS_V12_1_1_InboundListenersRequireTLS13(t *testing.T) {
	if files := productionGoFiles(t); len(files) < 100 {
		t.Fatalf("V12.1.1: only %d production files parsed; the scan is broken and every assertion below would pass vacuously", len(files))
	}

	inbound := map[string]bool{
		"internal/server/server.go": false,
		"cmd/admin-gateway/main.go": false,
	}

	for _, c := range compositeLiteralsOfType(productionGoFiles(t), "tls.Config") {
		if _, watched := inbound[c.path]; !watched {
			continue
		}
		value, ok := litField(c.Lit, "MinVersion")
		if !ok || selectorName(value) != "tls.VersionTLS13" {
			t.Errorf("V12.1.1: %s terminates inbound TLS but does not pin MinVersion to tls.VersionTLS13", c.pos(c.Lit))
			continue
		}
		inbound[c.path] = true
	}

	for path, found := range inbound {
		if !found {
			t.Errorf("V12.1.1: no inbound tls.Config was found in %s; either the listener moved or TLS was dropped", path)
		}
	}
}

// --- V12.1.3: mTLS client certificates are validated ---

// "Verify that the application validates that mTLS client certificates are
// trusted before using the certificate identity for authentication or
// authorization."
//
// tls.RequireAnyClientCert accepts any certificate a client presents, verifying
// nothing. Only RequireAndVerifyClientCert checks it against ClientCAs, so the
// constant itself is the control and is asserted by name.
func TestASVS_V12_1_3_AdminGatewayRequiresAndVerifiesClientCerts(t *testing.T) {
	var checked int
	for _, c := range compositeLiteralsOfType(productionGoFiles(t), "tls.Config") {
		if c.path != "cmd/admin-gateway/main.go" {
			continue
		}
		checked++

		auth, ok := litField(c.Lit, "ClientAuth")
		if !ok {
			t.Errorf("V12.1.3: %s sets no ClientAuth; the admin gateway would accept unauthenticated clients", c.pos(c.Lit))
			continue
		}
		if got := selectorName(auth); got != "tls.RequireAndVerifyClientCert" {
			t.Errorf("V12.1.3: %s sets ClientAuth to %s; only tls.RequireAndVerifyClientCert verifies the certificate against ClientCAs", c.pos(c.Lit), got)
		}
		if _, ok := litField(c.Lit, "ClientCAs"); !ok {
			t.Errorf("V12.1.3: %s verifies client certificates but supplies no ClientCAs pool", c.pos(c.Lit))
		}
	}
	if checked == 0 {
		t.Fatal("V12.1.3: no tls.Config found in cmd/admin-gateway/main.go; the admin gateway's mTLS listener has moved or been removed")
	}
}

// --- V12.3.2: TLS clients validate the certificates they receive ---

// "Verify that TLS clients validate certificates received before communicating
// with a TLS server."
//
// InsecureSkipVerify disables exactly that. It is legitimate in tests, which
// mint their own throwaway CAs, and never legitimate in shipped code. The scan
// covers internal/ and cmd/ with _test.go excluded, so a test helper cannot
// launder one in.
func TestASVS_V12_3_2_NoInsecureSkipVerifyInProductionCode(t *testing.T) {
	files := productionGoFiles(t)
	found := false

	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "InsecureSkipVerify" {
				return true
			}
			found = true
			if ident, ok := kv.Value.(*ast.Ident); ok && ident.Name == "false" {
				return true
			}
			t.Errorf("V12.3.2: %s sets InsecureSkipVerify in shipped code; the peer certificate would not be validated", pf.pos(kv))
			return true
		})
	}

	// Absence is the expected outcome, so it cannot double as the pass
	// condition for a broken scan. The file walk is already floor-checked in
	// productionGoFiles; this only records which case was observed.
	if found {
		t.Log("V12.3.2: InsecureSkipVerify appears in production code and was explicitly set to false")
	}
}

// --- V12.2.1 / V12.3.1: no fallback to unencrypted transport ---

// "Verify that TLS is used for all connectivity between a client and external
// facing, HTTP-based services, and does not fall back to insecure or
// unencrypted communications."
//
// vault42 permits plaintext only behind an explicit operator override. The
// property asserted is that the override exists and that the non-dev profile
// refuses to start without it, not that TLS happens to be on in this process.
func TestASVS_V12_2_1_PlaintextRequiresAnExplicitOverride(t *testing.T) {
	src := readProductionSource(t, "internal/config/config.go")

	for _, needle := range []string{"VAULT_ALLOW_PLAINTEXT", "c.TLSEnabled", "ForceSecureCookies"} {
		if !strings.Contains(src, needle) {
			t.Errorf("V12.2.1: internal/config/config.go no longer mentions %q; the plaintext guard has moved or been removed", needle)
		}
	}

	// The guard must live inside Validate, which the non-dev profile runs at
	// startup. A constant defined but never consulted is not a control.
	validateIdx := strings.Index(src, "func (c *Config) Validate() error")
	if validateIdx < 0 {
		t.Fatal("V12.2.1: Config.Validate is gone; the startup security gate no longer exists")
	}
	if !strings.Contains(src[validateIdx:], "VAULT_ALLOW_PLAINTEXT") {
		t.Error("V12.2.1: VAULT_ALLOW_PLAINTEXT is no longer checked inside Config.Validate; plaintext would be reachable without an override")
	}
}

// TestASVS_V12_3_1_TheCacheLinkCanBeEncrypted covers the requirement that
// traffic to a backend service is encrypted.
//
// The Redis client had a TLS branch from the beginning, and nothing in
// production ever set the flag that reached it: cache.NewRedisCache built its
// options from an address, a password and a database number, no environment
// variable supplied anything else, and the branch was unreachable code that
// read as a control. That is the shape this file exists to catch, and it stood
// for four releases because every test asked whether the client constructs
// rather than what it negotiates.
//
// So this asserts the wiring end to end and in the direction that fails when it
// is undone. The behaviour -- a real handshake, a refusal to downgrade against a
// plaintext server, a refusal without the issuing CA -- is held by the tests in
// internal/redis and internal/cache, which drive a TLS listener rather than
// reading source. What is left for a structural gate is the part those cannot
// see: that the setting still travels from the environment, through the config,
// into the options the dialer reads, and out to a chart an operator can set.
func TestASVS_V12_3_1_TheCacheLinkCanBeEncrypted(t *testing.T) {
	config := readProductionSource(t, "internal/config/config.go")
	for _, env := range []struct{ name, why string }{
		{"REDIS_TLS", "the switch itself; without it the dial path is unreachable again"},
		{"REDIS_TLS_CA_FILE", "an in-cluster issuer is not in the distroless image's trust store, so a private CA has to be supplied or only a publicly trusted Redis can be verified"},
		{"REDIS_TLS_SERVER_NAME", "the certificate's name and the address do not have to agree, and without an override the only options are to weaken verification or to not connect"},
	} {
		if !strings.Contains(config, env.name) {
			t.Errorf("V12.3.1: internal/config no longer reads %s -- %s", env.name, env.why)
		}
	}

	// The options literal is the join. A config field nothing copies into it is
	// the same unreachable branch in a different place.
	cache := readProductionSource(t, "internal/cache/redis.go")
	for _, field := range []string{"TLS:", "TLSServerName:", "TLSRootCAs:"} {
		if !strings.Contains(cache, field) {
			t.Errorf("V12.3.1: internal/cache/redis.go no longer sets %s on the client options, "+
				"so the dialer cannot see the setting however it was configured", field)
		}
	}

	// TLS 1.2 is the floor the dial path pins, and a version pinned in a
	// comment is not pinned.
	pool := readProductionSource(t, "internal/redis/pool.go")
	if !strings.Contains(pool, "MinVersion: tls.VersionTLS12") {
		t.Error("V12.3.1: internal/redis/pool.go no longer pins a minimum TLS version for the " +
			"cache dial, so the negotiated version is whatever the server will accept")
	}
	if !strings.Contains(pool, "RootCAs:") {
		t.Error("V12.3.1: the cache dial no longer passes a root CA pool, so verification falls " +
			"back to the host trust store and an in-cluster issuer cannot be used")
	}

	// And the chart, because a setting an operator cannot reach is a setting
	// that does not exist for a deployment. tests/spec holds the general rule;
	// this names the three that carry this requirement.
	for _, tpl := range []string{"charts/vault/templates/configmap.yaml", "charts/vault/templates/deployment.yaml"} {
		rendered := readProductionSource(t, tpl)
		if strings.Contains(rendered, "REDIS_TLS") {
			return
		}
	}
	t.Error("V12.3.1: neither chart template names REDIS_TLS, so no deployment can turn the " +
		"encryption on and the row is true about the code and false about anything installed")
}
