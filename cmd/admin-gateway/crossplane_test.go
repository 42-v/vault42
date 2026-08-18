package main

import (
	"strings"
	"syscall"
	"testing"

	"github.com/42-v/vault42/internal/config"
)

// Cross-plane HMAC_SECRET agreement, at the gateway.
//
// This is the binary that actions an Article 17 request. Its cascade clears
// identity.profiles, objects.blobs and objects.service_documents by a subject
// pseudonym HMAC'd under HMAC_SECRET, so a gateway holding a different secret
// than the vault plane deletes by strings no row ever carried and reports
// success anyway. tests/integration measures that against a real database;
// what follows is the gateway refusing to be that deployment.

// gatewayHMACSecret is the secret the erasure tests in this package configure.
const gatewayHMACSecret = "0123456789abcdef"

// A recorded fingerprint belonging to another secret is fatal. Refusing the
// whole gateway is deliberate: the alternative is a running gateway whose
// erasure endpoint answers 200 to requests it silently does not fulfil.
func TestAGatewayDisagreeingWithTheVaultPlaneRefusesToStart(t *testing.T) {
	const otherPlane = "ffeeddccbbaa99887766554433221100"
	f := newFixture(t)
	f.pg.scriptRow("INSERT INTO auth.admin_config", otherPlane)

	c := launch(t, childRoleRun, f.workDir, f.env(
		"HMAC_SECRET_FILE="+writeSecret(t, "hmac-secret", []byte(gatewayHMACSecret)),
	)...)

	if code := c.waitForExit(t); code != 1 {
		t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, c.stderr.String())
	}
	out := c.stderr.String()
	for _, want := range []string{
		"HMAC_SECRET disagrees with the other vault42 plane",
		config.HMACSecretFingerprint([]byte(gatewayHMACSecret)),
		otherPlane,
		"objects.service_documents",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, gatewayHMACSecret) {
		t.Errorf("the refusal leaked the HMAC secret:\n%s", out)
	}
	if strings.Contains(out, "admin-gateway: listening on") {
		t.Errorf("the gateway served traffic despite the disagreement:\n%s", out)
	}
}

// A gateway whose fingerprint matches the one already recorded starts normally
// and says nothing about it.
func TestAGatewayAgreeingWithTheVaultPlaneStartsQuietly(t *testing.T) {
	f := newFixture(t)
	f.pg.scriptRow("INSERT INTO auth.admin_config",
		config.HMACSecretFingerprint([]byte(gatewayHMACSecret)))

	c := f.start(t, "HMAC_SECRET_FILE="+writeSecret(t, "hmac-secret", []byte(gatewayHMACSecret)))

	out := c.stderr.String()
	if strings.Contains(out, "HMAC_SECRET disagrees") || strings.Contains(out, "unverified") {
		t.Errorf("an agreeing gateway complained about the check:\n%s", out)
	}
	if strings.Contains(out, "account erasure endpoint disabled") {
		t.Errorf("the erasure endpoint was disabled despite agreement:\n%s", out)
	}

	c.signal(t, syscall.SIGTERM)
	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, out)
	}
}

// A database that cannot answer the check is not a disagreement. The gateway's
// contract against an unmigrated database is to log and keep serving — an
// operator locked out of the admin plane cannot fix the database it is
// complaining about — and a cascade run against that same database fails
// loudly on its own rather than silently.
func TestAGatewayThatCannotReadTheFingerprintWarnsAndKeepsServing(t *testing.T) {
	f := newFixture(t)

	c := f.start(t, "HMAC_SECRET_FILE="+writeSecret(t, "hmac-secret", []byte(gatewayHMACSecret)))

	out := c.stderr.String()
	if !strings.Contains(out, "erasure agreement with the vault plane is unverified") {
		t.Errorf("an unanswerable check was not reported:\n%s", out)
	}
	if strings.Contains(out, "HMAC_SECRET disagrees") {
		t.Errorf("a store failure was reported as a disagreement:\n%s", out)
	}

	c.signal(t, syscall.SIGTERM)
	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, out)
	}
}
