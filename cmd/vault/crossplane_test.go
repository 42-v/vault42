package main

import (
	"strings"
	"syscall"
	"testing"

	"github.com/42-v/vault42/internal/config"
)

// Cross-plane HMAC_SECRET agreement, at the entry point.
//
// The hazard is not a crash. cmd/admin-gateway derives the same subject
// pseudonyms from the same secret, so a deployment whose two planes hold
// different HMAC secrets erases by strings no row ever carried: zero rows
// cleared from identity.profiles, objects.blobs and objects.service_documents,
// no error, and an AccountErased audit row. tests/integration measures that
// against a real database; this file pins what this binary does about it.

// bootHMACSecret is the secret bootEnv writes to HMAC_SECRET_FILE. The
// fingerprint a healthy boot records is derived from exactly this value.
var bootHMACSecret = strings.Repeat("h", 32)

// fingerprintRule scripts the auth.admin_config claim with the fingerprint a
// database already holds. The claim is an upsert that returns the incumbent, so
// what this rule answers with IS what the other plane recorded.
func fingerprintRule(recorded string) pgRule {
	return pgRule{
		match: "INSERT INTO auth.admin_config",
		cols:  textColumns("value"),
		rows:  [][][]byte{textRow(recorded)},
		tag:   "INSERT 0 1",
	}
}

// A database that already carries this plane's own fingerprint is the ordinary
// case: the other plane recorded first, they agree, and startup says nothing.
func TestABootAgreeingWithTheOtherPlaneIsSilent(t *testing.T) {
	stub := startPGStub(t,
		adminTokenRule("$argon2id$already-provisioned"),
		fingerprintRule(config.HMACSecretFingerprint([]byte(bootHMACSecret))),
	)
	addr := freeAddr(t)

	res := bootAndShutdown(t, vaultRun{env: bootEnv(t, stub, addr)}, addr, syscall.SIGTERM, nil)

	requireExit(t, res, 0, "Shutting down...")
	if strings.Contains(res.stderr, "HMAC_SECRET") {
		t.Errorf("an agreeing boot said something about HMAC_SECRET:\n%s", res.stderr)
	}
	if !stub.sawQuery("INSERT INTO auth.admin_config") {
		t.Error("startup never claimed the cross-plane fingerprint row")
	}
	requireNoSecretLeak(t, res, bootHMACSecret)
}

// The defect, at the only place this binary can refuse it. A recorded
// fingerprint that belongs to another secret means every pseudonym this server
// would write from here on is unreachable by the plane that erases, so it must
// not serve.
func TestABootDisagreeingWithTheOtherPlaneRefusesToServe(t *testing.T) {
	const otherPlane = "00112233445566778899aabbccddeeff"
	stub := startPGStub(t,
		adminTokenRule("$argon2id$already-provisioned"),
		fingerprintRule(otherPlane),
	)

	res := runVault(t, vaultRun{env: bootEnv(t, stub, freeAddr(t))})

	requireExit(t, res, 1, "HMAC_SECRET disagrees with the other vault42 plane")
	// An operator has to be able to act on this: which fingerprint is here,
	// which one is recorded, and what to do about it.
	for _, want := range []string{
		config.HMACSecretFingerprint([]byte(bootHMACSecret)),
		otherPlane,
		"HMAC_SECRET_FILE",
		"objects.service_documents",
	} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, res.stderr)
		}
	}
	requireNoSecretLeak(t, res, bootHMACSecret)
}

// A store that cannot answer is not a disagreement. This process is about to
// depend on the same pool for everything and its own failures will say so, so an
// unanswerable check is reported and startup continues — the alternative turns
// any database hiccup into a refusal to boot.
func TestABootThatCannotReadTheFingerprintWarnsAndContinues(t *testing.T) {
	stub := startPGStub(t,
		adminTokenRule("$argon2id$already-provisioned"),
		pgRule{
			match:   "INSERT INTO auth.admin_config",
			errCode: "42P01",
			errMsg:  "relation \"auth.admin_config\" does not exist",
		},
	)
	addr := freeAddr(t)

	res := bootAndShutdown(t, vaultRun{env: bootEnv(t, stub, addr)}, addr, syscall.SIGTERM, nil)

	requireExit(t, res, 0, "Shutting down...")
	if !strings.Contains(res.stderr, "erasure agreement with the admin gateway is unverified") {
		t.Errorf("an unanswerable check was not reported:\n%s", res.stderr)
	}
	if strings.Contains(res.stderr, "disagrees with the other vault42 plane") {
		t.Errorf("a store failure was reported as a disagreement:\n%s", res.stderr)
	}
	requireNoSecretLeak(t, res, bootHMACSecret)
}
