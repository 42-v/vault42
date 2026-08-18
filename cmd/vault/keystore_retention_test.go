package main

// The expired-key sweeper, observed in a running process.
//
// keystore.CleanupExpired shipped with the DB-backed keystore and nothing in the
// product called it, so retired signing keys accumulated in auth.signing_keys
// forever. The unit tests in internal/keystore prove the sweep loop starts,
// stops and survives a failure; what they cannot see is whether this binary ever
// builds one. That is what these tests observe, from the outside, the way an
// operator would: the reap reaches the database and says so.

import (
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// reapRule answers the sweep's DELETE with a command tag reporting deleted rows.
//
// It has to sort ahead of signingKeysRule: rules are tried in order and that one
// matches on "FROM auth.signing_keys", which the DELETE also contains.
func reapRule(deleted int) pgRule {
	return pgRule{
		match: "DELETE FROM auth.signing_keys",
		tag:   "DELETE " + strconv.Itoa(deleted),
	}
}

// The sweep runs once at startup rather than waiting for its first tick, so a
// deployment that rolls its pods faster than the interval still reaps. A vault
// that only reaped on the ticker would look identical in every test that watches
// a short-lived process, and identical in production to one that never reaped
// at all.
func TestTheVaultReapsExpiredSigningKeysWithoutWaitingForATick(t *testing.T) {
	active := newSigningKeyRow(t, "active", time.Now())

	stub := startPGStub(t,
		adminTokenRule("$argon2id$already-provisioned"),
		reapRule(2),
		signingKeysRule(active),
	)
	addr := freeAddr(t)

	res := bootAndShutdown(t, vaultRun{env: keystoreEnv(t, stub, addr)}, addr, syscall.SIGTERM, nil)

	requireExit(t, res, 0, "keystore retention: reaped 2 retired signing keys past their expiry")
}

// A retention period below the access token TTL strands tokens on every
// rotation: the key leaves the verification set while tokens it signed are still
// inside their lifetime. Before the sweeper existed an operator could recover by
// pushing expires_at back out, because the row was still there. Reaping removes
// that recourse, so the misconfiguration has to announce itself at startup
// rather than at the next rotation.
func TestAKeyRetentionShorterThanTheAccessTokenTTLIsAnnouncedAtStartup(t *testing.T) {
	active := newSigningKeyRow(t, "active", time.Now())

	stub := startPGStub(t,
		adminTokenRule("$argon2id$already-provisioned"),
		reapRule(0),
		signingKeysRule(active),
	)
	addr := freeAddr(t)

	env := keystoreEnv(t, stub, addr)
	env["VAULT_KEY_RETENTION_PERIOD"] = "1m"
	env["VAULT_ACCESS_TOKEN_TTL"] = "15m"

	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)

	requireExit(t, res, 0,
		"WARNING: VAULT_KEY_RETENTION_PERIOD (1m0s) is shorter than the access token TTL (15m0s)")
}

// The control for the test above. A retention period that covers the token TTL
// is the supported configuration and must not be reported as a problem, or the
// warning becomes noise an operator learns to scroll past.
func TestAKeyRetentionThatCoversTheAccessTokenTTLIsNotWarnedAbout(t *testing.T) {
	active := newSigningKeyRow(t, "active", time.Now())

	stub := startPGStub(t,
		adminTokenRule("$argon2id$already-provisioned"),
		reapRule(0),
		signingKeysRule(active),
	)
	addr := freeAddr(t)

	env := keystoreEnv(t, stub, addr)
	env["VAULT_KEY_RETENTION_PERIOD"] = "1h"
	env["VAULT_ACCESS_TOKEN_TTL"] = "15m"

	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)

	requireExit(t, res, 0, "")
	if strings.Contains(res.stderr, "VAULT_KEY_RETENTION_PERIOD") {
		t.Errorf("a retention period longer than the token TTL was warned about\nstderr:\n%s", res.stderr)
	}
}

// Scheduled rotation is opt-out by value rather than by flag: a non-positive
// VAULT_KEY_ROTATION_INTERVAL disables it. That is a supported configuration —
// an operator who rotates from a pipeline does not want a second scheduler doing
// it too — but it is also what a typo produces, and the consequence is the
// defect the scheduler was added to remove: every token the install ever issues
// stays verifiable under one private key.
//
// So it has to be announced. The two directions are asserted together because
// each is the other's control: a warning that also fired on a healthy deployment
// would be noise, and a silence that also covered the disabled one would hide
// the typo.
func TestANonPositiveKeyRotationIntervalIsAnnouncedAtStartup(t *testing.T) {
	const scheduled = "keystore rotation: rotating the signing key once it is older than"
	const disabled = "WARNING: VAULT_KEY_ROTATION_INTERVAL is not positive"

	boot := func(t *testing.T, interval string) vaultResult {
		t.Helper()
		active := newSigningKeyRow(t, "active", time.Now())
		stub := startPGStub(t,
			adminTokenRule("$argon2id$already-provisioned"),
			reapRule(0),
			signingKeysRule(active),
		)
		addr := freeAddr(t)
		env := keystoreEnv(t, stub, addr)
		env["VAULT_KEY_ROTATION_INTERVAL"] = interval
		return bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)
	}

	t.Run("zero disables rotation and says so", func(t *testing.T) {
		res := boot(t, "0s")
		requireExit(t, res, 0, disabled)
		if strings.Contains(res.stderr, scheduled) {
			t.Errorf("the vault reported a rotation schedule it does not have\nstderr:\n%s", res.stderr)
		}
	})

	t.Run("a positive interval schedules rotation and does not warn", func(t *testing.T) {
		res := boot(t, "720h")
		requireExit(t, res, 0, scheduled)
		if strings.Contains(res.stderr, disabled) {
			t.Errorf("a configured rotation interval was reported as not positive\nstderr:\n%s", res.stderr)
		}
	})
}
