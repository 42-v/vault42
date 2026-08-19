package integration_test

// The identity and material columns of auth.signing_keys, under the roles the
// services connect as.
//
// 026 states that a kid its tombstone frees "can never be filled again" and 035
// states that "a rotated-out key stays retired". Neither held. Both claims were
// enforced against the writes their authors pictured -- an INSERT of a
// tombstoned kid, a status flip with the material untouched -- and both are
// reachable by an UPDATE that says something slightly different. Reproduced as
// vault_app on PostgreSQL 16.15 with every migration applied verbatim:
//
//	UPDATE auth.signing_keys SET kid='Kr-old' WHERE kid='Kr';       -- UPDATE 1
//	INSERT INTO auth.signing_keys (kid,...) VALUES ('Kr',...);      -- INSERT 0 1
//
//	DELETE FROM auth.signing_keys WHERE kid='Kreap';                -- tombstoned
//	INSERT INTO auth.signing_keys (kid,...) VALUES ('Kreap',...);   -- refused
//	UPDATE auth.signing_keys SET kid='Kreap' WHERE kid='Kn';        -- UPDATE 1
//
//	UPDATE auth.signing_keys SET status='retired', retired_at=NOW(),
//	       expires_at=NOW()+INTERVAL '1 hour' WHERE kid='Ka';       -- UPDATE 1
//	UPDATE auth.signing_keys SET status='active', private_key='\xdeadbeef',
//	       retired_at=NULL, expires_at=NULL WHERE kid='Kr';         -- UPDATE 1
//
// Renaming the active kid succeeds too, and the kid is the AEAD associated data
// its private half is wrapped under, so the row then stops opening and EnsureKey
// refuses to start: no pod boots or scales until someone puts the name back.
//
// Exactly one test in this tree renamed a kid before this one, and only on a
// revoked row (postgres_signing_key_revocation_test.go). That is the whole
// reason a green suite coexisted with all four writes above.
//
// Two controls answer these now and the tests keep them apart, because a test
// that accepted either would not notice the two swapping places. 037's trigger
// is a table invariant and holds for every role including the owner, so it is
// asserted on the owner pool. 037's privilege change holds only for the two
// application roles, so it is asserted on a real vault_app connection -- and it
// is what answers first there, before any trigger is consulted.

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

func TestSigningKeyIdentityIsNotRawWritable(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	applyRealGrants(t, adminPool)
	appPool := appRolePool(t, adminPool)

	// 037's trigger message. A permission error, a CHECK violation or a unique
	// collision would be a different control and must not be read as this one.
	kidFrozen := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "signing key kid is immutable")
	}
	// 017's message. It must still be what a revoked row returns: 037's WHEN
	// excludes revoked rows so that 017 stays the only guard speaking for them.
	revocationTerminal := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "revocation is terminal")
	}
	// 026's INSERT guard, which is the half of the tombstone that always worked.
	tombstoned := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "is tombstoned")
	}

	statusOf := func(t *testing.T, kid string) string {
		t.Helper()
		var status string
		if err := adminPool.QueryRow(ctx,
			`SELECT status FROM auth.signing_keys WHERE kid = $1`, kid).Scan(&status); err != nil {
			t.Fatalf("read back status of %q: %v", kid, err)
		}
		return status
	}

	// M-C1a. The tombstone is written by an AFTER DELETE trigger, so a kid
	// vacated by UPDATE is recorded nowhere and the INSERT guard has nothing to
	// refuse. Freezing the column is what makes DELETE the only way a kid is
	// ever freed, which is the event that records a tombstone.
	t.Run("a retired row cannot be renamed", func(t *testing.T) {
		truncateSigningKeys(t, adminPool)
		ks := newKeyStore(t, appPool, time.Hour, 0x61)
		defer ks.Stop()

		retired, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (retiring %q): %v", retired, err)
		}

		if _, err := appPool.Exec(ctx,
			`UPDATE auth.signing_keys SET kid = 'kid-freed' WHERE kid = $1`, retired); !permissionDenied(err) {
			t.Errorf("vault_app renamed a retired kid: err = %v.\n"+
				"The rename frees the identifier without leaving a tombstone, and the next INSERT "+
				"fills it with material of the writer's choosing.", err)
		}
		if _, err := adminPool.Exec(ctx,
			`UPDATE auth.signing_keys SET kid = 'kid-freed' WHERE kid = $1`, retired); !kidFrozen(err) {
			t.Errorf("renaming a retired kid as the owner: err = %v, want 037's trigger", err)
		}
		if got := statusOf(t, retired); got != "retired" {
			t.Errorf("kid %q is %q after two refused renames, want retired", retired, got)
		}
	})

	// M-C1c. Not a resurrection: the kid is the AES-GCM associated data the
	// private half is wrapped under, so moving it breaks the row's own
	// ciphertext. Refresh treats that as fatal on the active row and EnsureKey
	// will not start without a Refresh, so it is a deployment-wide boot failure
	// that stays invisible until the next rollout.
	t.Run("the active row cannot be renamed", func(t *testing.T) {
		truncateSigningKeys(t, adminPool)
		ks := newKeyStore(t, appPool, time.Hour, 0x62)
		defer ks.Stop()

		active, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}

		if _, err := appPool.Exec(ctx,
			`UPDATE auth.signing_keys SET kid = 'kid-hijacked' WHERE kid = $1`, active); !permissionDenied(err) {
			t.Errorf("vault_app renamed the active kid: err = %v.\n"+
				"The row stops decrypting, Refresh fails on the active key, and no pod boots or "+
				"scales from that moment on.", err)
		}
		if _, err := adminPool.Exec(ctx,
			`UPDATE auth.signing_keys SET kid = 'kid-hijacked' WHERE kid = $1`, active); !kidFrozen(err) {
			t.Errorf("renaming the active kid as the owner: err = %v, want 037's trigger", err)
		}

		// The proof that matters is not the error but that the key still opens.
		if err := ks.Refresh(ctx); err != nil {
			t.Fatalf("Refresh after the refused renames: %v", err)
		}
		if _, kid := ks.ActiveKey(); kid != active {
			t.Errorf("active kid is %q after the refused renames, want %q", kid, active)
		}
	})

	// M-C1b. The reaper's DELETE tombstones the kid, 026 refuses to INSERT it
	// again, and an UPDATE walked a surviving row onto it instead. The end state
	// that produced was a live signing_keys row and a tombstone naming the same
	// kid at the same time.
	t.Run("a row cannot be moved onto a tombstoned kid", func(t *testing.T) {
		truncateSigningKeys(t, adminPool)
		// Negative retention back-dates the retired row's expiry, so the sweep
		// finds it reapable without waiting.
		ks := newKeyStore(t, appPool, -time.Minute, 0x63)
		defer ks.Stop()

		reaped, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		survivor, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate (retiring %q): %v", reaped, err)
		}
		if n, err := ks.CleanupExpired(ctx); err != nil || n != 1 {
			t.Fatalf("CleanupExpired = (%d, %v), want (1, nil): the fixture needs a tombstoned kid", n, err)
		}

		// Control: the half of 026's tombstone that always worked.
		if _, err := appPool.Exec(ctx, `
			INSERT INTO auth.signing_keys (kid, private_key, public_key, algorithm, status, created_at, expires_at)
			VALUES ($1, $2, $3, 'RS256', 'retired', NOW(), NOW() + INTERVAL '1 hour')`,
			reaped, []byte("attacker"), []byte("attacker")); !tombstoned(err) {
			t.Fatalf("re-inserting a tombstoned kid: err = %v, want 026's guard", err)
		}

		if _, err := appPool.Exec(ctx,
			`UPDATE auth.signing_keys SET kid = $1 WHERE kid = $2`, reaped, survivor); !permissionDenied(err) {
			t.Errorf("vault_app moved a live row onto a tombstoned kid: err = %v.\n"+
				"026 refuses the INSERT and had no answer for the UPDATE, so the table ended up "+
				"holding a kid its own tombstone table says was retired forever.", err)
		}
		if _, err := adminPool.Exec(ctx,
			`UPDATE auth.signing_keys SET kid = $1 WHERE kid = $2`, reaped, survivor); !kidFrozen(err) {
			t.Errorf("moving a row onto a tombstoned kid as the owner: err = %v, want 037's trigger", err)
		}

		var live int
		if err := adminPool.QueryRow(ctx, `
			SELECT count(*) FROM auth.signing_keys k
			  JOIN auth.signing_key_tombstones t ON t.kid = k.kid`).Scan(&live); err != nil {
			t.Fatalf("count rows that are both live and tombstoned: %v", err)
		}
		if live != 0 {
			t.Errorf("%d kid(s) are live and tombstoned at once: 026's invariant is that a freed kid is never filled again", live)
		}
	})

	// M-C2, 035's disclosed residual. The first statement is the shape an
	// ordinary rotation writes and stays inside vault_app's lifecycle grant. The
	// second used to slip past 035's WHEN (public_key untouched, status active)
	// and past its CHECK (retired_at cleared). No trigger can refuse it: a
	// re-import and a substitution differ only in whether the ciphertext opens,
	// which the database cannot test. So the column stopped being writable.
	t.Run("a retired row cannot be reactivated under new key material", func(t *testing.T) {
		truncateSigningKeys(t, adminPool)
		ks := newKeyStore(t, appPool, time.Hour, 0x64)
		defer ks.Stop()

		retired, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		active, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate (retiring %q): %v", retired, err)
		}

		if _, err := appPool.Exec(ctx, `
			UPDATE auth.signing_keys SET status = 'retired', retired_at = NOW(),
			       expires_at = NOW() + INTERVAL '1 hour' WHERE kid = $1`, active); err != nil {
			t.Fatalf("retiring the active key is inside vault_app's lifecycle grant and must still work: %v", err)
		}

		if _, err := appPool.Exec(ctx, `
			UPDATE auth.signing_keys SET status = 'active', private_key = $2,
			       retired_at = NULL, expires_at = NULL WHERE kid = $1`,
			retired, []byte{0xde, 0xad, 0xbe, 0xef}); !permissionDenied(err) {
			t.Errorf("vault_app reactivated a retired key under its own bytes: err = %v.\n"+
				"The sole active signing key then carries material no pod can open, so Refresh "+
				"fails and the deployment cannot restart or scale.", err)
		}
		if got := statusOf(t, retired); got != "retired" {
			t.Errorf("kid %q is %q after the refused reactivation, want retired", retired, got)
		}

		var carriesAttackerBytes bool
		if err := adminPool.QueryRow(ctx,
			`SELECT private_key = $2 FROM auth.signing_keys WHERE kid = $1`,
			retired, []byte{0xde, 0xad, 0xbe, 0xef}).Scan(&carriesAttackerBytes); err != nil {
			t.Fatalf("read back private_key of %q: %v", retired, err)
		}
		if carriesAttackerBytes {
			t.Errorf("kid %q kept the written bytes even though the statement was refused", retired)
		}
	})

	// ------------------------------------------------------------------------
	// Controls: every write the product makes to this table still works, and the
	// guards that were already here still answer for the rows they own.
	// ------------------------------------------------------------------------

	t.Run("control: a revoked row is still answered by 017, not by 037", func(t *testing.T) {
		truncateSigningKeys(t, adminPool)
		ks := newKeyStore(t, adminPool, time.Hour, 0x65)
		defer ks.Stop()

		leaked, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (replacement): %v", err)
		}
		if err := ks.Revoke(ctx, leaked); err != nil {
			t.Fatalf("Revoke: %v", err)
		}

		// Same-event triggers fire in name order and signing_keys_kid_immutable
		// sorts ahead of signing_keys_revocation_terminal. Its WHEN excludes
		// revoked rows for exactly this reason, so the message a revoked rename
		// returns is 017's and the ordering never has to be relied on.
		if _, err := adminPool.Exec(ctx,
			`UPDATE auth.signing_keys SET kid = 'kid-renamed' WHERE kid = $1`, leaked); !revocationTerminal(err) {
			t.Errorf("renaming a revoked kid: err = %v, want 017's message: 037 must not take over "+
				"the rows 017 exists to speak for", err)
		}
	})

	t.Run("control: rotation, revocation, re-import and the reap still work as vault_app", func(t *testing.T) {
		truncateSigningKeys(t, adminPool)
		ks := newKeyStore(t, appPool, -time.Minute, 0x66)
		defer ks.Stop()

		first, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		second, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate (retiring %q): %v", first, err)
		}
		if err := ks.Revoke(ctx, second); err != nil {
			t.Fatalf("Revoke of an active key: %v", err)
		}
		if n, err := ks.CleanupExpired(ctx); err != nil || n != 1 {
			t.Errorf("CleanupExpired = (%d, %v), want (1, nil)", n, err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Errorf("Rotate after a revocation: %v", err)
		}
	})

	// 026 left the genuine re-import of a rotated-out key working on purpose and
	// 035 kept it working. 037 must not quietly take it away: this is the path a
	// deployment uses when its configured signing key is already in the table
	// retired, and EnsureKey reaches it on any boot that finds no active key.
	t.Run("control: Import still reactivates a retired key", func(t *testing.T) {
		truncateSigningKeys(t, adminPool)
		ks := newKeyStore(t, appPool, time.Hour, 0x67)
		defer ks.Stop()

		key, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair: %v", err)
		}
		kid, err := ks.Import(ctx, key)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (retiring %q): %v", kid, err)
		}
		again, err := ks.Import(ctx, key)
		if err != nil {
			t.Fatalf("re-importing a retired key: %v.\n"+
				"026 protected this path deliberately and 037 must not close it: a deployment whose "+
				"configured key is already retired can no longer boot without it.", err)
		}
		if again != kid {
			t.Errorf("re-import filed the key under %q, want %q", again, kid)
		}
		if got := statusOf(t, kid); got != "active" {
			t.Errorf("re-imported kid %q is %q, want active", kid, got)
		}
	})

	// 001 gave vault_admin the same table-level UPDATE here, so both bypasses
	// were open to the admin gateway's role too and 037 takes the privilege off
	// both. Nothing else in this tree exercises key rotation as vault_admin --
	// the admin-key tests all run on the owner pool with the grants stripped --
	// so a missing EXECUTE on the new function would have surfaced as a broken
	// POST /admin/keys/rotate in a deployment and nowhere before it.
	t.Run("control: vault_admin still rotates, and still cannot write material raw", func(t *testing.T) {
		truncateSigningKeys(t, adminPool)
		gatewayPool := adminRolePool(t, adminPool)
		ks := newKeyStore(t, gatewayPool, time.Hour, 0x68)
		defer ks.Stop()

		first, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("vault_admin cannot rotate a signing key, so the admin gateway's rotate "+
				"endpoint is dead in production: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("vault_admin cannot rotate a second time (retiring %q): %v", first, err)
		}
		if err := ks.Revoke(ctx, first); err != nil {
			t.Fatalf("vault_admin cannot revoke a signing key: %v", err)
		}

		if _, err := gatewayPool.Exec(ctx,
			`UPDATE auth.signing_keys SET private_key = $1 WHERE status = 'active'`,
			[]byte{0xde, 0xad}); !permissionDenied(err) {
			t.Errorf("vault_admin wrote key material by raw UPDATE: err = %v", err)
		}
		if _, err := gatewayPool.Exec(ctx,
			`UPDATE auth.signing_keys SET kid = 'kid-renamed' WHERE status = 'active'`); !permissionDenied(err) {
			t.Errorf("vault_admin renamed a kid: err = %v", err)
		}
	})

	// 037 teaches the database one fact about key material that it can actually
	// check: a kid is the digest of the public key it is filed under. That fact
	// is duplicated from internal/crypto/jwt.go, so it is pinned against the Go
	// derivation rather than against a literal -- changing one without the other
	// would refuse every import in production and this is what says so.
	t.Run("control: the kid the function requires is the kid internal/crypto derives", func(t *testing.T) {
		truncateSigningKeys(t, adminPool)

		key, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair: %v", err)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		kid := vaultcrypto.KIDFromPublicKey(&key.PublicKey)

		var wrote bool
		if err := appPool.QueryRow(ctx, `SELECT auth.import_signing_key($1, $2, $3, $4, $5)`,
			kid, []byte("ciphertext"), pubDER, "RS256", time.Now()).Scan(&wrote); err != nil {
			t.Fatalf("auth.import_signing_key refused the kid KIDFromPublicKey derived: %v.\n"+
				"The SQL derivation and the Go one have diverged, and no key can be imported.", err)
		}
		if !wrote {
			t.Fatalf("auth.import_signing_key wrote nothing for a fresh kid")
		}

		err = appPool.QueryRow(ctx, `SELECT auth.import_signing_key($1, $2, $3, $4, $5)`,
			"deadbeef-deadbeef", []byte("ciphertext"), pubDER, "RS256", time.Now()).Scan(&wrote)
		if err == nil || !strings.Contains(err.Error(), "is not the digest of the public key") {
			t.Errorf("filing material under a kid that is not its digest: err = %v, want the function to refuse it", err)
		}
	})
}
