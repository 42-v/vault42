package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/keystore"
)

// Migration 020 grants vault_app the DELETE that keystore.CleanupExpired always
// needed and never had, and bounds it with a trigger.
//
// The bound is the interesting half. PostgreSQL has no row scope for a privilege
// and DELETE takes no column list, so the grant covers the active key, whose row
// holds the only copy of its private material, and every retired key still inside
// its retention window, whose tokens are still verifying. The trigger narrows the
// reachable set to exactly the sweep's own predicate.
//
// The controls matter as much as the finding, in the same way they do for 017: a
// trigger that froze the whole table would look like it had fixed something while
// breaking the sweep it exists to enable.
func TestSigningKeyReapReachesOnlyRowsAlreadyOutOfTheVerificationSet(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	// The reap-scope trigger's own message. A permission error or a foreign key
	// violation would be a different control and must not count as this one
	// working.
	notReapable := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "is not reapable")
	}

	t.Run("the active signing key cannot be deleted", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x61)
		defer ks.Stop()

		active, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}

		if _, err := pool.Exec(ctx, `DELETE FROM auth.signing_keys WHERE kid = $1`, active); !notReapable(err) {
			t.Errorf("deleting the active key returned %v, want the reap-scope refusal: its row is "+
				"the only copy of the private material that exists, so one DELETE ends the vault's "+
				"ability to sign", err)
		}

		if _, err := ks.CleanupExpired(ctx); err != nil {
			t.Fatalf("CleanupExpired: %v", err)
		}
		if _, kid := ks.ActiveKey(); kid != active {
			t.Errorf("the active kid is %q after a sweep, want %q: the sweep reached a row it must not", kid, active)
		}
	})

	t.Run("a retired key still inside its retention window cannot be deleted", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x62)
		defer ks.Stop()

		retired, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (replacement): %v", err)
		}

		if _, err := pool.Exec(ctx, `DELETE FROM auth.signing_keys WHERE kid = $1`, retired); !notReapable(err) {
			t.Errorf("deleting a retired key inside its window returned %v, want the reap-scope "+
				"refusal: it is still published in JWKS and tokens signed under it are still "+
				"verifying at every service polling this issuer", err)
		}
	})

	t.Run("a revoked key is refused by the revocation trigger and not by the reap guard", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x63)
		defer ks.Stop()

		leaked := revokedKID(t, ctx, ks)

		_, err := pool.Exec(ctx, `DELETE FROM auth.signing_keys WHERE kid = $1`, leaked)
		if err == nil {
			t.Fatal("a revoked row was deleted: its kid is now free for re-insert under a key an " +
				"attacker chose, which is the escalation 017 exists to prevent")
		}
		if !strings.Contains(err.Error(), "revocation is terminal") {
			t.Errorf("deleting a revoked key reported %v, want 017's terminality refusal", err)
		}
		if notReapable(err) {
			t.Error("the reap-scope trigger answered for a revoked row. Same-event triggers fire in " +
				"name order and signing_keys_reap_scope sorts first, so its WHEN clause must exclude " +
				"revoked rows or it reports the wrong reason for the refusal")
		}
	})

	// The property the whole design rests on: a row becomes reapable only after it
	// has stopped being published, never before. Both halves are asserted on the
	// same row, so the flip is visible rather than inferred.
	t.Run("a retired key becomes reapable only after it leaves JWKS", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x64)
		defer ks.Stop()

		retired, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (replacement): %v", err)
		}

		if ks.AllPublicKeys()[retired] == nil {
			t.Fatalf("retired kid %q left JWKS before its retention period elapsed; the rest of this "+
				"subtest would prove nothing", retired)
		}
		n, err := ks.CleanupExpired(ctx)
		if err != nil {
			t.Fatalf("CleanupExpired: %v", err)
		}
		if n != 0 {
			t.Errorf("the sweep reaped %d rows while the retired key was still published, want 0", n)
		}

		// Back-date the expiry rather than sleeping through it. A revoked row could
		// not be edited this way; a retired one can, and that difference is the
		// distinction the reap depends on.
		if _, err := pool.Exec(ctx,
			`UPDATE auth.signing_keys SET expires_at = NOW() - INTERVAL '1 minute' WHERE kid = $1`,
			retired); err != nil {
			t.Fatalf("back-date expiry: %v", err)
		}
		if err := ks.Refresh(ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if ks.AllPublicKeys()[retired] != nil {
			t.Fatalf("retired kid %q is still published past its expiry; Refresh's WHERE no longer "+
				"bounds the verification set", retired)
		}

		n, err = ks.CleanupExpired(ctx)
		if err != nil {
			t.Fatalf("CleanupExpired: %v", err)
		}
		if n != 1 {
			t.Errorf("the sweep reaped %d rows, want 1: the retired key is past its expiry and out of "+
				"JWKS, which is exactly the state the reap exists for", n)
		}
	})
}

// The sweep has to work under the privileges the server actually connects with,
// which the rest of the integration suite cannot see: setupPostgres strips every
// grant and runs as the container owner, so a sweep that fails with 42501 in
// production passes there.
//
// This is the test that would have caught the original defect from the privilege
// side. keystore.CleanupExpired predates any caller, and 001 grants vault_app no
// DELETE on auth.signing_keys, so the sweep could not have removed a row even
// once something called it.
func TestVaultAppHoldsTheDeletePrivilegeTheSweepNeeds(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	applyRealGrants(t, adminPool)
	truncateSigningKeys(t, adminPool)

	app := appRolePool(t, adminPool)

	// A negative retention period back-dates expires_at, so the key the second
	// rotation retires is already past its expiry and already out of JWKS.
	ks := newKeyStore(t, app, -time.Minute, 0x65)
	defer ks.Stop()

	if _, err := ks.Rotate(ctx); err != nil {
		t.Fatalf("Rotate (initial): %v", err)
	}
	active, err := ks.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	n, err := keystore.NewRetention(ks).Sweep(ctx)
	if err != nil {
		t.Fatalf("the sweep failed as vault_app, so expired signing keys accumulate in every real "+
			"deployment regardless of what calls it: %v", err)
	}
	if n != 1 {
		t.Errorf("the sweep reaped %d rows as vault_app, want 1", n)
	}

	keys, err := ks.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].KID != active {
		t.Errorf("after the sweep ListKeys = %v, want only the active kid %q", keys, active)
	}
}
