package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/keystore"
)

// Migration 017 moves the terminality of a revocation from application SQL into
// the table. keystore.Import refuses to reactivate a revoked kid with a WHERE
// clause inside its upsert, which holds only for statements the Go code issues:
// vault_app holds INSERT and UPDATE on auth.signing_keys, so anything that
// reaches the database as that role puts a leaked key back into JWKS with one
// UPDATE that never runs the guard.
//
// The controls in this test matter as much as the finding. A trigger that froze
// the whole table, rather than revoked rows only, would break rotation and
// cleanup while looking like it had fixed something.
func TestSigningKeyRevocationIsTerminalInTheDatabase(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	isTerminal := func(err error) bool {
		// The trigger's own message. A CHECK violation or a permission error
		// would be a different control and must not count as this one working.
		return err != nil && strings.Contains(err.Error(), "revocation is terminal")
	}

	t.Run("a revoked row cannot be moved back out of revoked", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x51)
		defer ks.Stop()

		leaked := revokedKID(t, ctx, ks)

		for _, status := range []string{"retired", "active"} {
			_, err := pool.Exec(ctx, `
				UPDATE auth.signing_keys
				SET status = $2, retired_at = NOW(), expires_at = NULL
				WHERE kid = $1`, leaked, status)
			if !isTerminal(err) {
				t.Errorf("UPDATE to %q on a revoked row: err = %v, want the trigger to refuse it", status, err)
			}
		}

		if err := ks.Refresh(ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if ks.AllPublicKeys()[leaked] != nil {
			t.Errorf("revoked kid %q is verifying again", leaked)
		}
	})

	// Renaming the kid is the same resurrection by another route: it frees the
	// identifier, and the ciphertext in the row is genuine, so re-inserting the
	// leaked key under its original kid would decrypt and publish cleanly.
	t.Run("a revoked row cannot be renamed or edited in place", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x52)
		defer ks.Stop()

		leaked := revokedKID(t, ctx, ks)

		if _, err := pool.Exec(ctx,
			`UPDATE auth.signing_keys SET kid = 'kid-renamed' WHERE kid = $1`, leaked); !isTerminal(err) {
			t.Errorf("renaming a revoked kid: err = %v, want the trigger to refuse it", err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE auth.signing_keys SET expires_at = NULL WHERE kid = $1`, leaked); !isTerminal(err) {
			t.Errorf("editing a revoked row: err = %v, want the trigger to refuse it", err)
		}
	})

	// The row is the tombstone: while it exists, the kid is taken and cannot be
	// written afresh with the ciphertext an attacker already read out of it.
	t.Run("a revoked row cannot be deleted", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x53)
		defer ks.Stop()

		leaked := revokedKID(t, ctx, ks)

		if _, err := pool.Exec(ctx, `DELETE FROM auth.signing_keys WHERE kid = $1`, leaked); !isTerminal(err) {
			t.Errorf("deleting a revoked row: err = %v, want the trigger to refuse it", err)
		}
	})

	// Controls: everything the product does to this table still works.
	t.Run("rotation, revocation and cleanup still work (control)", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		// A negative retention period back-dates expires_at, so the row the
		// second Import retires is already eligible for cleanup.
		ks := newKeyStore(t, pool, -time.Minute, 0x54)
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
			t.Errorf("CleanupExpired = (%d, %v), want (1, nil): the retired row is untouched by the trigger", n, err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Errorf("Rotate after a revocation: %v", err)
		}
	})
}

// revokedKID rotates twice and revokes the older kid, so the store is left with
// a working active key and one revoked row to attack.
func revokedKID(t *testing.T, ctx context.Context, ks *keystore.KeyStore) string {
	t.Helper()
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
	return leaked
}
