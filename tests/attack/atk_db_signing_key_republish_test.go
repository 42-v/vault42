package attack

// Finding B2: SQL running as vault_app can bring a rotated-out signing key back
// into the verification set, and can recycle a reaped kid.
//
// 017 makes a REVOKED row terminal and 020 grants vault_app the reaper's DELETE
// bounded to retired, expired rows. Neither speaks for a RETIRED row that is
// merely being edited in place, and 001 grants vault_app SELECT, INSERT, UPDATE
// (and 020, DELETE) on auth.signing_keys. So two escalations survive:
//
//   * B2a, republish by UPDATE. A retired row's private_key is genuine vault
//     ciphertext and its public_key matches, so Refresh's "publish only what
//     decrypts and matches" guard admits it. 017 fires only on OLD.status =
//     'revoked'. That leaves `SET expires_at = NULL` (never expire, so a key that
//     had left JWKS is dragged back in) and `SET status = 'active'` (hand the
//     signer a kid operators believe is dead) open to vault_app.
//
//   * B2b, reap-then-reinsert. 020's DELETE frees the kid, and unlike a revoked
//     row a reaped one leaves no tombstone, so the kid can be re-INSERTed under
//     material of the attacker's choosing: 017's resurrection reached one DELETE
//     earlier.
//
// Migration 026 closes both: a retire-path trigger that refuses clearing or
// extending a retired row's expiry and refuses reactivation without new key
// material, and a persistent kid tombstone that refuses re-inserting any kid that
// was ever deleted. These tests run every hostile write as the real vault_app
// role with the grants the migrations actually make.

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/keystore"
)

// atkKeyStoreRetention builds a KeyStore over pool with the suite's master key
// and a caller-chosen retention period. A negative period back-dates a retired
// key's expires_at, which is how these tests reach the "retired and past expiry"
// state without sleeping.
func atkKeyStoreRetention(t *testing.T, pool *pgxpool.Pool, retention time.Duration) *keystore.KeyStore {
	t.Helper()
	master := make([]byte, 32)
	for i := range master {
		master[i] = 0x5a
	}
	ks, err := keystore.New(pool, master, retention)
	if err != nil {
		t.Fatalf("keystore.New: %v", err)
	}
	t.Cleanup(ks.Stop)
	return ks
}

// TestSigningKeyRepublishAndReapReinsertAsVaultApp exercises B2a and B2b as
// vault_app, and confirms the legitimate lifecycle writes 026 must not break.
func TestSigningKeyRepublishAndReapReinsertAsVaultApp(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	app := atkDBRolePool(t, owner, "vault_app")

	// The retire-path trigger's own message. A CHECK violation, a unique-index
	// collision or a permission error would be a different control and must not
	// be mistaken for this one working.
	isRetirePath := func(err error) bool {
		return err != nil && (strings.Contains(err.Error(), "cannot return to active without new key material") ||
			strings.Contains(err.Error(), "cannot be reactivated under different key material") ||
			strings.Contains(err.Error(), "its expiry cannot be cleared or extended"))
	}
	isTombstoned := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "is tombstoned")
	}
	// 035's CHECK, matched by constraint name so a trigger refusal is never read
	// as the constraint holding. The two guard the same transition from opposite
	// sides and only the constraint survives with row triggers suspended.
	isRetirementStamp := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "signing_keys_active_is_not_retired")
	}

	t.Run("B2a: expires_at of a retired key cannot be cleared to republish it", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		// Negative retention back-dates the retired key's expiry, so after the
		// second rotation the first kid is retired AND already out of JWKS.
		ks := atkKeyStoreRetention(t, app, -time.Minute)

		retired, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (replacement): %v", err)
		}
		if err := ks.Refresh(ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if ks.AllPublicKeys()[retired] != nil {
			t.Fatalf("retired kid %q is still in JWKS; the fixture cannot demonstrate a republish", retired)
		}

		// Clearing expires_at makes Refresh's WHERE (expires_at IS NULL OR ...)
		// publish this key forever.
		_, err = app.Exec(ctx, `UPDATE auth.signing_keys SET expires_at = NULL WHERE kid = $1`, retired)
		if !isRetirePath(err) {
			t.Fatalf("clearing expires_at on a retired row returned %v, want the retire-path refusal: "+
				"a rotated-out key would be back in JWKS within one refresh interval", err)
		}

		if err := ks.Refresh(ctx); err != nil {
			t.Fatalf("Refresh after refused clear: %v", err)
		}
		if ks.AllPublicKeys()[retired] != nil {
			t.Errorf("retired kid %q is verifying again after the clear", retired)
		}
	})

	t.Run("B2a: expires_at of a retired key cannot be extended", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		retired, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (replacement): %v", err)
		}

		_, err = app.Exec(ctx,
			`UPDATE auth.signing_keys SET expires_at = NOW() + INTERVAL '100 years' WHERE kid = $1`, retired)
		if !isRetirePath(err) {
			t.Errorf("extending expires_at on a retired row returned %v, want the retire-path refusal", err)
		}
	})

	t.Run("B2a: a retired key cannot be flipped back to active with no new material", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		kid, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		// Retire the active key from under vault_app (OLD.status = 'active', which
		// no guard touches), leaving the row retired and no active key, so the
		// reactivation below is not merely blocked by the unique active index.
		if _, err := app.Exec(ctx,
			`UPDATE auth.signing_keys SET status = 'retired', retired_at = NOW(), expires_at = NOW() + INTERVAL '1 hour' WHERE kid = $1`,
			kid); err != nil {
			t.Fatalf("retire the active key: %v", err)
		}

		// A bare status flip: private_key is untouched, so this is a resurrection
		// of the vault's own rotated-out material, not a re-import.
		_, err = app.Exec(ctx,
			`UPDATE auth.signing_keys SET status = 'active', expires_at = NULL WHERE kid = $1`, kid)
		if !isRetirePath(err) {
			t.Fatalf("flipping a retired row to active returned %v, want the retire-path refusal: the "+
				"signer would resume issuing under a kid operators retired", err)
		}
	})

	t.Run("B2b: a reaped kid cannot be re-inserted", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, -time.Minute)

		reaped, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (replacement): %v", err)
		}

		// The reaper's own DELETE: the row is retired and past its expiry, which
		// 020 permits. This must keep working; it is the tombstone's source.
		if _, err := app.Exec(ctx, `DELETE FROM auth.signing_keys WHERE kid = $1`, reaped); err != nil {
			t.Fatalf("the reaper's legitimate DELETE was refused: %v", err)
		}

		attacker, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair: %v", err)
		}
		attackerPub, err := x509.MarshalPKIXPublicKey(&attacker.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}

		// Re-inserting the freed kid is what a persistent tombstone must refuse.
		_, err = app.Exec(ctx, `
			INSERT INTO auth.signing_keys (kid, private_key, public_key, algorithm, status, created_at, expires_at)
			VALUES ($1, $2, $3, 'RS256', 'retired', NOW(), NULL)`,
			reaped, []byte{0x00}, attackerPub)
		if !isTombstoned(err) {
			t.Errorf("re-inserting the reaped kid %q returned %v, want the tombstone refusal: the "+
				"identifier 017 relies on can otherwise be recycled one DELETE after a reap", reaped, err)
		}
	})

	// ------------------------------------------------------------------------
	// B2c: 026's reactivation guard is selected by the attacker.
	//
	// Its WHEN clause fires on NEW.status = 'active' AND NEW.private_key =
	// OLD.private_key. 026 documents the exemption as the way keystore.Import's
	// genuine re-import gets through, since Import always writes freshly
	// encrypted material. But the exemption is chosen by whoever writes the
	// UPDATE: an attacker who also sets private_key steps straight out of the
	// condition, and the guard whose stated purpose is "a rotated-out key stays
	// retired" never runs. Reproduced on PostgreSQL 16.15 with every migration
	// applied verbatim.
	//
	// atkKeyRetireActive puts the sole key into the retired state the way
	// vault_app can today: OLD.status = 'active' is judged by no guard, and 027
	// requires the retired row to carry an expiry.
	// ------------------------------------------------------------------------

	atkKeyRetireActive := func(t *testing.T, kid string) {
		t.Helper()
		if _, err := app.Exec(ctx,
			`UPDATE auth.signing_keys SET status = 'retired', retired_at = NOW(),
			        expires_at = NOW() + INTERVAL '1 hour' WHERE kid = $1`, kid); err != nil {
			t.Fatalf("retire the active key: %v", err)
		}
	}

	t.Run("B2c: a retired key cannot be reactivated under different key material", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		kid, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		atkKeyRetireActive(t, kid)

		attacker, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair: %v", err)
		}
		attackerPub, err := x509.MarshalPKIXPublicKey(&attacker.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}

		// retired_at is cleared in the same statement so this subtest is judged by
		// the retire-path guard alone: the constraint below would otherwise mask
		// whether the trigger sees the write at all.
		//
		// kid is the first 16 hex of SHA-256 over the public key's DER, so a row's
		// public_key can never legitimately change under a fixed kid. A re-import
		// of the same key supplies the same bytes; only an attacker supplies
		// different ones.
		// 037 leaves vault_app no UPDATE on private_key or public_key, so this
		// statement is refused for want of a privilege before any trigger runs.
		// Both controls are asserted: the privilege is what answers for the
		// role the services connect as, and the trigger is what answers for every
		// other role, which is why the same write is then made as the owner.
		_, err = app.Exec(ctx, `
			UPDATE auth.signing_keys
			SET status = 'active', private_key = $2, public_key = $3, retired_at = NULL
			WHERE kid = $1`, kid, []byte{0x99}, attackerPub)
		if !atkKeyPermissionDenied(err) {
			t.Fatalf("vault_app wrote a retired row's key material: err = %v, want 037's privilege refusal", err)
		}
		_, err = owner.Exec(ctx, `
			UPDATE auth.signing_keys
			SET status = 'active', private_key = $2, public_key = $3, retired_at = NULL
			WHERE kid = $1`, kid, []byte{0x99}, attackerPub)
		if !isRetirePath(err) {
			t.Fatalf("reactivating a retired row under new material returned %v, want the retire-path "+
				"refusal: writing private_key is all it took to step outside 026's WHEN clause", err)
		}

		var status string
		if err := owner.QueryRow(ctx, `SELECT status FROM auth.signing_keys WHERE kid = $1`, kid).Scan(&status); err != nil {
			t.Fatalf("read back status: %v", err)
		}
		if status != "retired" {
			t.Errorf("kid %q is %q after a refused reactivation, want retired", kid, status)
		}
	})

	t.Run("B2c: a reactivation cannot leave the retirement stamp behind", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		kid, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		atkKeyRetireActive(t, kid)

		// The narrower shape: only private_key is rewritten, so byte-for-byte this
		// is what a genuine re-import looks like to a trigger comparing OLD and
		// NEW. What it is not is a row that stopped being retired — Import clears
		// retired_at, an attacker rewriting material in place does not.
		//
		// 037 answers this for vault_app with a privilege error; the CHECK is
		// what answers for every other role, and it is the only one of the two
		// that survives with row triggers suspended, so it is still exercised on
		// the owner pool below.
		_, err = app.Exec(ctx,
			`UPDATE auth.signing_keys SET status = 'active', private_key = $2 WHERE kid = $1`,
			kid, []byte{0x77})
		if !atkKeyPermissionDenied(err) {
			t.Fatalf("vault_app rewrote a retired row's private_key: err = %v, want 037's privilege refusal", err)
		}
		_, err = owner.Exec(ctx,
			`UPDATE auth.signing_keys SET status = 'active', private_key = $2 WHERE kid = $1`,
			kid, []byte{0x77})
		if !isRetirementStamp(err) {
			t.Fatalf("promoting a retired row while it still carries retired_at returned %v, want the "+
				"signing_keys_active_is_not_retired violation", err)
		}
	})

	// The residual 035 disclosed and 037 narrows rather than closes. With the
	// retirement stamp cleared in the same statement, a rewrite of private_key
	// under an unchanged public_key is byte-for-byte a genuine re-import, and the
	// database cannot open a ciphertext to tell them apart. vault_app can no
	// longer express it -- that is the subtest above -- but the owner can, and
	// nothing in the schema refuses it. Pinned here so the limit is a recorded
	// fact rather than an assumption, and so that a later change which does close
	// it fails this test loudly instead of passing unnoticed.
	t.Run("B2c: the owner can still rewrite material on a reactivation (disclosed residual)", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		kid, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		atkKeyRetireActive(t, kid)

		if _, err := owner.Exec(ctx, `
			UPDATE auth.signing_keys SET status = 'active', private_key = $2,
			       retired_at = NULL, expires_at = NULL WHERE kid = $1`,
			kid, []byte{0x77}); err != nil {
			t.Fatalf("the residual has been closed for the owner too, which is better than this test "+
				"expects: err = %v. Update the finding rather than the assertion.", err)
		}

		// What holds is the control that always held: the row does not publish,
		// because opening it needs the master key.
		if err := ks.Refresh(ctx); err == nil {
			t.Errorf("Refresh accepted an active row whose ciphertext cannot be opened")
		}
	})

	t.Run("B2c: the retirement stamp holds with row triggers suspended", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		kid, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		atkKeyRetireActive(t, kid)

		// session_replication_role = replica suspends row triggers, and 016, 017,
		// 020, 023, 024 and 026 all name it as a limit their triggers cannot
		// answer. It is superuser-only, so this runs on the owner pool: the point
		// is not that vault_app can reach it but that the invariant must not
		// depend on a mechanism with an off switch. One connection, because the
		// setting is per-session.
		conn, err := owner.Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		defer conn.Release()
		defer func() { _, _ = conn.Exec(ctx, `RESET session_replication_role`) }()

		if _, err := conn.Exec(ctx, `SET session_replication_role = 'replica'`); err != nil {
			t.Fatalf("suspend row triggers: %v", err)
		}

		// Proof the triggers really are inert: extending a retired key's expiry is
		// refused by 026 and by nothing else, and here it goes through.
		if _, err := conn.Exec(ctx,
			`UPDATE auth.signing_keys SET expires_at = NOW() + INTERVAL '100 years' WHERE kid = $1`,
			kid); err != nil {
			t.Fatalf("row triggers are still firing, so this subtest proves nothing about the "+
				"constraint: %v", err)
		}

		_, err = conn.Exec(ctx,
			`UPDATE auth.signing_keys SET status = 'active', private_key = $2 WHERE kid = $1`,
			kid, []byte{0x55})
		if !isRetirementStamp(err) {
			t.Fatalf("with row triggers suspended, promoting a retired row returned %v: terminality "+
				"is being asserted only by a mechanism that has an off switch", err)
		}
	})

	// ------------------------------------------------------------------------
	// Controls: every legitimate lifecycle write still works after 026.
	// ------------------------------------------------------------------------

	t.Run("control: rotation still retires and inserts", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		first, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		second, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate (retiring %q): %v", first, err)
		}
		pubs := ks.AllPublicKeys()
		if pubs[first] == nil || pubs[second] == nil {
			t.Errorf("after two rotations JWKS holds %d keys, want the retired and the active one", len(pubs))
		}
	})

	t.Run("control: the reaper still deletes a retired, expired key", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, -time.Minute)

		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (initial): %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (replacement): %v", err)
		}
		n, err := ks.CleanupExpired(ctx)
		if err != nil {
			t.Fatalf("CleanupExpired was refused for vault_app: %v", err)
		}
		if n != 1 {
			t.Errorf("the sweep reaped %d rows, want 1: the retired, expired key is exactly its target", n)
		}
	})

	t.Run("control: an early expiry (shrink) on a retired key is allowed", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		retired, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (replacement): %v", err)
		}
		// Back-dating the expiry earlier is the reap test's own move and must stay
		// open; only clearing or extending is refused.
		if _, err := app.Exec(ctx,
			`UPDATE auth.signing_keys SET expires_at = NOW() - INTERVAL '1 minute' WHERE kid = $1`, retired); err != nil {
			t.Errorf("back-dating a retired key's expiry was refused: %v", err)
		}
	})

	t.Run("control: Revoke of a retired key still works", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		retired, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (replacement): %v", err)
		}
		// retired -> revoked must pass the retire-path guard untouched.
		if err := ks.Revoke(ctx, retired); err != nil {
			t.Errorf("Revoke of a retired key was refused: %v", err)
		}
	})

	t.Run("control: re-import of a retired key with fresh material re-activates it", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		key, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair: %v", err)
		}
		imported, err := ks.Import(ctx, key)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil { // retires `imported`
			t.Fatalf("Rotate (retiring the imported key): %v", err)
		}
		// Re-importing the same key lands on the retired row and reactivates it
		// with a freshly encrypted private_key: retired -> active WITH new
		// material, which the guard must allow.
		again, err := ks.Import(ctx, key)
		if err != nil {
			t.Fatalf("re-import of a retired key was refused: %v", err)
		}
		if again != imported {
			t.Fatalf("re-import produced kid %q, want the original %q", again, imported)
		}
		if _, kid := ks.ActiveKey(); kid != imported {
			t.Errorf("after re-import the active kid is %q, want %q", kid, imported)
		}
	})
}
