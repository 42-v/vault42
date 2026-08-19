package attack

// Finding B3: a vault_app UPDATE can retire the live key and null its expiry in a
// single statement, planting a retired row with no expiry.
//
// 026 made the retired row terminal against the writes it could see, but its
// retire-path trigger fires only WHEN OLD.status = 'retired', so it never judges
// the move INTO 'retired' from 'active'. 001 grants vault_app UPDATE on
// auth.signing_keys, so this is within its rights:
//
//	UPDATE auth.signing_keys SET status = 'retired', expires_at = NULL WHERE status = 'active';
//
// The resulting retired, no-expiry row rides Refresh's `expires_at IS NULL` branch
// into JWKS forever, is never eligible for the reaper (which needs expires_at <
// NOW()), and 020's reap-scope trigger even refuses a manual DELETE of it. 027
// adds a CHECK that makes retired-with-no-expiry unrepresentable on every INSERT
// and UPDATE for every role, and the Refresh predicate is narrowed so only the
// active key may publish on a NULL expiry.

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestRetiredSigningKeyMustCarryExpiryAsVaultApp exercises B3 as vault_app and
// confirms 027 leaves the active key's own NULL expiry alone.
func TestRetiredSigningKeyMustCarryExpiryAsVaultApp(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	app := atkDBRolePool(t, owner, "vault_app")

	// The CHECK's own constraint name. A trigger refusal, a permission error or a
	// unique-index collision would be a different control and must not be counted
	// as this one working.
	isRetiredExpiryCheck := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "signing_keys_retired_has_expiry")
	}

	t.Run("B3: the active key cannot be retired with a null expiry", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		// One statement inside vault_app's 001 UPDATE grant that 026 never judges
		// (OLD.status = 'active'). Without 027 it plants a permanent JWKS key that
		// neither the reaper nor a manual DELETE can remove.
		_, err := app.Exec(ctx,
			`UPDATE auth.signing_keys SET status = 'retired', expires_at = NULL WHERE status = 'active'`)
		if !isRetiredExpiryCheck(err) {
			t.Fatalf("retiring the active key with a null expiry returned %v, want the "+
				"signing_keys_retired_has_expiry CHECK refusal: the row would verify forever", err)
		}
	})

	t.Run("B3: a retired row with a null expiry cannot be inserted", func(t *testing.T) {
		atkKeyTruncate(t, owner)

		key, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair: %v", err)
		}
		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		_, err = app.Exec(ctx, `
			INSERT INTO auth.signing_keys (kid, private_key, public_key, algorithm, status, created_at, expires_at)
			VALUES ($1, $2, $3, 'RS256', 'retired', NOW(), NULL)`,
			atkDBRandomID(t), []byte{0x00}, pub)
		if !isRetiredExpiryCheck(err) {
			t.Fatalf("inserting a retired row with a null expiry returned %v, want the "+
				"signing_keys_retired_has_expiry CHECK refusal", err)
		}
	})

	// ------------------------------------------------------------------------
	// Controls: 027 and the Refresh change must not narrow any legitimate state.
	// ------------------------------------------------------------------------

	t.Run("control: the active key keeps its null expiry and stays in JWKS", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStoreRetention(t, app, time.Hour)

		active, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if err := ks.Refresh(ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if ks.AllPublicKeys()[active] == nil {
			t.Errorf("active kid %q left JWKS: the constraint and the predicate must not touch the active key's null expiry", active)
		}
	})

	t.Run("control: rotation retires the old key with a concrete expiry", func(t *testing.T) {
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
}
