package attack

// Finding: SQL running as vault_app can publish a verification key of its own
// choosing, and can bring a revoked key back.
//
// Migration 001 line 354 grants vault_app SELECT, INSERT and UPDATE on
// auth.signing_keys. KeyStore.Refresh loads every row that is not revoked and
// not expired and, before the fix these tests pin, copied each row's public_key
// straight into the published set; the private_key column was decrypted only
// when status was 'active'. A row the process could not open was published as a
// verification key anyway.
//
//   * Attack A, forged INSERT. Write a row with status 'retired', a public key
//     the attacker holds the private half of, expires_at NULL (never expires)
//     and junk in private_key, which nothing would ever read. Within one
//     VAULT_KEY_REFRESH_INTERVAL that key is in GET /.well-known/jwks.json and
//     in the map middleware.AuthDynamic verifies against, so a token the
//     attacker signs for any subject validates, here and in every service that
//     polls this issuer. No master key and no vault private key are needed.
//
//   * Attack A', public key swapped by UPDATE. Same outcome without inserting a
//     row: overwrite public_key on a genuine row. "Must decrypt to be published"
//     alone does not catch this one, because the private_key column is still the
//     vault's own ciphertext and still decrypts under the master key. Only
//     checking the published public key against the key that decrypted does.
//
//   * Attack B, un-revoking a leaked key. A kid is revoked because its private
//     material leaked. The only thing that kept it revoked was the
//     WHERE signing_keys.status != 'revoked' guard inside Import's upsert, which
//     is application SQL a raw UPDATE never runs.
//
// Attack B needs a database-side fix rather than the one that closes A: the row
// it resurrects is a genuine vault row, so its private_key decrypts and a
// "publish only what decrypts" rule waves it through.

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/keystore"
)

const (
	atkKeyIssuer   = "https://vault42.test"
	atkKeyAudience = "https://beon3.test"
)

// atkKeyStore builds a KeyStore over the given pool with its own master key
// copy, since Stop zeroes the slice in place.
func atkKeyStore(t *testing.T, pool *pgxpool.Pool) *keystore.KeyStore {
	t.Helper()
	master := make([]byte, 32)
	for i := range master {
		master[i] = 0x5a
	}
	ks, err := keystore.New(pool, master, time.Hour)
	if err != nil {
		t.Fatalf("keystore.New: %v", err)
	}
	t.Cleanup(ks.Stop)
	return ks
}

// atkKeyTruncate clears the table between subtests. vault_app holds no TRUNCATE
// privilege, so this runs as the owner.
func atkKeyTruncate(t *testing.T, owner *pgxpool.Pool) {
	t.Helper()
	if _, err := owner.Exec(context.Background(), `TRUNCATE auth.signing_keys`); err != nil {
		t.Fatalf("truncate signing_keys: %v", err)
	}
}

// atkKeyForgeToken mints an RS256 token for victim under the attacker's key,
// exactly as a relying party would receive it.
func atkKeyForgeToken(t *testing.T, key *rsa.PrivateKey, kid, victim string) string {
	t.Helper()
	tok, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   victim,
			Issuer:    atkKeyIssuer,
			Audience:  vjwt.ClaimStrings{atkKeyAudience},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}
	return tok
}

// atkKeyValidates reports whether the published key set accepts the token. The
// key lookup is the one middleware.AuthDynamic performs.
func atkKeyValidates(tok string, pubs map[string]*rsa.PublicKey) bool {
	_, err := vaultcrypto.ParseAndValidate(tok, func(t *vjwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, ok := pubs[kid]
		if !ok {
			return nil, vjwt.ErrTokenSignatureInvalid
		}
		return key, nil
	}, atkKeyIssuer, atkKeyAudience)
	return err == nil
}

// TestSigningKeyInjectionAsVaultApp runs the three hostile writes as the real
// vault_app role, with the grants migration 001 actually makes, against a
// KeyStore holding the real master key. Nothing the attacker does here needs
// that master key or any vault private key.
func TestSigningKeyInjectionAsVaultApp(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	// The role the vault process runs as. Every write below goes through it, so
	// a write that fails on privilege alone would show up as a fatal here.
	app := atkDBRolePool(t, owner, "vault_app")

	t.Run("forged INSERT is not published as a verification key", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStore(t, app)
		if err := ks.EnsureKey(ctx, nil); err != nil {
			t.Fatalf("EnsureKey: %v", err)
		}
		_, genuineKID := ks.ActiveKey()

		attacker, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair: %v", err)
		}
		attackerKID := vaultcrypto.KIDFromPublicKey(&attacker.PublicKey)
		attackerPub, err := x509.MarshalPKIXPublicKey(&attacker.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}

		// status 'retired' so nothing competes with the active row, expires_at
		// NULL so Refresh's WHERE never drops it, private_key junk because until
		// the fix nothing read it.
		if _, err := app.Exec(ctx, `
			INSERT INTO auth.signing_keys (kid, private_key, public_key, algorithm, status, created_at, expires_at)
			VALUES ($1, $2, $3, 'RS256', 'retired', NOW(), NULL)`,
			attackerKID, []byte{0x00}, attackerPub); err != nil {
			t.Fatalf("the premise of this test is that vault_app can write this row: %v", err)
		}

		if err := ks.Refresh(ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}

		pubs := ks.AllPublicKeys()
		// The vault's own key must survive. A fix that empties JWKS instead of
		// rejecting the one bad row trades forgery for a total outage.
		if pubs[genuineKID] == nil {
			t.Fatalf("the vault's own active kid %q vanished from JWKS", genuineKID)
		}
		if pubs[attackerKID] != nil {
			t.Errorf("kid %q was inserted by vault_app and cannot be decrypted by this vault, yet it is published as a verification key", attackerKID)
		}
		if atkKeyValidates(atkKeyForgeToken(t, attacker, attackerKID, "victim-user-id"), pubs) {
			t.Errorf("a token signed by the attacker's own key validates against the published key set: any subject can be impersonated")
		}
	})

	t.Run("public key swapped by UPDATE is not published", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStore(t, app)

		// Two rotations leave a retired row whose private_key is genuine vault
		// ciphertext. Only its public_key changes below, so the row still
		// decrypts under the master key.
		victimKID, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (replacement): %v", err)
		}
		genuinePub := ks.AllPublicKeys()[victimKID]
		if genuinePub == nil {
			t.Fatalf("retired kid %q is not in JWKS before the swap: the fixture is broken", victimKID)
		}

		attacker, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair: %v", err)
		}
		attackerPub, err := x509.MarshalPKIXPublicKey(&attacker.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		if _, err := app.Exec(ctx,
			`UPDATE auth.signing_keys SET public_key = $1 WHERE kid = $2`,
			attackerPub, victimKID); err != nil {
			t.Fatalf("the premise of this test is that vault_app can write this column: %v", err)
		}

		if err := ks.Refresh(ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		pubs := ks.AllPublicKeys()
		if got := pubs[victimKID]; got != nil && got.Equal(&attacker.PublicKey) {
			t.Errorf("kid %q now publishes the attacker's public key: its private_key column still decrypts, so a decrypt-only check waves this through", victimKID)
		}
		if atkKeyValidates(atkKeyForgeToken(t, attacker, victimKID, "victim-user-id"), pubs) {
			t.Errorf("a token signed by the attacker's own key validates under kid %q", victimKID)
		}
	})

	t.Run("revocation cannot be undone by UPDATE", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStore(t, app)

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

		// Import's guard lives in application SQL. This statement never runs it.
		tag, err := app.Exec(ctx, `
			UPDATE auth.signing_keys
			SET status = 'retired', retired_at = NOW(), expires_at = NULL
			WHERE kid = $1 AND status = 'revoked'`, leaked)
		if err != nil {
			if !strings.Contains(err.Error(), "revocation is terminal") {
				t.Fatalf("the un-revoke failed for an unrelated reason: %v", err)
			}
			return
		}

		if tag.RowsAffected() == 0 {
			t.Fatalf("the UPDATE matched no row: the fixture is broken, not the control")
		}
		if err := ks.Refresh(ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if ks.AllPublicKeys()[leaked] != nil {
			t.Errorf("revoked kid %q is verifying again after a plain UPDATE: revocation is not terminal", leaked)
		}
		t.Errorf("vault_app moved kid %q out of 'revoked' with a plain UPDATE; the only guard is the WHERE clause inside keystore.Import, which raw SQL never executes", leaked)
	})

	// Control: the tombstone that keeps a revoked kid from being written afresh
	// only holds while the row cannot be deleted. 001 grants no DELETE here
	// ("no DELETE -- revoke only"), and this pins that.
	t.Run("vault_app cannot delete a revoked row (control)", func(t *testing.T) {
		atkKeyTruncate(t, owner)
		ks := atkKeyStore(t, app)

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

		if _, err := app.Exec(ctx, `DELETE FROM auth.signing_keys WHERE kid = $1`, leaked); err == nil {
			t.Errorf("vault_app deleted a revoked row: the leaked kid can be re-inserted with the ciphertext it already read")
		}
	})
}
