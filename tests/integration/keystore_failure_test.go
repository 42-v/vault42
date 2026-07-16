package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// keystoreFailTrigger installs a raise-exception trigger on auth.signing_keys
// and drops it when the subtest finishes. The integration container connects as
// the table owner, so DDL is permitted and isolated per test function.
func keystoreFailTrigger(t *testing.T, pool *pgxpool.Pool, ddl string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, ddl); err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DROP TRIGGER IF EXISTS keystore_fail ON auth.signing_keys`); err != nil {
			t.Fatalf("drop trigger: %v", err)
		}
	})
}

// keystoreWantError asserts err carries the wrapped branch prefix, pinning
// WHICH statement of the operation failed, not merely that something did.
func keystoreWantError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("operation reported success, want error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}
}

// TestKeyStoreWriteFailures drives Import, EnsureKey, Refresh, and ListKeys
// into their mid-transaction and row-scan error branches. Raise-exception
// triggers make individual statements of Import's transaction fail; a NULL
// algorithm row (NOT NULL dropped for the test) makes Scan fail. Every branch
// must surface an error: a keystore write that quietly failed would leave the
// operator believing a rotation happened when the old key still signs.
func TestKeyStoreWriteFailures(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION keystore_test_explode() RETURNS trigger AS $$
		BEGIN
			RAISE EXCEPTION 'keystore test trigger';
		END;
		$$ LANGUAGE plpgsql
	`); err != nil {
		t.Fatalf("create trigger function: %v", err)
	}

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}

	t.Run("Import surfaces a failed retire UPDATE", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x41)
		defer ks.Stop()

		// Statement-level BEFORE UPDATE fires even with no active row to retire.
		keystoreFailTrigger(t, pool, `
			CREATE TRIGGER keystore_fail BEFORE UPDATE ON auth.signing_keys
			FOR EACH STATEMENT EXECUTE FUNCTION keystore_test_explode()
		`)
		_, err := ks.Import(ctx, key)
		keystoreWantError(t, err, "keystore: retire active key:")
	})

	t.Run("Import surfaces a failed INSERT", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x42)
		defer ks.Stop()

		keystoreFailTrigger(t, pool, `
			CREATE TRIGGER keystore_fail BEFORE INSERT ON auth.signing_keys
			FOR EACH STATEMENT EXECUTE FUNCTION keystore_test_explode()
		`)
		_, err := ks.Import(ctx, key)
		keystoreWantError(t, err, "keystore: insert key:")
	})

	t.Run("Import surfaces a failed COMMIT", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x43)
		defer ks.Stop()

		// A deferred constraint trigger raises only at COMMIT, after the UPDATE
		// and INSERT both succeeded inside the transaction.
		keystoreFailTrigger(t, pool, `
			CREATE CONSTRAINT TRIGGER keystore_fail AFTER INSERT ON auth.signing_keys
			DEFERRABLE INITIALLY DEFERRED
			FOR EACH ROW EXECUTE FUNCTION keystore_test_explode()
		`)
		_, err := ks.Import(ctx, key)
		keystoreWantError(t, err, "keystore: commit:")

		var rows int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.signing_keys`).Scan(&rows); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if rows != 0 {
			t.Errorf("failed commit left %d rows in signing_keys, want 0", rows)
		}
	})

	t.Run("EnsureKey surfaces a failed import of the supplied key", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x44)
		defer ks.Stop()

		// SELECTs are unaffected, so the initial Refresh succeeds and finds no
		// active key; the import's retire UPDATE then explodes.
		keystoreFailTrigger(t, pool, `
			CREATE TRIGGER keystore_fail BEFORE UPDATE ON auth.signing_keys
			FOR EACH STATEMENT EXECUTE FUNCTION keystore_test_explode()
		`)
		keystoreWantError(t, ks.EnsureKey(ctx, key), "keystore: import initial key:")
		if k, _ := ks.ActiveKey(); k != nil {
			t.Error("EnsureKey published an active key despite the failed import")
		}
	})

	t.Run("EnsureKey surfaces a failed generate", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x45)
		defer ks.Stop()

		keystoreFailTrigger(t, pool, `
			CREATE TRIGGER keystore_fail BEFORE UPDATE ON auth.signing_keys
			FOR EACH STATEMENT EXECUTE FUNCTION keystore_test_explode()
		`)
		keystoreWantError(t, ks.EnsureKey(ctx, nil), "keystore: generate initial key:")
		if k, _ := ks.ActiveKey(); k != nil {
			t.Error("EnsureKey published an active key despite the failed generate")
		}
	})

	t.Run("NULL algorithm row surfaces scan errors", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x46)
		defer ks.Stop()

		// Every column is NOT NULL or scanned into a pointer, so a scan failure
		// needs the constraint relaxed. expires_at stays NULL so Refresh's WHERE
		// clause keeps the row.
		if _, err := pool.Exec(ctx, `ALTER TABLE auth.signing_keys ALTER COLUMN algorithm DROP NOT NULL`); err != nil {
			t.Fatalf("drop NOT NULL: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO auth.signing_keys (kid, private_key, public_key, algorithm, status, created_at)
			VALUES ('kid-null-alg', $1, $2, NULL, 'retired', NOW())
		`, []byte("unused"), []byte("unused")); err != nil {
			t.Fatalf("insert NULL-algorithm row: %v", err)
		}

		keystoreWantError(t, ks.Refresh(ctx), "keystore: scan row:")

		_, err := ks.ListKeys(ctx)
		keystoreWantError(t, err, "keystore: scan key info:")

		// Import itself commits fine; the trailing Refresh then meets the NULL
		// row, so the key is persisted but the error still reaches the caller.
		_, err = ks.Import(ctx, key)
		keystoreWantError(t, err, "keystore: refresh after import:")
	})
}
