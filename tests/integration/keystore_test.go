package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/keystore"
)

// masterKey returns a fresh 32-byte AES-256 master key. Each KeyStore gets its
// own copy: Stop() zeroes the slice in place, so a shared array would silently
// break every other store in the test.
func masterKey(fill byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = fill
	}
	return k
}

// newKeyStore builds a KeyStore over the integration Postgres pool.
func newKeyStore(t *testing.T, pool *pgxpool.Pool, retention time.Duration, fill byte) *keystore.KeyStore {
	t.Helper()
	ks, err := keystore.New(pool, masterKey(fill), retention)
	if err != nil {
		t.Fatalf("keystore.New: %v", err)
	}
	return ks
}

// TestKeyStoreLifecycle walks a signing key through the whole DB-backed
// lifecycle: bootstrap, rotate, revoke, list, and expiry cleanup.
func TestKeyStoreLifecycle(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("EnsureKey generates when the table is empty", func(t *testing.T) {
		ks := newKeyStore(t, pool, time.Hour, 0x01)
		defer ks.Stop()

		if err := ks.EnsureKey(ctx, nil); err != nil {
			t.Fatalf("EnsureKey: %v", err)
		}
		key, kid := ks.ActiveKey()
		if key == nil || kid == "" {
			t.Fatalf("EnsureKey left no active key (key=%v kid=%q)", key, kid)
		}
		if got := ks.AllPublicKeys(); len(got) != 1 || got[kid] == nil {
			t.Fatalf("AllPublicKeys = %v, want exactly the active kid %q", got, kid)
		}

		// EnsureKey is idempotent: a second call must not rotate.
		if err := ks.EnsureKey(ctx, nil); err != nil {
			t.Fatalf("EnsureKey (second call): %v", err)
		}
		if _, kid2 := ks.ActiveKey(); kid2 != kid {
			t.Errorf("EnsureKey rotated an existing key: kid %q -> %q", kid, kid2)
		}
	})

	t.Run("Rotate retires the old key but keeps it in JWKS", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x02)
		defer ks.Stop()

		oldKID, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate (initial): %v", err)
		}
		newKID, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if oldKID == newKID {
			t.Fatalf("Rotate reused kid %q", newKID)
		}

		if _, kid := ks.ActiveKey(); kid != newKID {
			t.Errorf("ActiveKey = %q, want the freshly rotated %q", kid, newKID)
		}
		// The retired key must stay published so tokens it signed still verify
		// until the retention period lapses.
		pubs := ks.AllPublicKeys()
		if pubs[oldKID] == nil {
			t.Error("retired key dropped from JWKS before its retention period elapsed")
		}
		if pubs[newKID] == nil {
			t.Error("active key missing from JWKS")
		}

		keys, err := ks.ListKeys(ctx)
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		status := map[string]string{}
		for _, k := range keys {
			status[k.KID] = k.Status
		}
		if status[newKID] != "active" || status[oldKID] != "retired" {
			t.Errorf("ListKeys status = %v, want %q active and %q retired", status, newKID, oldKID)
		}
	})

	t.Run("Revoke removes the key from JWKS", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x03)
		defer ks.Stop()

		doomed, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (replacement): %v", err)
		}
		if err := ks.Revoke(ctx, doomed); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if pubs := ks.AllPublicKeys(); pubs[doomed] != nil {
			t.Error("revoked key still served from JWKS")
		}
	})

	t.Run("Revoke reports unknown and already-revoked kids", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x04)
		defer ks.Stop()

		if err := ks.Revoke(ctx, "kid-that-does-not-exist"); err == nil {
			t.Error("Revoke(unknown kid) = nil, want error")
		}

		kid, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if err := ks.Revoke(ctx, kid); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if err := ks.Revoke(ctx, kid); err == nil {
			t.Error("Revoke(already revoked) = nil, want error")
		}
	})

	t.Run("CleanupExpired deletes only lapsed retired keys", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		// A negative retention period back-dates expires_at, so the key the next
		// Import retires is already past its expiry.
		ks := newKeyStore(t, pool, -time.Minute, 0x05)
		defer ks.Stop()

		if _, err := ks.Rotate(ctx); err != nil {
			t.Fatalf("Rotate (initial): %v", err)
		}
		activeKID, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}

		n, err := ks.CleanupExpired(ctx)
		if err != nil {
			t.Fatalf("CleanupExpired: %v", err)
		}
		if n != 1 {
			t.Errorf("CleanupExpired deleted %d keys, want 1", n)
		}

		keys, err := ks.ListKeys(ctx)
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 1 || keys[0].KID != activeKID {
			t.Errorf("after cleanup ListKeys = %v, want only the active kid %q", keys, activeKID)
		}
	})
}

// TestKeyStoreImport covers Import's explicit-key path and the OnKeyChange
// notification that multi-pod refresh relies on.
func TestKeyStoreImport(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("EnsureKey imports the supplied key", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x11)
		defer ks.Stop()

		key, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair: %v", err)
		}
		want := vaultcrypto.KIDFromPublicKey(&key.PublicKey)

		if err := ks.EnsureKey(ctx, key); err != nil {
			t.Fatalf("EnsureKey: %v", err)
		}
		got, kid := ks.ActiveKey()
		if kid != want {
			t.Errorf("active kid = %q, want %q", kid, want)
		}
		if got == nil || got.N.Cmp(key.N) != 0 {
			t.Error("active key is not the imported key (round-trip through AES-256-GCM failed)")
		}
	})

	t.Run("Import is idempotent for the same key", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x12)
		defer ks.Stop()

		key, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair: %v", err)
		}
		first, err := ks.Import(ctx, key)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		second, err := ks.Import(ctx, key)
		if err != nil {
			t.Fatalf("Import (repeat): %v", err)
		}
		if first != second {
			t.Fatalf("kid changed across re-import: %q -> %q", first, second)
		}
		keys, err := ks.ListKeys(ctx)
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 1 {
			t.Errorf("re-importing the same key produced %d rows, want 1", len(keys))
		}
		if _, kid := ks.ActiveKey(); kid != first {
			t.Errorf("re-imported key is not active: %q", kid)
		}
	})

	t.Run("OnKeyChange fires when the active kid changes", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x13)
		defer ks.Stop()

		type change struct {
			kid  string
			pubs int
		}
		var seen []change
		ks.SetOnKeyChange(func(_ *rsa.PrivateKey, kid string, all map[string]*rsa.PublicKey) {
			seen = append(seen, change{kid: kid, pubs: len(all)})
		})

		kid1, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		// A Refresh that finds the same active kid must NOT re-notify.
		if err := ks.Refresh(ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		kid2, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}

		if len(seen) != 2 {
			t.Fatalf("OnKeyChange fired %d times (%v), want 2 — once per active-kid change", len(seen), seen)
		}
		if seen[0].kid != kid1 || seen[1].kid != kid2 {
			t.Errorf("OnKeyChange kids = %v, want [%q %q]", seen, kid1, kid2)
		}
		if seen[1].pubs != 2 {
			t.Errorf("second OnKeyChange saw %d public keys, want 2 (active + retired)", seen[1].pubs)
		}
	})
}

// TestKeyStoreRefreshResilience covers Refresh's error and skip branches: a
// wrong master key must fail closed, and an unusable public key must not take
// the whole JWKS down with it.
func TestKeyStoreRefreshResilience(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("wrong master key fails closed", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		writer := newKeyStore(t, pool, time.Hour, 0x21)
		defer writer.Stop()
		if _, err := writer.Rotate(ctx); err != nil {
			t.Fatalf("Rotate: %v", err)
		}

		// Same rows, different master key: the AES-256-GCM tag must not verify.
		reader := newKeyStore(t, pool, time.Hour, 0x22)
		defer reader.Stop()
		if err := reader.Refresh(ctx); err == nil {
			t.Fatal("Refresh with the wrong master key succeeded, want decrypt failure")
		}
		if key, _ := reader.ActiveKey(); key != nil {
			t.Error("a failed Refresh published an active key")
		}
	})

	t.Run("undecodable retired key is skipped, not fatal", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x23)
		defer ks.Stop()

		goodKID, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		insertRetiredKey(t, pool, "kid-garbage-pub", []byte("not-a-public-key"))

		// A non-RSA (ed25519) key parses as PKIX but is not an *rsa.PublicKey.
		edPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		edDER, err := x509.MarshalPKIXPublicKey(edPub)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		insertRetiredKey(t, pool, "kid-ed25519", edDER)

		if err := ks.Refresh(ctx); err != nil {
			t.Fatalf("Refresh must skip unusable keys, got: %v", err)
		}
		pubs := ks.AllPublicKeys()
		if pubs[goodKID] == nil {
			t.Error("usable key dropped from JWKS")
		}
		if _, ok := pubs["kid-garbage-pub"]; ok {
			t.Error("undecodable public key published to JWKS")
		}
		if _, ok := pubs["kid-ed25519"]; ok {
			t.Error("non-RSA public key published to JWKS")
		}
	})

	t.Run("AllPublicKeys returns a copy", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x24)
		defer ks.Stop()
		kid, err := ks.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}

		got := ks.KeyProvider()()
		delete(got, kid)
		if ks.AllPublicKeys()[kid] == nil {
			t.Error("mutating the returned map corrupted the KeyStore's JWKS")
		}
	})
}

// TestKeyStoreRefreshLoop verifies the background loop picks up a key another
// pod wrote, and that Stop terminates it.
func TestKeyStoreRefreshLoop(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()
	truncateSigningKeys(t, pool)

	// writer plays the pod that rotates; follower plays every other pod.
	writer := newKeyStore(t, pool, time.Hour, 0x31)
	defer writer.Stop()
	follower := newKeyStore(t, pool, time.Hour, 0x31)

	changed := make(chan string, 4)
	follower.SetOnKeyChange(func(_ *rsa.PrivateKey, kid string, _ map[string]*rsa.PublicKey) {
		changed <- kid
	})
	follower.StartRefreshLoop(ctx, 20*time.Millisecond)

	kid, err := writer.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	select {
	case got := <-changed:
		if got != kid {
			t.Errorf("refresh loop picked up kid %q, want %q", got, kid)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("refresh loop never observed the key written by another pod")
	}

	follower.Stop()

	// After Stop the loop is gone and the master key is zeroed, so a further
	// Refresh can no longer decrypt.
	if err := follower.Refresh(ctx); err == nil {
		t.Error("Refresh succeeded after Stop zeroed the master key")
	}
}

// truncateSigningKeys clears the signing key table between subtests so each one
// starts from a known-empty state.
func truncateSigningKeys(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `TRUNCATE auth.signing_keys`); err != nil {
		t.Fatalf("truncate signing_keys: %v", err)
	}
}

// insertRetiredKey writes a retired row directly, bypassing Import, so Refresh
// meets a public key it cannot use. Retired rows are never decrypted, so the
// private_key bytes are irrelevant.
func insertRetiredKey(t *testing.T, pool *pgxpool.Pool, kid string, pubDER []byte) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO auth.signing_keys (kid, private_key, public_key, algorithm, status, created_at, expires_at)
		VALUES ($1, $2, $3, 'RS256', 'retired', NOW(), NOW() + INTERVAL '1 hour')
	`, kid, []byte("unused"), pubDER)
	if err != nil {
		t.Fatalf("insert retired key %s: %v", kid, err)
	}
}
