package keystore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// deadPool returns a pool that can never connect. pgxpool dials lazily, so New
// succeeds and every query fails — the shape of a database outage at runtime.
func deadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// Port 1 is reserved; nothing listens there.
	pool, err := pgxpool.New(context.Background(), "postgres://vault:vault@127.0.0.1:1/vault?connect_timeout=1")
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func deadKeyStore(t *testing.T) *KeyStore {
	t.Helper()
	ks, err := New(deadPool(t), make([]byte, 32), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ks
}

// The keystore holds the JWT signing keys, encrypted at rest under the master key.
// Every one of these operations must fail loudly when the database is unreachable.
//
// The quiet failures are the dangerous ones. A Rotate that reported success without
// writing would leave the operator believing a compromised key had been retired. A
// Revoke that did the same leaves a stolen key signing valid tokens. And an EnsureKey
// that swallowed the error at boot is the worst of the three: the process would come
// up "healthy" with no active signing key at all.
func TestKeyStore_SurfacesDatabaseFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("Refresh", func(t *testing.T) {
		if err := deadKeyStore(t).Refresh(ctx); err == nil {
			t.Error("Refresh reported success against an unreachable database")
		}
	})

	t.Run("Rotate", func(t *testing.T) {
		if _, err := deadKeyStore(t).Rotate(ctx); err == nil {
			t.Error("Rotate reported success — the operator would believe a compromised key was retired")
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		if err := deadKeyStore(t).Revoke(ctx, "kid-1"); err == nil {
			t.Error("Revoke reported success — a stolen key would keep signing valid tokens")
		}
	})

	t.Run("ListKeys", func(t *testing.T) {
		if _, err := deadKeyStore(t).ListKeys(ctx); err == nil {
			t.Error("ListKeys returned no error — an empty list would read as 'no keys exist'")
		}
	})

	t.Run("CleanupExpired", func(t *testing.T) {
		if _, err := deadKeyStore(t).CleanupExpired(ctx); err == nil {
			t.Error("CleanupExpired reported success against an unreachable database")
		}
	})

	t.Run("Import", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		if _, err := deadKeyStore(t).Import(ctx, key); err == nil {
			t.Error("Import reported success — the key was never persisted and would vanish on restart")
		}
	})

	t.Run("EnsureKey", func(t *testing.T) {
		if err := deadKeyStore(t).EnsureKey(ctx, nil); err == nil {
			t.Error("EnsureKey reported success — the process would boot with no active signing key")
		}
	})
}

// The master key must be exactly 32 bytes: AES-256 takes nothing else, and a
// silently-accepted short key would mean the signing keys are encrypted under
// something the operator never chose.
func TestNew_RejectsWrongMasterKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := New(deadPool(t), make([]byte, n), time.Hour); err == nil {
			t.Errorf("New accepted a %d-byte master key", n)
		}
	}
}
