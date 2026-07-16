package keystore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"strings"
	"sync"
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

// Encrypt refuses any master key that is not 32 bytes. New rejects those too,
// so this branch is reachable only through direct construction, the shape of
// a master key corrupted after startup. Import must fail before touching the
// database: a key that cannot be encrypted must never be persisted.
func TestKeyStore_ImportFailsBeforeDBOnUnusableMasterKey(t *testing.T) {
	ks := &KeyStore{
		masterKey:  make([]byte, 16),
		publicKeys: make(map[string]*rsa.PublicKey),
		stopCh:     make(chan struct{}),
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// pool is nil: if Import ever reached the database with an unencryptable
	// key, this test would panic instead of pass.
	_, err = ks.Import(context.Background(), key)
	if err == nil {
		t.Fatal("Import reported success with an unusable master key")
	}
	if !strings.Contains(err.Error(), "encrypt private key") {
		t.Errorf("Import error = %q, want it to surface the encrypt failure", err)
	}
}

// keystoreLogBuffer is a mutex-guarded log sink safe to read while the refresh
// loop goroutine is still writing lines.
type keystoreLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *keystoreLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *keystoreLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A ticker-driven refresh that fails must be logged, not silently dropped: the
// pod keeps serving its last known keys, and the log line is the only signal
// that it is drifting from the database.
func TestKeyStore_RefreshLoopLogsFailedRefresh(t *testing.T) {
	var logBuf keystoreLogBuffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	ks := deadKeyStore(t)
	ks.StartRefreshLoop(context.Background(), 5*time.Millisecond)

	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logBuf.String(), "refresh failed") {
		if time.Now().After(deadline) {
			ks.Stop()
			t.Fatal("refresh loop never logged its failed refresh")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ks.Stop()
}
