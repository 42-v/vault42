package integration_test

import (
	"bytes"
	"context"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/keystore"
)

// Nothing rotated the signing key on a schedule. VAULT_KEY_ROTATION_DB is off by
// default and even with it on the only rotations available were an admin endpoint
// and a CLI command, so a default install either signed with one key forever or,
// in a multi-replica deployment with no key file, ran replicas that did not agree
// on one.
//
// RotateIfOlderThan is the decision the scheduler makes each tick, and it makes it
// against the STORED key's age rather than the process's uptime, so it survives a
// restart, a rollout and a replica count above one. These cases pin it against a
// real Postgres, because the age query, the advisory lock and the retire-terminal
// invariants of migrations 026 and 027 all live in the database.
func TestSigningKeyRotatesOnItsAgeAndRespectsTheRetireInvariants(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("a key younger than the horizon is left alone", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x71)
		defer ks.Stop()

		if err := ks.EnsureKey(ctx, nil); err != nil {
			t.Fatalf("EnsureKey: %v", err)
		}
		_, before := ks.ActiveKey()

		kid, err := ks.RotateIfOlderThan(ctx, 720*time.Hour)
		if err != nil {
			t.Fatalf("RotateIfOlderThan: %v", err)
		}
		if kid != "" {
			t.Errorf("rotated to %q; a key minutes old must not be rotated on a 30-day horizon", kid)
		}
		if _, after := ks.ActiveKey(); after != before {
			t.Errorf("active kid changed from %q to %q with nothing due", before, after)
		}
	})

	t.Run("a key past the horizon rotates and retires its predecessor with an expiry", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		const retention = 2 * time.Hour
		ks := newKeyStore(t, pool, retention, 0x72)
		defer ks.Stop()

		if err := ks.EnsureKey(ctx, nil); err != nil {
			t.Fatalf("EnsureKey: %v", err)
		}
		_, old := ks.ActiveKey()

		// Back-date the active key rather than wait 30 days. created_at is the
		// column the scheduler reads, and moving it on an ACTIVE row is untouched
		// by both retire guards: 026 fires only on a row that is already retired,
		// and 027's CHECK constrains retired rows only.
		if _, err := pool.Exec(ctx,
			`UPDATE auth.signing_keys SET created_at = NOW() - INTERVAL '40 days' WHERE kid = $1`, old); err != nil {
			t.Fatalf("back-date the active key: %v", err)
		}

		kid, err := ks.RotateIfOlderThan(ctx, 720*time.Hour)
		if err != nil {
			t.Fatalf("RotateIfOlderThan: %v", err)
		}
		if kid == "" || kid == old {
			t.Fatalf("rotated to %q, want a new kid distinct from %q", kid, old)
		}
		if _, active := ks.ActiveKey(); active != kid {
			t.Errorf("active kid is %q after rotation, want %q", active, kid)
		}

		// Migration 027: a retired key must carry a concrete expiry, or it sits in
		// the verification set forever and CleanupExpired can never reach it. The
		// constraint would have refused the write, so reaching this assertion at
		// all means rotation obeyed it; reading the row back states what the
		// scheduler actually produced.
		var status string
		var expiresAt *time.Time
		if err := pool.QueryRow(ctx,
			`SELECT status, expires_at FROM auth.signing_keys WHERE kid = $1`, old).Scan(&status, &expiresAt); err != nil {
			t.Fatalf("read back the rotated-out key: %v", err)
		}
		if status != "retired" {
			t.Errorf("previous key status = %q, want retired", status)
		}
		if expiresAt == nil {
			t.Fatal("the rotated-out key has a NULL expires_at; migration 027 forbids that state " +
				"precisely because such a row never leaves JWKS and the reaper never becomes eligible for it")
		}
		if until := time.Until(*expiresAt); until <= 0 || until > retention+time.Minute {
			t.Errorf("expires_at is %s away, want within the %s retention period", until, retention)
		}

		// Migration 026: the retired row is terminal. Rotation must not have left a
		// state where the old key can be dragged back into the verification set.
		if _, err := pool.Exec(ctx,
			`UPDATE auth.signing_keys SET expires_at = NULL WHERE kid = $1`, old); err == nil {
			t.Error("clearing a retired key's expiry succeeded; the rotated-out key can be put back into JWKS forever")
		}

		// Both keys still verify, which is what makes rotation zero-downtime.
		pubs := ks.AllPublicKeys()
		if _, ok := pubs[old]; !ok {
			t.Error("the rotated-out key left JWKS immediately, so every token it signed stopped verifying")
		}
		if _, ok := pubs[kid]; !ok {
			t.Error("the new key is not in JWKS")
		}
	})

	t.Run("an empty keystore is not rotated into", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x73)
		defer ks.Stop()

		kid, err := ks.RotateIfOlderThan(ctx, time.Nanosecond)
		if err != nil {
			t.Fatalf("RotateIfOlderThan on an empty store: %v", err)
		}
		if kid != "" {
			t.Errorf("rotated to %q with no active key; creating the first key is EnsureKey's job and "+
				"racing it would leave two", kid)
		}
	})

	t.Run("a replica that does not get the lock skips the round", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x74)
		defer ks.Stop()

		if err := ks.EnsureKey(ctx, nil); err != nil {
			t.Fatalf("EnsureKey: %v", err)
		}
		_, before := ks.ActiveKey()
		if _, err := pool.Exec(ctx,
			`UPDATE auth.signing_keys SET created_at = NOW() - INTERVAL '40 days' WHERE kid = $1`, before); err != nil {
			t.Fatalf("back-date the active key: %v", err)
		}

		// Stand in for the other replica: hold the same advisory lock on a session
		// of our own. 4244 is keystore's rotation lock; the audit sweeper's 4242 and
		// the escrow prune's 4243 must not collide with it.
		holder, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire a second session: %v", err)
		}
		var held bool
		if err := holder.QueryRow(ctx, `SELECT pg_try_advisory_lock(4244)`).Scan(&held); err != nil || !held {
			holder.Release()
			t.Fatalf("take the rotation lock: held=%v err=%v", held, err)
		}

		kid, err := ks.RotateIfOlderThan(ctx, 720*time.Hour)
		if _, unlockErr := holder.Exec(ctx, `SELECT pg_advisory_unlock(4244)`); unlockErr != nil {
			t.Errorf("release the rotation lock: %v", unlockErr)
		}
		holder.Release()

		if err != nil {
			t.Fatalf("RotateIfOlderThan while another replica holds the lock: %v", err)
		}
		if kid != "" {
			t.Errorf("rotated to %q while another replica held the lock; two replicas rotating on one "+
				"due date produce two keys and retire one of them the instant it is created", kid)
		}
		if _, after := ks.ActiveKey(); after != before {
			t.Errorf("active kid changed from %q to %q despite losing the lock", before, after)
		}

		// The lock is released again afterwards, so the next tick can take it.
		kid, err = ks.RotateIfOlderThan(ctx, 720*time.Hour)
		if err != nil {
			t.Fatalf("RotateIfOlderThan after the lock was released: %v", err)
		}
		if kid == "" {
			t.Error("the rotation never happened after the lock was released; the previous call " +
				"leaked the session lock back into the pool")
		}
	})

	t.Run("the scheduler drives the same decision", func(t *testing.T) {
		truncateSigningKeys(t, pool)
		ks := newKeyStore(t, pool, time.Hour, 0x75)
		defer ks.Stop()

		if err := ks.EnsureKey(ctx, nil); err != nil {
			t.Fatalf("EnsureKey: %v", err)
		}
		_, before := ks.ActiveKey()
		if _, err := pool.Exec(ctx,
			`UPDATE auth.signing_keys SET created_at = NOW() - INTERVAL '40 days' WHERE kid = $1`, before); err != nil {
			t.Fatalf("back-date the active key: %v", err)
		}

		rotation := keystore.NewRotation(ks, 720*time.Hour)
		if !rotation.Enabled() {
			t.Fatal("a scheduler over a live keystore reports itself disabled")
		}
		rotation.Start(ctx)
		defer rotation.Stop()

		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, after := ks.ActiveKey(); after != before {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Error("the scheduler never rotated an overdue key on its first check; a loop that only " +
			"acts on its ticker never acts at all in a deployment that rolls hourly")
	})
}

// A failure to reach the database must be an error rather than "nothing was due",
// which is indistinguishable from a healthy check of a fresh key and would let a
// deployment sit on one signing key while its logs stayed clean.
func TestSigningKeyRotationSurfacesDatabaseFailures(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	ctx := context.Background()

	ks := newKeyStore(t, pool, time.Hour, 0x76)
	if err := ks.EnsureKey(ctx, nil); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	ks.Stop()
	cleanup()

	if kid, err := ks.RotateIfOlderThan(ctx, time.Nanosecond); err == nil {
		t.Fatalf("RotateIfOlderThan against a closed pool returned (%q, nil), want an error", kid)
	}
}

// rotationLogCapture collects what the rotation writes to the standard logger.
// The unlock failure has no return value and no metric; the log line is the
// entire observable, so an operator debugging a fleet whose rotations have
// stopped has nothing else to read.
type rotationLogCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *rotationLogCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *rotationLogCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// TestSigningKeyRotationSurvivesItsSessionDyingUnderTheLock is the failure a
// rotation meets in a real fleet rather than in a closed-pool unit test.
//
// RotateIfOlderThan takes a SESSION advisory lock, so the lock lives on one
// connection and travels with it. A rotation whose backend is terminated while
// it holds that lock — a failover, an idle-session timeout, an operator running
// pg_terminate_backend on what looks like a stuck query — has to do two things.
// It has to report the failure rather than return ("", nil), because "nothing
// was due" is indistinguishable from a healthy check and would let a deployment
// sit on one signing key with clean logs. And its unlock, which cannot succeed
// on a dead connection, has to say so: a session lock believed released but
// still held would block every later rotation in the fleet, and the release is
// deferred with no error to return.
//
// The kill window is made deterministic by taking an ACCESS EXCLUSIVE lock on
// auth.signing_keys first. The rotation then blocks inside its age query with
// the advisory lock already taken, which is the only moment its session can be
// killed with the lock held.
func TestSigningKeyRotationSurvivesItsSessionDyingUnderTheLock(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()
	truncateSigningKeys(t, pool)

	ks := newKeyStore(t, pool, time.Hour, 0x77)
	defer ks.Stop()
	if err := ks.EnsureKey(ctx, nil); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}

	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire the blocking session: %v", err)
	}
	defer blocker.Release()
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatalf("begin the blocking transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE auth.signing_keys IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock auth.signing_keys: %v", err)
	}

	var logs rotationLogCapture
	priorOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(priorOutput) })

	type outcome struct {
		kid string
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		kid, err := ks.RotateIfOlderThan(ctx, time.Nanosecond)
		done <- outcome{kid, err}
	}()

	// Wait for the rotation's own backend to be the one blocked on the table
	// lock, then kill it. Matching on the age query's text keeps this off the
	// keystore's refresh loop, which reads the same table.
	var pid int32
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		err := pool.QueryRow(ctx, `
			SELECT pid FROM pg_stat_activity
			WHERE state = 'active'
			  AND query LIKE '%SELECT created_at FROM auth.signing_keys%'
			  AND pid <> pg_backend_pid()
			LIMIT 1`).Scan(&pid)
		if err == nil && pid != 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("the rotation never reached its age query, so its session was never killed under the lock")
	}
	if _, err := pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatalf("terminate the rotation's backend: %v", err)
	}

	var got outcome
	select {
	case got = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("RotateIfOlderThan never returned after its session was terminated")
	}
	_ = tx.Rollback(context.Background())

	if got.err == nil {
		t.Fatalf("RotateIfOlderThan returned (%q, nil) after its session died mid-query; a rotation "+
			"that reports no error and no kid is indistinguishable from one that found nothing due, "+
			"and the deployment would stay on one signing key with clean logs", got.kid)
	}
	if !strings.Contains(got.err.Error(), "read active key age") {
		t.Errorf("error = %q, want it to name the age query that failed", got.err)
	}
	if got.kid != "" {
		t.Errorf("RotateIfOlderThan returned kid %q alongside an error", got.kid)
	}
	if out := logs.String(); !strings.Contains(out, "keystore rotation: unlock failed") {
		t.Errorf("the failed advisory unlock was not reported. A session lock the fleet believes is "+
			"released and is not blocks every later rotation, and this log line is the only place it "+
			"is visible. Captured:\n%s", out)
	}
}
