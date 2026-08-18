package keystore

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// RotationCheckInterval is how often the scheduler asks whether the active
// signing key is due for rotation.
//
// It is deliberately not the rotation interval itself. The decision is made
// against the ACTIVE KEY'S AGE, read from the database, not against this
// process's uptime, so the schedule survives a restart, a rollout and a replica
// count greater than one. An hourly check makes a 720-hour rotation land within
// an hour of when it is due, which is as precise as a monthly schedule needs to
// be.
const RotationCheckInterval = time.Hour

// DefaultRotationInterval is how old the active signing key may get before it is
// rotated. It matches docs/spec-draft.md's 30 days, which is the number the
// design specified and the number the shipped code never implemented.
const DefaultRotationInterval = 720 * time.Hour

// signingKeyRotationLockKey is the advisory-lock key rotation serialises on.
// Arbitrary but fixed, and distinct from the audit sweeper's 4242 and the escrow
// prune's 4243: those touch different tables and must not block this.
const signingKeyRotationLockKey int64 = 4244

// keyRotator is the single operation the scheduler needs. Narrowing the
// dependency to it is what lets the loop be tested without a database, which
// matters more here than usual: the rotation itself is covered against a live
// Postgres, but the loop's start, stop and failure behavior is the part that
// decides whether anything ever runs in production.
type keyRotator interface {
	RotateIfOlderThan(ctx context.Context, maxAge time.Duration) (string, error)
}

// Rotation rotates the JWT signing key on a schedule.
//
// Nothing did. docs/spec-draft.md specified rotation every 30 days with at most
// three keys in JWKS; docs/spec.md quietly redefined rotation as manual
// (POST /admin/keys/rotate and the rotate-jwks CLI) and no interval setting
// existed — only VAULT_KEY_REFRESH_INTERVAL, which is how often a pod re-reads
// the store, and VAULT_KEY_RETENTION_PERIOD, which is how long a retired key
// lingers. Neither rotates anything. A default install therefore signed with one
// key forever, and every token ever issued by that deployment verified under a
// single private key whose exposure window was the lifetime of the install.
//
// The horizon is an operator's call in the same way the audit and escrow
// horizons are, so the interval is configurable; unlike those two it defaults to
// ON, because a key that is never rotated is not a retained record an operator
// might want kept, it is a control that does not exist.
type Rotation struct {
	rotator  keyRotator
	interval time.Duration
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
	started  atomic.Bool
}

// NewRotation builds a scheduler over ks. An interval of zero or less disables
// it, which is how an operator who rotates on their own schedule turns it off.
//
// A vault running the file-based signing key mode builds no keystore at all, so
// the caller may well have nothing to give: an inert scheduler is the answer
// rather than a second branch at the call site.
func NewRotation(ks keyRotator, interval time.Duration) *Rotation {
	return &Rotation{
		rotator:  ks,
		interval: interval,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Enabled reports whether there is a keystore to rotate and a horizon to rotate
// against.
//
// The typed-nil check is not paranoia. cmd/vault holds the keystore as a
// *KeyStore that stays nil in file-based mode, and a nil *KeyStore stored in an
// interface is not a nil interface, so `r.rotator == nil` is false for it and the
// first tick would dereference a nil pool inside a goroutine, where the panic
// takes the process down with no request to attribute it to.
func (r *Rotation) Enabled() bool {
	if r == nil || r.rotator == nil || r.interval <= 0 {
		return false
	}
	if ks, ok := r.rotator.(*KeyStore); ok {
		return ks != nil
	}
	return true
}

// Done is closed once the rotation loop has exited, whether it ended via Stop or
// via its context being canceled. The channel never closes if Start was not
// called: a loop that never ran has nothing to wait for.
func (r *Rotation) Done() <-chan struct{} { return r.doneCh }

// Rotate rotates the active key if it is older than the configured interval, and
// returns the new kid or "" when nothing was due.
func (r *Rotation) Rotate(ctx context.Context) (string, error) {
	if !r.Enabled() {
		return "", nil
	}
	return r.rotator.RotateIfOlderThan(ctx, r.interval)
}

// Start runs the scheduler until Stop is called or ctx is canceled. It checks
// once immediately, which is safe precisely because the check is against the
// stored key's age: a deployment that restarts more often than the check interval
// still rotates exactly when the key is old enough, and never because a pod
// booted.
//
// Calling it more than once starts nothing further. Two loops would share one
// doneCh, and the second one to exit would close an already-closed channel: an
// unrecoverable panic raised from a deferred call in a background goroutine,
// which no handler can catch and which takes the process with it.
func (r *Rotation) Start(ctx context.Context) {
	if !r.Enabled() {
		return
	}
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer close(r.doneCh)
		ticker := time.NewTicker(RotationCheckInterval)
		defer ticker.Stop()
		for {
			// A failed rotation is logged and the loop continues. The decision is
			// re-derived from the stored key's age on the next tick, so a database
			// blip must not cost the deployment its rotation for the rest of the
			// process's life.
			if kid, err := r.Rotate(ctx); err != nil {
				log.Printf("keystore rotation: failed: %v", err)
			} else if kid != "" {
				log.Printf("keystore rotation: signing key rotated to kid=%s after %s", kid, r.interval)
			}
			select {
			case <-ticker.C:
			case <-r.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop terminates the rotation loop and blocks until it has actually exited.
//
// The wait is the point. Stop is deferred in cmd/vault above a deferred close of
// the database pool, so a Stop that only asked the loop to finish could return
// while a rotation was still inside its transaction and have the pool torn out
// from under it. Safe to call more than once, and safe on a scheduler that was
// never started.
func (r *Rotation) Stop() {
	if !r.Enabled() {
		return
	}
	r.stopOnce.Do(func() { close(r.stopCh) })
	if r.started.Load() {
		<-r.doneCh
	}
}

// RotateIfOlderThan rotates the active signing key when it is older than maxAge
// and returns the new kid, or "" when nothing was due.
//
// Serialised across replicas by a session-scoped advisory lock. Rotation is not
// idempotent the way a sweep is: two replicas deciding simultaneously would each
// generate a key, each retire whatever was active when it looked, and the
// deployment would come out of one due date with two rotations and a key retired
// the instant it was created. A replica that does not get the lock returns
// ("", nil) and re-derives the decision on its next tick, where the key it sees
// is the freshly rotated one.
//
// The age comes from auth.signing_keys.created_at, so it is the key's age and not
// the process's. No active key at all is not this function's problem: EnsureKey
// creates one at startup, and rotating into an empty store would race that.
//
// The retire-terminal invariants hold by construction. Rotation reaches the
// database only through Import, whose retire statement always writes a concrete
// expires_at (now + retentionPeriod), so migration 027's
// `status <> 'retired' OR expires_at IS NOT NULL` CHECK is satisfied on every
// rotation, and migration 026's guard is never even reached: it fires only on
// writes to a row that is ALREADY retired, and Import only ever retires a row
// that was active.
func (ks *KeyStore) RotateIfOlderThan(ctx context.Context, maxAge time.Duration) (string, error) {
	conn, err := ks.pool.Acquire(ctx)
	if err != nil {
		return "", fmt.Errorf("keystore rotation: acquire: %w", err)
	}
	defer conn.Release()

	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", signingKeyRotationLockKey).Scan(&acquired); err != nil {
		return "", fmt.Errorf("keystore rotation: lock: %w", err)
	}
	if !acquired {
		return "", nil
	}
	// Released before the connection goes back to the pool: deferred calls run
	// last-in-first-out, so this runs ahead of conn.Release above. A session lock
	// left held would travel with the connection and block every later rotation
	// in the fleet.
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx),
			"SELECT pg_advisory_unlock($1)", signingKeyRotationLockKey); err != nil {
			log.Printf("keystore rotation: unlock failed: %v", err)
		}
	}()

	var createdAt time.Time
	err = conn.QueryRow(ctx, `
		SELECT created_at FROM auth.signing_keys
		WHERE status = 'active'
		ORDER BY created_at DESC
		LIMIT 1`).Scan(&createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("keystore rotation: read active key age: %w", err)
	}
	if time.Since(createdAt) < maxAge {
		return "", nil
	}
	return ks.Rotate(ctx)
}
