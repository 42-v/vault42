package keystore

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// SweepInterval is how often the expired-key sweeper runs.
//
// The rows it removes have already stopped mattering: Refresh drops a retired
// key from the verification set the moment expires_at passes, so a row waiting
// for the next sweep is bytes and nothing else. Sweeping more often would buy
// nothing, and matching the audit and recovery sweepers leaves one number for
// an operator to reason about instead of three.
const SweepInterval = 6 * time.Hour

// expiredKeyReaper is the single operation the sweeper needs. Narrowing the
// dependency to it is what lets the loop be tested without a database, which
// matters more here than usual: the reap itself is one DELETE and is covered
// against a live Postgres, but the loop's start, stop and failure behavior is
// the part that decides whether anything ever runs in production.
type expiredKeyReaper interface {
	CleanupExpired(ctx context.Context) (int64, error)
}

// Retention removes retired signing keys that have outlived their retention
// window.
//
// CleanupExpired shipped with the DB-backed keystore and nothing ever called
// it. Its doc comment says it is "called periodically during refresh", which
// was true of no code path: the refresh loop only refreshes. So auth.signing_keys
// grew by one row per rotation forever, and every one of those rows carries an
// AES-256-GCM ciphertext of a private key that no longer verifies anything.
// Keeping decommissioned key material around indefinitely is the part that
// makes this more than table bloat.
//
// Unlike the audit and recovery sweepers this one has no horizon of its own and
// no off switch. Those two default to disabled because destroying security logs
// or the only recoverable copy of an erased account is an operator's call. Here
// the horizon is already a per-row decision the keystore made at retirement
// time, expires_at is that decision written down, and a row past it verifies
// nothing for anyone. There is no judgment left to defer.
//
// Revoked keys are not reapable and are not meant to be. Their row is the
// tombstone that keeps a leaked kid from being re-inserted, so it outlives
// everything; the database refuses to delete one whatever this sweeper asks.
type Retention struct {
	reaper   expiredKeyReaper
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
	started  atomic.Bool
}

// NewRetention builds a sweeper over ks.
//
// A vault running the file-based signing key mode builds no keystore at all, so
// the caller may well have nothing to give: an inert sweeper is the answer
// rather than a second branch at the call site.
func NewRetention(ks expiredKeyReaper) *Retention {
	return &Retention{
		reaper: ks,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Enabled reports whether there is a keystore to sweep.
//
// The typed-nil check is not paranoia. cmd/vault holds the keystore as a
// *KeyStore that stays nil in file-based mode, and a nil *KeyStore stored in an
// interface is not a nil interface, so `r.reaper == nil` is false for it and the
// first tick would dereference a nil pool inside a goroutine, where the panic
// takes the process down with no request to attribute it to.
func (r *Retention) Enabled() bool {
	if r == nil || r.reaper == nil {
		return false
	}
	if ks, ok := r.reaper.(*KeyStore); ok {
		return ks != nil
	}
	return true
}

// Done is closed once the sweep loop has exited, whether it ended via Stop or
// via its context being canceled. The channel never closes if Start was not
// called: a loop that never ran has nothing to wait for.
func (r *Retention) Done() <-chan struct{} { return r.doneCh }

// Sweep removes every retired key past its expiry and returns how many rows
// went.
//
// It cannot shorten any key's verification life. Refresh loads a row only while
// `expires_at > NOW() OR (expires_at IS NULL AND status = 'active')`, and the reap's predicate is
// `expires_at IS NOT NULL AND expires_at < NOW()`. The two sets are disjoint, so
// every row this deletes is one the keystore already refuses to publish, and the
// tokens it signed had already stopped verifying at expires_at rather than here.
// What decides whether a live token outlives its key is VAULT_KEY_RETENTION_PERIOD
// against the access token TTL, which is a choice made at rotation time and
// nothing this sweeper can affect either way.
func (r *Retention) Sweep(ctx context.Context) (int64, error) {
	if !r.Enabled() {
		return 0, nil
	}
	return r.reaper.CleanupExpired(ctx)
}

// Start runs the sweeper until Stop is called or ctx is canceled. It sweeps
// once immediately: a deployment that rolls its pods more often than the
// interval would otherwise never reach a tick and the reap would never happen.
func (r *Retention) Start(ctx context.Context) {
	if !r.Enabled() {
		return
	}
	// CompareAndSwap, not Store: a second Start would spawn a second loop
	// sharing this one doneCh, and the second of the two to exit would close
	// an already-closed channel. That panic is raised from a deferred call in
	// a background goroutine, where no handler can catch it and it takes the
	// process with it. Matches the four sibling sweepers.
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer close(r.doneCh)
		ticker := time.NewTicker(SweepInterval)
		defer ticker.Stop()
		for {
			// A failed sweep is logged and the loop continues. The work is
			// idempotent and the next tick retries it, so a database blip must
			// not cost the process its reaping for the rest of its life.
			if deleted, err := r.Sweep(ctx); err != nil {
				log.Printf("keystore retention: sweep failed: %v", err)
			} else if deleted > 0 {
				log.Printf("keystore retention: reaped %d retired signing keys past their expiry", deleted)
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

// Stop terminates the sweep loop and blocks until it has actually exited.
//
// The wait is the point. Stop is deferred in cmd/vault above a deferred close of
// the database pool, so a Stop that only asked the loop to finish could return
// while a sweep was still inside its DELETE and have the pool torn out from
// under it. Safe to call more than once, and safe on a sweeper that was never
// started.
func (r *Retention) Stop() {
	if !r.Enabled() {
		return
	}
	r.stopOnce.Do(func() { close(r.stopCh) })
	if r.started.Load() {
		<-r.doneCh
	}
}
