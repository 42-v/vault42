package service

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/42-v/vault42/internal/repository"
)

// RecoverySweepInterval is how often the escrow retention sweeper runs.
// Retention horizons are measured in days, so sweeping more often than daily
// buys nothing; sweeping exactly daily would pin the purge to whenever the
// process last restarted.
const RecoverySweepInterval = 6 * time.Hour

// RecoveryRetention purges account-recovery escrow records past their retention
// horizon.
//
// Every erasure with a recovery key configured appends a record holding the
// subject's real email, creation date, roles and display name, encrypted to the
// offline operator key. Like the audit log, the escrow is deliberately exempt
// from the erasure cascade — the whole point is that it outlives the account —
// and like the audit log it therefore has to be bounded by time instead, under
// Art. 5(1)(e). It shipped bounded by nothing: append-only triggers, no expiry
// column, UPDATE and DELETE revoked from both application roles, and no code
// path that removed a row.
//
// The horizon is the Operator's call. It has to be long enough to cover the
// window in which an accidental or malicious deletion would still be noticed
// and reversed, and no longer.
type RecoveryRetention struct {
	pruner   repository.AccountRecoveryPruner
	period   time.Duration
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
	started  atomic.Bool
}

// NewRecoveryRetention builds a sweeper. A period of zero disables it, which is
// the default: the escrow holds the only recoverable copy of an erased account,
// so destroying it must be an explicit operator choice, exactly as for the audit
// sweeper.
func NewRecoveryRetention(pruner repository.AccountRecoveryPruner, period time.Duration) *RecoveryRetention {
	return &RecoveryRetention{
		pruner: pruner,
		period: period,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Done is closed once the sweep loop has exited, whether it ended via Stop or
// via its context being canceled. A caller that closes the database pool on its
// return can otherwise race a sweep that is mid-DELETE. The channel never closes
// if Start was not called.
func (r *RecoveryRetention) Done() <-chan struct{} { return r.doneCh }

// Enabled reports whether a retention horizon is configured.
func (r *RecoveryRetention) Enabled() bool { return r != nil && r.period > 0 && r.pruner != nil }

// SweepMaxBatches bounds one tick.
//
// PruneLocked deletes at most one batch per call, so a sweep loops. The loop
// needs a ceiling for the same reason the audit sweeper has one: a tick that
// keeps going until the horizon is empty is a tick with no end, and the
// remainder is not urgent — the next tick picks it up. At the repository's batch
// size this is 40 000 rows per tick, four times a day.
const SweepMaxBatches = 20

// Sweep deletes every escrow record older than the retention horizon and returns
// how many rows went.
//
// Serialized across replicas: the underlying prune takes an ACCESS EXCLUSIVE
// lock on the escrow table (it disables the append-only trigger to delete), so
// only one replica may sweep at a time. A replica that does not get the lock
// returns what it has and tries again next tick — the work is idempotent, so
// there is nothing to catch up on.
//
// It loops, because one call deletes at most repository.RecoveryCleanupBatch
// rows. Holding that exclusive lock over an unbounded DELETE stalled every
// erasure for the length of the whole purge: an Art. 17 deletion with a recovery
// key configured appends its escrow record on the request path, and that append
// waits behind the ALTER TABLE the purge does to turn the append-only trigger
// off.
func (r *RecoveryRetention) Sweep(ctx context.Context) (int64, error) {
	if !r.Enabled() {
		return 0, nil
	}
	var total int64
	for range SweepMaxBatches {
		deleted, acquired, err := r.pruner.PruneLocked(ctx, time.Now().Add(-r.period))
		if err != nil {
			return total, err
		}
		// Another replica holds the advisory lock. The work is idempotent, so
		// there is nothing to catch up on: stop and try again next tick.
		if !acquired {
			return total, nil
		}
		total += deleted
		// A short batch means the horizon is clear. Stop rather than spend
		// another round trip and another ACCESS EXCLUSIVE lock proving it.
		if deleted < repository.RecoveryCleanupBatch {
			return total, nil
		}
		// Give the erasures waiting behind the exclusive lock a turn before
		// taking it again, and honor a shutdown between batches.
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-r.stopCh:
			return total, nil
		default:
		}
	}
	return total, nil
}

// Start runs the sweeper until Stop is called. It sweeps once immediately: a
// process that restarts more often than the interval would otherwise never reach
// a tick and the purge would never happen.
//
// Calling it more than once starts nothing further. Two loops would share one
// doneCh, and the second one to exit would close an already-closed channel: an
// unrecoverable panic raised from a deferred call in a background goroutine,
// which no handler can catch and which takes the process with it.
func (r *RecoveryRetention) Start(ctx context.Context) {
	if !r.Enabled() {
		return
	}
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer close(r.doneCh)
		ticker := time.NewTicker(RecoverySweepInterval)
		defer ticker.Stop()
		for {
			if deleted, err := r.Sweep(ctx); err != nil {
				log.Printf("recovery retention: sweep failed: %v", err)
			} else if deleted > 0 {
				log.Printf("recovery retention: purged %d escrow records older than %s", deleted, r.period)
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

// Stop terminates the sweep loop and blocks until it has actually exited, so the
// sweeper cannot outlive the database pool its caller closes on return. Safe to
// call more than once, and safe on a sweeper that was never started.
func (r *RecoveryRetention) Stop() {
	if !r.Enabled() {
		return
	}
	r.stopOnce.Do(func() { close(r.stopCh) })
	if r.started.Load() {
		<-r.doneCh
	}
}
