package audit

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/42-v/vault42/internal/repository"
)

// SweepInterval is how often the retention sweeper runs. Retention horizons are
// measured in days, so sweeping more often than daily buys nothing; sweeping
// exactly daily would pin the purge to whenever the process last restarted.
const SweepInterval = 6 * time.Hour

// Retention purges audit entries past their retention horizon.
//
// Art. 5(1)(e) allows personal data to be kept only as long as it is needed for
// the purpose it was collected for. Audit entries carry user IDs, IP addresses,
// user agents and fingerprint hashes, and were the one store with no expiry: a
// manual `vault cleanup-audit` existed, but nothing ran it, so in a deployment
// nobody hand-tended, security logs accumulated indefinitely.
//
// Erasure does not cover this. Art. 17(3)(b)/(e) lets security records outlive an
// erasure request, so audit entries are deliberately exempt from the account
// cascade — which is precisely why they need a time-based purge of their own.
type Retention struct {
	repo     repository.AuditRepository
	period   time.Duration
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
	started  atomic.Bool
}

// NewRetention builds a sweeper. A period of zero disables it, which is the
// default: an operator who has not chosen a horizon should not have one silently
// chosen for them, and deleting security logs is not a safe default.
func NewRetention(repo repository.AuditRepository, period time.Duration) *Retention {
	return &Retention{
		repo:   repo,
		period: period,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Done is closed once the sweep loop has exited, whether it ended via Stop or via
// its context being canceled. Without it there is no way to know the sweeper has
// actually stopped: Stop and cancel both only *request* an exit, and a caller that
// closes the database pool on their return can still race a sweep that is mid-DELETE.
//
// The channel never closes if Start was not called — a sweeper that was never
// running has nothing to wait for.
func (r *Retention) Done() <-chan struct{} { return r.doneCh }

// Enabled reports whether a retention horizon is configured.
func (r *Retention) Enabled() bool { return r != nil && r.period > 0 }

// SweepMaxBatches bounds one tick.
//
// CleanupLocked deletes at most one batch per call, so a sweep loops. The loop
// needs a ceiling for the same reason the postgres cache reaper has one: a tick
// that keeps going until the table is empty is a tick with no end, and the
// remainder is not urgent — the next tick picks it up. At the repository's
// batch size this is 40 000 rows per tick, four times a day.
const SweepMaxBatches = 20

// Sweep deletes every audit entry older than the retention horizon and returns
// how many rows went.
//
// Serialized across replicas: the underlying cleanup takes an ACCESS EXCLUSIVE
// lock on the audit table (it disables the append-only trigger to delete), so
// only one replica may sweep at a time. A replica that does not get the lock
// returns what it has and tries again next tick — the work is idempotent, so
// there is nothing to catch up on.
//
// It loops, because one call deletes at most repository.AuditCleanupBatch rows.
// Holding that exclusive lock over an unbounded DELETE blocked every audit
// insert for the length of the whole purge, and a failed login is a critical
// event written synchronously on the request path even when the buffer is full.
func (r *Retention) Sweep(ctx context.Context) (int64, error) {
	if !r.Enabled() {
		return 0, nil
	}
	var total int64
	for i := 0; i < SweepMaxBatches; i++ {
		deleted, acquired, err := r.repo.CleanupLocked(ctx, time.Now().Add(-r.period))
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
		if deleted < repository.AuditCleanupBatch {
			return total, nil
		}
		// Give the inserts waiting behind the exclusive lock a turn before
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
// process that restarts more often than the interval would otherwise never
// reach a tick and the purge would never happen.
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
			if deleted, err := r.Sweep(ctx); err != nil {
				log.Printf("audit retention: sweep failed: %v", err)
			} else if deleted > 0 {
				log.Printf("audit retention: purged %d entries older than %s", deleted, r.period)
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
// The wait is the point. The sole caller is `defer auditRetention.Stop()` in main,
// which returns straight into the deferred close of the database pool — so a Stop
// that only *asked* the loop to finish could return while a sweep was still inside
// its DELETE, and the pool would be torn out from under it. Waiting for the loop to
// exit is what makes "the sweeper does not outlive shutdown" true rather than
// merely intended.
//
// Safe to call more than once, and safe on a sweeper that was never started: an
// unstarted loop closes nothing, so there is nothing to wait for.
func (r *Retention) Stop() {
	if !r.Enabled() {
		return
	}
	r.stopOnce.Do(func() { close(r.stopCh) })
	if r.started.Load() {
		<-r.doneCh
	}
}
