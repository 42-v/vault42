package audit

import (
	"context"
	"fmt"
	"log"
	"os"
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
	auditLog *Logger
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
		repo: repo,
		// The sweeper records its own purges through a logger it builds over
		// the store it already holds, rather than being handed the
		// process-wide one at wiring time. An optional logger is one a caller
		// forgets to pass, and a sweeper holding nil deletes audit rows in
		// silence -- which is the exact defect the record exists to close, and
		// the one internal/server already needs a wiring gate to keep out of
		// the handlers.
		//
		// Immediate mode, because a sweep produces at most one entry per tick:
		// there is nothing to batch, and a buffered row is one a full buffer
		// can drop or a shutdown can lose after the rows it describes are
		// already gone.
		auditLog: NewLogger(repo, 0),
		period:   period,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// purgeRecordTimeout bounds the write of a purge's own audit entry.
//
// The write runs on a context that deliberately outlives the sweep's, so it
// needs a limit of its own or a wedged pool turns a canceled sweep into a
// shutdown that never returns: Stop blocks on the sweep loop, and main's next
// deferred call closes the pool the write would be waiting on.
const purgeRecordTimeout = 5 * time.Second

// replicaID names the process that ran a purge.
//
// The sweep is elected per tick by an advisory lock, so a record that does not
// say which replica won it cannot answer the question an operator actually has:
// a fleet where the purge has stopped running looks exactly like a fleet where
// one replica is quietly doing all of it, and neither is distinguishable from
// the trail alone. The hostname is the pod name under Kubernetes and the machine
// name anywhere else; the pid separates two processes sharing a host, which is
// what a compose file or a bare-metal box looks like.
var replicaID = replicaLabel(processHostname())

// processHostname returns the hostname, or "" when the system will not report
// one. The error is discarded rather than branched on: os.Hostname signals
// failure by returning an empty name as well, so both conditions want the same
// answer and a branch here would be a statement no test can reach.
func processHostname() string {
	host, _ := os.Hostname()
	return host
}

// replicaLabel formats one replica's identity for the purge record.
func replicaLabel(host string) string {
	if host == "" {
		// A host that cannot name itself is still a distinct replica. An empty
		// field in the record would read as "nobody recorded which replica
		// swept" rather than "this replica could not name itself".
		host = "unknown"
	}
	return fmt.Sprintf("%s/%d", host, os.Getpid())
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
//
// A sweep that did work leaves an entry in the log it swept. See recordPurge.
func (r *Retention) Sweep(ctx context.Context) (int64, error) {
	if !r.Enabled() {
		return 0, nil
	}
	// One cutoff for the whole sweep rather than one per batch, so the record
	// can name the boundary the DELETEs actually applied. Recomputed inside the
	// loop it moved forward by the duration of every batch, which would leave
	// the entry naming a horizon no DELETE ever used -- and an attestation that
	// is approximately true is the kind an auditor is right not to accept.
	cutoff := time.Now().Add(-r.period)
	total, elected, err := r.sweepBatches(ctx, cutoff)
	// Only the replica that held the advisory lock writes the record. Every
	// replica ticks on the same schedule, so recording from the ones that lost
	// the election would put a row in the log for each of them and have an
	// operator counting deletions across the fleet read one purge as several.
	if elected {
		r.recordPurge(ctx, cutoff, total, err)
	}
	return total, err
}

// sweepBatches runs the delete loop and reports whether this replica ever held
// the advisory lock, which is what decides who speaks for the purge.
func (r *Retention) sweepBatches(ctx context.Context, cutoff time.Time) (total int64, elected bool, err error) {
	for i := 0; i < SweepMaxBatches; i++ {
		deleted, acquired, cleanupErr := r.repo.CleanupLocked(ctx, cutoff)
		if cleanupErr != nil {
			// The lock is taken before the delete, so a failure under it is
			// this replica's purge failing rather than another replica's purge
			// happening. Only that first case is ours to record.
			return total, elected || acquired, cleanupErr
		}
		// Another replica holds the advisory lock. The work is idempotent, so
		// there is nothing to catch up on: stop and try again next tick.
		if !acquired {
			return total, elected, nil
		}
		elected = true
		total += deleted
		// A short batch means the horizon is clear. Stop rather than spend
		// another round trip and another ACCESS EXCLUSIVE lock proving it.
		if deleted < repository.AuditCleanupBatch {
			return total, elected, nil
		}
		// Give the inserts waiting behind the exclusive lock a turn before
		// taking it again, and honor a shutdown between batches.
		select {
		case <-ctx.Done():
			return total, elected, ctx.Err()
		case <-r.stopCh:
			return total, elected, nil
		default:
		}
	}
	return total, elected, nil
}

// recordPurge writes the audit entry for a purge this replica ran.
//
// Deleting audit rows is the one operation an append-only log cannot describe by
// holding its result, so it has to describe it by holding a row about itself.
// docs/security.md AR-12 accepts that vault_app can purge entries past the
// retention horizon; what made that risk worse than it needed to be was the
// purge being invisible in the log it purges, so a trail that stops abruptly
// read the same whether the sweeper ran, whether it ran on the horizon the
// operator configured, or whether somebody called audit.cleanup_old_entries()
// by hand.
//
// It files as admin_action, the class already reserved for an operator acting on
// the deployment. A purge is that action taken on a schedule instead of by hand,
// the metadata carries which one it was, and the class is already treated as
// critical by isCriticalEvent, which is the property this row wants most.
//
// A sweep that deleted nothing is not recorded, and that is a decision rather
// than an omission. Nothing was destroyed, so there is nothing to attest to, and
// the alternative writes a row every six hours per replica whose only content is
// that there was nothing to do. It also bounds the one cycle this record can
// create: the entry is itself an audit row, so a horizon later it becomes
// eligible for deletion, and deleting it is a purge that writes another entry.
// Recording only non-empty purges makes that converge on a single row per
// horizon in a deployment that has gone quiet, instead of every tick recording
// the purge of the tick before it.
//
// A failure is recorded whatever the count, because "the purge did not finish"
// is at least as interesting to whoever reads the trail as "the purge finished",
// and a sweep that took the lock, deleted some rows and then failed is the case
// where knowing how many went matters most.
//
// The store's own error stays out of the metadata. The process log beside this
// carries it verbatim at the same instant, while a driver error is unbounded
// text of the store's choosing and an audit row is permanent, exported under
// Art. 15 and exempt from erasure -- not somewhere to put text nobody bounded.
func (r *Retention) recordPurge(ctx context.Context, cutoff time.Time, deleted int64, sweepErr error) {
	if deleted == 0 && sweepErr == nil {
		return
	}

	outcome := "completed"
	if sweepErr != nil {
		outcome = "failed"
	}

	// The write outlives the sweep's context on purpose. A shutdown that cancels
	// mid-sweep leaves rows already deleted, and canceling the record along with
	// the work would destroy the evidence of exactly the purge nobody watched
	// finish.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), purgeRecordTimeout)
	defer cancel()

	err := r.auditLog.Log(writeCtx, AdminAction, "", "", "", "", "", "", map[string]interface{}{
		"action":  "audit_retention_purge",
		"outcome": outcome,
		// UTC and RFC 3339, so the boundary stays comparable against the
		// timestamps of the rows that are gone when the trail is read from a
		// different timezone than the one that wrote it.
		"cutoff":  cutoff.UTC().Format(time.RFC3339Nano),
		"deleted": deleted,
		"horizon": r.period.String(),
		"replica": replicaID,
	})
	if err != nil {
		log.Printf("audit retention: purged %d entries and could not record it: %v", deleted, err)
	}
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
