package audit

import (
	"context"
	"log"
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
	repo   repository.AuditRepository
	period time.Duration
	stopCh chan struct{}
}

// NewRetention builds a sweeper. A period of zero disables it, which is the
// default: an operator who has not chosen a horizon should not have one silently
// chosen for them, and deleting security logs is not a safe default.
func NewRetention(repo repository.AuditRepository, period time.Duration) *Retention {
	return &Retention{repo: repo, period: period, stopCh: make(chan struct{})}
}

// Enabled reports whether a retention horizon is configured.
func (r *Retention) Enabled() bool { return r != nil && r.period > 0 }

// Sweep deletes every audit entry older than the retention horizon and returns
// how many rows went. Safe to call directly (the CLI does).
func (r *Retention) Sweep(ctx context.Context) (int64, error) {
	if !r.Enabled() {
		return 0, nil
	}
	return r.repo.Cleanup(ctx, time.Now().Add(-r.period))
}

// Start runs the sweeper until Stop is called. It sweeps once immediately: a
// process that restarts more often than the interval would otherwise never
// reach a tick and the purge would never happen.
func (r *Retention) Start(ctx context.Context) {
	if !r.Enabled() {
		return
	}
	go func() {
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

// Stop terminates the sweep loop.
func (r *Retention) Stop() {
	if r.Enabled() {
		close(r.stopCh)
	}
}
