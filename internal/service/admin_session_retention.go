package service

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/42-v/vault42/internal/repository"
)

// AdminSessionSweepInterval is how often expired admin sessions are reaped.
// Admin sessions are short-lived and few (one row per admin login), so an hour
// is frequent enough to keep the table from accumulating expired rows without
// pinning the sweep to a shorter cadence than the data warrants.
const AdminSessionSweepInterval = time.Hour

// AdminSessionRetention reaps expired admin sessions on a timer.
//
// AdminSessionRepo.DeleteExpired removes every row past its expiry, but nothing
// called it: the admin gateway ran only its HTTPS listener, so expired sessions
// accumulated with their token hash, IP and user-agent long after they could
// authenticate. This runs the sweep the same way RecoveryRetention runs the
// escrow purge, with the same guards, so the reaper actually reaps.
type AdminSessionRetention struct {
	repo     repository.AdminSessionRepository
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
	started  atomic.Bool
}

// NewAdminSessionRetention builds a sweeper over the admin-session repository.
func NewAdminSessionRetention(repo repository.AdminSessionRepository) *AdminSessionRetention {
	return &AdminSessionRetention{
		repo:   repo,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Done is closed once the sweep loop has exited, whether via Stop or a canceled
// context, so a caller that closes the database pool on return does not race a
// sweep mid-DELETE. It never closes if Start was not called.
func (r *AdminSessionRetention) Done() <-chan struct{} { return r.doneCh }

// Sweep deletes every expired admin session and returns how many rows went.
func (r *AdminSessionRetention) Sweep(ctx context.Context) (int64, error) {
	if r == nil || r.repo == nil {
		return 0, nil
	}
	return r.repo.DeleteExpired(ctx)
}

// Start runs the sweeper until Stop is called. It sweeps once immediately so a
// process that restarts more often than the interval still reaps. Calling it
// more than once starts nothing further: two loops would share one doneCh, and
// the second to exit would close an already-closed channel.
func (r *AdminSessionRetention) Start(ctx context.Context) {
	if r == nil || r.repo == nil {
		return
	}
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer close(r.doneCh)
		ticker := time.NewTicker(AdminSessionSweepInterval)
		defer ticker.Stop()
		for {
			if deleted, err := r.Sweep(ctx); err != nil {
				log.Printf("admin session retention: sweep failed: %v", err)
			} else if deleted > 0 {
				log.Printf("admin session retention: reaped %d expired admin sessions", deleted)
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

// Stop terminates the sweep loop and blocks until it has exited, so the sweeper
// cannot outlive the pool its caller closes on return. Safe to call more than
// once and safe on a sweeper that was never started.
func (r *AdminSessionRetention) Stop() {
	if r == nil || r.repo == nil {
		return
	}
	r.stopOnce.Do(func() { close(r.stopCh) })
	if r.started.Load() {
		<-r.doneCh
	}
}
