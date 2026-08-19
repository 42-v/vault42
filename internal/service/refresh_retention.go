package service

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/42-v/vault42/internal/repository"
)

// RefreshTokenSweepInterval is how often spent and expired refresh tokens are
// reaped. Refresh tokens are short-lived relative to an hour and there is one
// row per rotation, so hourly keeps the table flat without making the sweep a
// load of its own.
const RefreshTokenSweepInterval = time.Hour

// expiredUnusedReaper is the optional second predicate: rows that expired
// without ever being used or revoked. It is asserted on the repository rather
// than added to the interface so a store that cannot answer simply is not
// asked, instead of every implementation growing a method it does not use.
type expiredUnusedReaper interface {
	DeleteExpiredUnused(ctx context.Context) (int64, error)
}

// RefreshTokenRetention reaps dead refresh-token rows on a timer.
//
// RefreshTokenRepository.DeleteExpired existed and worked, and nothing on the
// server path ever called it: the only production caller was `vault cleanup`,
// a CLI subcommand an operator has to remember to run. cmd/vault started the
// audit, recovery, keystore and admin-session sweepers and not this one, so
// auth.refresh_tokens was the one table with a reaper and no schedule — which
// is also why the unbatched DELETE it used to run mattered.
type RefreshTokenRetention struct {
	repo     repository.RefreshTokenRepository
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
	started  atomic.Bool
}

// NewRefreshTokenRetention builds a sweeper over the refresh-token repository.
func NewRefreshTokenRetention(repo repository.RefreshTokenRepository) *RefreshTokenRetention {
	return &RefreshTokenRetention{
		repo:   repo,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Done is closed once the sweep loop has exited, whether via Stop or a canceled
// context, so a caller that closes the database pool on return does not race a
// sweep mid-DELETE. It never closes if Start was not called.
func (r *RefreshTokenRetention) Done() <-chan struct{} { return r.doneCh }

// Sweep deletes spent and expired refresh tokens and returns how many rows went.
func (r *RefreshTokenRetention) Sweep(ctx context.Context) (int64, error) {
	if r == nil || r.repo == nil {
		return 0, nil
	}
	deleted, err := r.repo.DeleteExpired(ctx)
	if err != nil {
		return deleted, err
	}
	if unused, ok := r.repo.(expiredUnusedReaper); ok {
		n, err := unused.DeleteExpiredUnused(ctx)
		deleted += n
		if err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// Start runs the sweeper until Stop is called. It sweeps once immediately so a
// process that restarts more often than the interval still reaps. Calling it
// more than once starts nothing further: two loops would share one doneCh, and
// the second to exit would close an already-closed channel.
func (r *RefreshTokenRetention) Start(ctx context.Context) {
	if r == nil || r.repo == nil {
		return
	}
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer close(r.doneCh)
		ticker := time.NewTicker(RefreshTokenSweepInterval)
		defer ticker.Stop()
		for {
			if deleted, err := r.Sweep(ctx); err != nil {
				log.Printf("refresh token retention: sweep failed: %v", err)
			} else if deleted > 0 {
				log.Printf("refresh token retention: reaped %d dead refresh tokens", deleted)
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
func (r *RefreshTokenRetention) Stop() {
	if r == nil || r.repo == nil {
		return
	}
	r.stopOnce.Do(func() { close(r.stopCh) })
	if r.started.Load() {
		<-r.doneCh
	}
}
