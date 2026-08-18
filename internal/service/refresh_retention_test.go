package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-v/vault42/tests/mocks"
)

// RefreshTokenRepository.DeleteExpired existed and worked and nothing on the
// server path ever called it: the only production caller was a CLI subcommand
// an operator had to remember to run. cmd/vault started the audit, recovery,
// keystore and admin-session sweepers and not this one.

// unusedReapingRepo adds the second predicate to the mock, so the optional
// interface assertion in Sweep is exercised the way the real repository
// satisfies it.
type unusedReapingRepo struct {
	*mocks.MockRefreshTokenRepo
	unused    int64
	unusedErr error
	calls     atomic.Int64
}

func (r *unusedReapingRepo) DeleteExpiredUnused(context.Context) (int64, error) {
	r.calls.Add(1)
	return r.unused, r.unusedErr
}

func TestRefreshRetentionSweepsBothPredicates(t *testing.T) {
	base := &mocks.MockRefreshTokenRepo{
		DeleteExpiredFn: func(context.Context) (int64, error) { return 7, nil },
	}
	repo := &unusedReapingRepo{MockRefreshTokenRepo: base, unused: 5}

	r := NewRefreshTokenRetention(repo)
	got, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got != 12 {
		t.Fatalf("Sweep reaped %d rows, want 12 (7 spent + 5 expired-unused)", got)
	}
	if repo.calls.Load() != 1 {
		t.Fatalf("DeleteExpiredUnused called %d times, want 1 — rows that expire without ever "+
			"being used are invisible to the used-or-revoked predicate and live forever",
			repo.calls.Load())
	}
}

func TestRefreshRetentionReportsErrors(t *testing.T) {
	wantErr := errors.New("db down")

	t.Run("first predicate", func(t *testing.T) {
		repo := &mocks.MockRefreshTokenRepo{
			DeleteExpiredFn: func(context.Context) (int64, error) { return 3, wantErr },
		}
		r := NewRefreshTokenRetention(repo)
		got, err := r.Sweep(context.Background())
		if !errors.Is(err, wantErr) {
			t.Fatalf("Sweep err = %v, want %v", err, wantErr)
		}
		if got != 3 {
			t.Fatalf("Sweep reported %d rows, want the 3 that did go", got)
		}
	})

	t.Run("second predicate", func(t *testing.T) {
		base := &mocks.MockRefreshTokenRepo{
			DeleteExpiredFn: func(context.Context) (int64, error) { return 3, nil },
		}
		repo := &unusedReapingRepo{MockRefreshTokenRepo: base, unused: 2, unusedErr: wantErr}
		r := NewRefreshTokenRetention(repo)
		got, err := r.Sweep(context.Background())
		if !errors.Is(err, wantErr) {
			t.Fatalf("Sweep err = %v, want %v", err, wantErr)
		}
		if got != 5 {
			t.Fatalf("Sweep reported %d rows, want 5", got)
		}
	})
}

// TestRefreshRetentionStartStopIsDrainable is the shutdown property every
// sweeper in this tree holds: Stop blocks until the loop has exited, so the
// sweeper cannot still be inside a DELETE when main closes the pool.
func TestRefreshRetentionStartStopIsDrainable(t *testing.T) {
	swept := make(chan struct{}, 1)
	repo := &mocks.MockRefreshTokenRepo{
		DeleteExpiredFn: func(context.Context) (int64, error) {
			select {
			case swept <- struct{}{}:
			default:
			}
			return 1, nil
		},
	}
	r := NewRefreshTokenRetention(repo)
	r.Start(context.Background())
	// Starting twice must not start a second loop: two loops share one doneCh
	// and the second to exit closes an already-closed channel.
	r.Start(context.Background())

	select {
	case <-swept:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweeper did not sweep once immediately")
	}

	r.Stop()
	r.Stop() // idempotent

	select {
	case <-r.Done():
	default:
		t.Fatal("Stop returned before the loop had exited")
	}
}

// TestRefreshRetentionLogsASweepFailure covers the loop's error arm: a sweep
// that fails must not stop the sweeper, or one transient database blip retires
// the reaper until the next restart.
func TestRefreshRetentionLogsASweepFailure(t *testing.T) {
	tried := make(chan struct{}, 1)
	repo := &mocks.MockRefreshTokenRepo{
		DeleteExpiredFn: func(context.Context) (int64, error) {
			select {
			case tried <- struct{}{}:
			default:
			}
			return 0, errors.New("db down")
		},
	}
	r := NewRefreshTokenRetention(repo)
	r.Start(context.Background())
	defer r.Stop()

	select {
	case <-tried:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweeper never attempted a sweep")
	}
}

// TestRefreshRetentionStopsOnContextCancel covers the other exit.
func TestRefreshRetentionStopsOnContextCancel(t *testing.T) {
	repo := &mocks.MockRefreshTokenRepo{
		DeleteExpiredFn: func(context.Context) (int64, error) { return 0, nil },
	}
	r := NewRefreshTokenRetention(repo)
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	cancel()

	select {
	case <-r.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a canceled context did not stop the sweep loop")
	}
	r.Stop()
}

// TestRefreshRetentionNilIsSafe keeps the guards honest: a sweeper with no
// repository must be inert rather than panicking during startup or shutdown.
func TestRefreshRetentionNilIsSafe(t *testing.T) {
	var r *RefreshTokenRetention
	r.Start(context.Background())
	r.Stop()
	if n, err := r.Sweep(context.Background()); n != 0 || err != nil {
		t.Fatalf("nil Sweep = (%d, %v)", n, err)
	}

	empty := NewRefreshTokenRetention(nil)
	empty.Start(context.Background())
	empty.Stop()
	if n, err := empty.Sweep(context.Background()); n != 0 || err != nil {
		t.Fatalf("repo-less Sweep = (%d, %v)", n, err)
	}
	if empty.Done() == nil {
		t.Fatal("Done returned nil")
	}
}
