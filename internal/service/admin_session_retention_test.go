package service

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
)

// fakeAdminSessionRepo implements repository.AdminSessionRepository; only
// DeleteExpired carries behavior, the rest are inert stubs.
type fakeAdminSessionRepo struct {
	deleteCalls atomic.Int64
	deleteN     int64
	deleteErr   error
}

func (f *fakeAdminSessionRepo) Create(context.Context, *model.AdminSession) error { return nil }
func (f *fakeAdminSessionRepo) GetByTokenHash(context.Context, string) (*model.AdminSession, error) {
	return nil, nil
}

func (f *fakeAdminSessionRepo) ListByAdmin(context.Context, string) ([]*model.AdminSession, error) {
	return nil, nil
}

func (f *fakeAdminSessionRepo) ListActive(context.Context) ([]*model.AdminSession, error) {
	return nil, nil
}
func (f *fakeAdminSessionRepo) Revoke(context.Context, string) error            { return nil }
func (f *fakeAdminSessionRepo) RevokeAllForAdmin(context.Context, string) error { return nil }
func (f *fakeAdminSessionRepo) RevokeAll(context.Context) error                 { return nil }
func (f *fakeAdminSessionRepo) DeleteExpired(context.Context) (int64, error) {
	f.deleteCalls.Add(1)
	return f.deleteN, f.deleteErr
}

func waitForSweep(t *testing.T, repo *fakeAdminSessionRepo) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for repo.deleteCalls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the sweeper did not run its immediate sweep")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAdminSessionRetention_SweepDeletesExpired(t *testing.T) {
	repo := &fakeAdminSessionRepo{deleteN: 3}
	n, err := NewAdminSessionRetention(repo).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n != 3 {
		t.Fatalf("Sweep returned %d, want 3", n)
	}
}

func TestAdminSessionRetention_NilRepoIsInert(t *testing.T) {
	r := NewAdminSessionRetention(nil)
	if n, err := r.Sweep(context.Background()); n != 0 || err != nil {
		t.Fatalf("nil-repo Sweep = %d, %v; want 0, nil", n, err)
	}
	r.Start(context.Background()) // no-op, no goroutine
	r.Stop()                      // safe
}

func TestAdminSessionRetention_StartSweepsImmediatelyThenStops(t *testing.T) {
	repo := &fakeAdminSessionRepo{deleteN: 1} // a reaped row exercises the success log
	r := NewAdminSessionRetention(repo)

	select {
	case <-r.Done():
		t.Fatal("Done closed before Start")
	default:
	}

	r.Start(context.Background())
	waitForSweep(t, repo)

	r.Start(context.Background()) // second Start is a no-op (CompareAndSwap fails)
	r.Stop()                      // blocks until the loop exits
	r.Stop()                      // safe to call again

	select {
	case <-r.Done():
	default:
		t.Fatal("Done not closed after Stop")
	}
}

// A sweep that cannot run is invisible otherwise: the loop swallows the error
// and keeps ticking, so the log line is the only evidence an operator ever gets
// that expired admin sessions are not being reaped.
func TestAdminSessionRetention_SweepErrorIsLogged(t *testing.T) {
	var logBuf claimLogBuffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	repo := &fakeAdminSessionRepo{deleteErr: errors.New("boom")}
	r := NewAdminSessionRetention(repo)
	r.Start(context.Background())
	waitForSweep(t, repo)
	r.Stop() // blocks until the loop exits, so the log line is already written

	if got := logBuf.String(); !strings.Contains(got, "admin session retention: sweep failed: boom") {
		t.Errorf("sweep failure log = %q, want it to name the failing sweep and its cause", got)
	}
}

func TestAdminSessionRetention_ContextCancelStopsTheLoop(t *testing.T) {
	repo := &fakeAdminSessionRepo{}
	r := NewAdminSessionRetention(repo)
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	waitForSweep(t, repo)
	cancel() // the loop exits through its ctx.Done case
	select {
	case <-r.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not exit when its context was canceled")
	}
	r.Stop() // safe after the loop has already exited on ctx cancel
}

// Reaching the end of this test is the assertion. Stop waits on doneCh, which
// only the sweep loop closes, so a Stop that did not check whether Start ever
// ran would block here until the test binary's timeout.
func TestAdminSessionRetention_StopBeforeStartIsSafe(t *testing.T) {
	NewAdminSessionRetention(&fakeAdminSessionRepo{}).Stop()
}
