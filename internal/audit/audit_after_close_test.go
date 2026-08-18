package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
)

// Close closes done and flushes once. Log had no closed check, so an entry
// written afterwards was appended to a buffer nothing would ever flush and the
// call still returned nil — a row silently discarded by the one component whose
// contract is that it does not silently discard rows.
//
// It is a live path, not a theoretical one. notifyNewCountry runs on the
// deferwork pool and writes audit.LoginNewCountry, and until the fix that ships
// with these tests cmd/vault closed the logger BEFORE draining that pool, so a
// job still running at shutdown wrote into the closed buffer.

// refusingRepo is a store that cannot take the row, which is what a pool closed
// ahead of the logger looks like.
type refusingRepo struct {
	*mockAuditRepo
	err error
}

func (r *refusingRepo) Insert(ctx context.Context, e *model.AuditEntry) error {
	if r.err != nil {
		return r.err
	}
	return r.mockAuditRepo.Insert(ctx, e)
}

// rows reports how many entries reached the store.
func rows(m *mockAuditRepo) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func TestAnEntryLoggedAfterCloseStillReachesTheStore(t *testing.T) {
	ctx := context.Background()
	repo := &mockAuditRepo{}
	l := NewLoggerWithBufferSize(repo, time.Hour, 100)

	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.Log(ctx, LoginNewCountry, "u-1", "", "1.2.3.4", "UA", "", "", nil, 20); err != nil {
		t.Fatalf("Log after Close: %v", err)
	}

	if got := rows(repo); got != 1 {
		t.Fatalf("rows written = %d, want 1: an entry logged after Close went into a buffer "+
			"nothing will flush, and Log reported success", got)
	}
}

// And when the store cannot take it either, the failure is reported rather than
// swallowed. A shutdown that loses an audit row must say so; silence is what
// made this invisible.
func TestAnEntryLoggedAfterCloseReportsAFailedStore(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("pool is closed")
	repo := &refusingRepo{mockAuditRepo: &mockAuditRepo{}, err: boom}
	l := NewLoggerWithBufferSize(repo, time.Hour, 100)

	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := l.Log(ctx, LoginNewCountry, "u-1", "", "1.2.3.4", "UA", "", "", nil, 20)
	if err == nil {
		t.Fatal("Log after Close returned nil while the store refused the row; a lost audit " +
			"entry must be loud")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap the store failure", err)
	}
}

// An open logger is unaffected: the ordinary path still buffers, so the check
// costs the hot path a channel poll and changes nothing else about it.
func TestAnOpenLoggerStillBuffers(t *testing.T) {
	ctx := context.Background()
	repo := &mockAuditRepo{}
	l := NewLoggerWithBufferSize(repo, time.Hour, 100)
	t.Cleanup(func() { _ = l.Close(context.Background()) })

	if err := l.Log(ctx, LoginSuccess, "u-1", "", "1.2.3.4", "UA", "", "", nil, 0); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if got := rows(repo); got != 0 {
		t.Fatalf("rows written = %d, want 0: a buffered logger must not insert per call", got)
	}
	if err := l.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := rows(repo); got != 1 {
		t.Fatalf("rows written after Flush = %d, want 1", got)
	}
}
