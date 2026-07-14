package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// hookAuditRepo lets a test observe and fail Insert calls.
type hookAuditRepo struct {
	inserts  int
	insertFn func(*model.AuditEntry) error
}

func (m *hookAuditRepo) Insert(_ context.Context, e *model.AuditEntry) error {
	m.inserts++
	if m.insertFn != nil {
		return m.insertFn(e)
	}
	return nil
}
func (m *hookAuditRepo) InsertBatch(_ context.Context, _ []*model.AuditEntry) error { return nil }
func (m *hookAuditRepo) Query(_ context.Context, _ repository.AuditFilter) ([]*model.AuditEntry, error) {
	return nil, nil
}
func (m *hookAuditRepo) Cleanup(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

// A full buffer drops a non-critical event (counted, not written).
func TestLogBufferFullDropsNonCritical(t *testing.T) {
	repo := &hookAuditRepo{}
	// Large interval so the batch loop never flushes during the test; cap of 1.
	l := NewLoggerWithBufferSize(repo, time.Hour, 1)

	// First entry fills the single-slot buffer.
	if err := l.Log(context.Background(), "noncritical:event", "u1", "", "", "", "", "", nil, 0); err != nil {
		t.Fatalf("first buffered log: %v", err)
	}
	// Second entry overflows: non-critical → dropped.
	if err := l.Log(context.Background(), "noncritical:event", "u2", "", "", "", "", "", nil, 0); err != nil {
		t.Fatalf("overflow log should not error: %v", err)
	}

	if repo.inserts != 0 {
		t.Errorf("non-critical overflow should not write to repo, got %d inserts", repo.inserts)
	}
	if got := l.DroppedTotal(); got != 1 {
		t.Errorf("DroppedTotal = %d, want 1", got)
	}
}

func (m *hookAuditRepo) CleanupLocked(ctx context.Context, olderThan time.Time) (int64, bool, error) {
	n, err := m.Cleanup(ctx, olderThan)
	return n, true, err
}

// A full buffer writes a critical event synchronously.
func TestLogBufferFullSyncWritesCritical(t *testing.T) {
	repo := &hookAuditRepo{}
	l := NewLoggerWithBufferSize(repo, time.Hour, 1)

	_ = l.Log(context.Background(), LoginFailure, "u1", "", "", "", "", "", nil, 0) // fills buffer
	if err := l.Log(context.Background(), LoginFailure, "u2", "", "", "", "", "", nil, 50); err != nil {
		t.Fatalf("critical overflow log should not error: %v", err)
	}

	if repo.inserts != 1 {
		t.Errorf("critical overflow should write synchronously, got %d inserts", repo.inserts)
	}
	if got := l.DroppedTotal(); got != 1 {
		t.Errorf("DroppedTotal = %d, want 1 (overflow still counted)", got)
	}
}

// A failing synchronous insert for a critical overflow is swallowed (logged, no error).
func TestLogBufferFullSyncCriticalInsertError(t *testing.T) {
	repo := &hookAuditRepo{insertFn: func(*model.AuditEntry) error { return errors.New("db down") }}
	l := NewLoggerWithBufferSize(repo, time.Hour, 1)

	_ = l.Log(context.Background(), PasswordChange, "u1", "", "", "", "", "", nil, 0)
	if err := l.Log(context.Background(), PasswordChange, "u2", "", "", "", "", "", nil, 0); err != nil {
		t.Fatalf("insert failure on critical overflow must not propagate, got %v", err)
	}
}
