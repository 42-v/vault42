package audit

import (
	"context"
	"testing"
	"time"
)

func TestLoggerDroppedTotalStartsZero(t *testing.T) {
	l := NewLogger(&mockAuditRepo{}, time.Hour)
	if got := l.DroppedTotal(); got != 0 {
		t.Fatalf("DroppedTotal = %d on fresh logger, want 0", got)
	}
}

func TestIsCriticalEvent(t *testing.T) {
	if !isCriticalEvent(LoginFailure) {
		t.Error("LoginFailure should be critical")
	}
	if !isCriticalEvent(PasswordChange) {
		t.Error("PasswordChange should be critical")
	}
	if isCriticalEvent("something:noncritical") {
		t.Error("arbitrary event should not be critical")
	}
}

// TestKMSUnwrapIsCritical asserts the key-release audit event is classified
// critical so it is never silently dropped under buffer pressure.
func TestKMSUnwrapIsCritical(t *testing.T) {
	if !isCriticalEvent(KMSUnwrap) {
		t.Error("KMSUnwrap must be critical — a key-release action needs a guaranteed trail")
	}
}

// TestKMSUnwrapSynchronousWhenBufferFull proves that when the batch buffer is
// saturated (DoS / high load), a KMSUnwrap event is written SYNCHRONOUSLY to the
// repository rather than dropped — unlike a non-critical event, which is dropped.
func TestKMSUnwrapSynchronousWhenBufferFull(t *testing.T) {
	repo := &mockAuditRepo{}
	// flushEvery large so the batch loop never flushes during the test; bufferSize
	// 1 so a single buffered entry saturates the buffer.
	l := NewLoggerWithBufferSize(repo, time.Hour, 1)
	ctx := context.Background()

	// Fill the buffer with one non-critical event (stays buffered, not persisted).
	if err := l.Log(ctx, LoginSuccess, "u1", "", "1.1.1.1", "", "", "", nil, 0); err != nil {
		t.Fatalf("buffer-fill Log: %v", err)
	}

	// A non-critical event now hits the full buffer and is dropped (not persisted).
	if err := l.Log(ctx, LoginSuccess, "u2", "", "1.1.1.1", "", "", "", nil, 0); err != nil {
		t.Fatalf("noncritical Log: %v", err)
	}

	// KMSUnwrap on the full buffer must be persisted synchronously.
	if err := l.Log(ctx, KMSUnwrap, "life42-gateway", "life42-gateway", "1.1.1.1", "", "", "",
		map[string]interface{}{"kid": "life42-root-kek", "success": true}, 0); err != nil {
		t.Fatalf("KMSUnwrap Log: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	var kmsWritten, loginWritten int
	for _, e := range repo.entries {
		switch e.EventType {
		case KMSUnwrap:
			kmsWritten++
		case LoginSuccess:
			loginWritten++
		}
	}
	if kmsWritten != 1 {
		t.Fatalf("KMSUnwrap should be written synchronously exactly once, got %d", kmsWritten)
	}
	if loginWritten != 0 {
		t.Fatalf("non-critical LoginSuccess must not be synchronously written when buffer full, got %d", loginWritten)
	}
	if l.DroppedTotal() != 2 {
		t.Fatalf("both buffer-full events increment DroppedTotal, got %d", l.DroppedTotal())
	}
}
