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
	// The critical set is the list of events that survive a full in-memory
	// buffer. Shrinking it reintroduces silent drops under
	// VAULT_AUDIT_FLUSH_INTERVAL > 0 (the embedded profile default).
	critical := []string{
		LoginFailure, PasswordChange, PasswordReset, TokenRevoke, AdminAction, KMSUnwrap,
		TokenMinted, SvcDocPut, SvcDocGet, SvcDocDelete,
		AdminAuthzDenied, AdminSessionRejected,
	}
	for _, ev := range critical {
		if !isCriticalEvent(ev) {
			t.Errorf("%q must be critical", ev)
		}
	}

	// login_success is the control: it is high volume and was deliberately
	// left droppable. If this starts returning true, the critical set has
	// been widened into a sync-write amplifier.
	notCritical := []string{
		LoginSuccess, TokenRefresh, Registration, "something:noncritical",
		"svcdoc", "svcdocx_put", "blob_put",
	}
	for _, ev := range notCritical {
		if isCriticalEvent(ev) {
			t.Errorf("%q must not be critical", ev)
		}
	}

	// Prefix, not an allow-list of today's three names: a future svcdoc_
	// event must not fall back to the droppable buffer the way token_minted
	// did when it was added without updating isCriticalEvent.
	if !isCriticalEvent("svcdoc_rotate") {
		t.Error("any svcdoc_ event must be critical, including ones added later")
	}

	// handler.AuditTokenMinted / AuditSvcDoc* are string literals in another
	// package. A rename here that does not keep those values would silently
	// un-protect the events we just classified.
	if TokenMinted != "token_minted" {
		t.Fatalf("TokenMinted = %q, want token_minted (handler.AuditTokenMinted)", TokenMinted)
	}
	if SvcDocPut != "svcdoc_put" || SvcDocGet != "svcdoc_get" || SvcDocDelete != "svcdoc_delete" {
		t.Fatalf("svcdoc constants drifted from handler.AuditSvcDoc*: put=%q get=%q delete=%q",
			SvcDocPut, SvcDocGet, SvcDocDelete)
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

// TestMintAndSvcDocSurviveBufferPressure is the regression for mint
// attribution (and service-document access) being dropped when the embedded
// profile's non-zero flush interval fills the in-memory buffer.
//
// POST /mint signs a subject vault42 never authenticated. The JWT looks like
// any other, so token_minted is the only record of who asked. Losing it under
// buffer pressure is worse than losing a password_change, which was already
// critical. The same flood that fills the buffer is exactly when a caller
// would hide a mint or a svcdoc mutation.
func TestMintAndSvcDocSurviveBufferPressure(t *testing.T) {
	events := []string{TokenMinted, SvcDocPut, SvcDocGet, SvcDocDelete, AdminAuthzDenied, AdminSessionRejected}
	for _, ev := range events {
		t.Run(ev, func(t *testing.T) {
			repo := &mockAuditRepo{}
			l := NewLoggerWithBufferSize(repo, time.Hour, 1)
			ctx := context.Background()

			if err := l.Log(ctx, LoginSuccess, "u1", "", "1.1.1.1", "", "", "", nil, 0); err != nil {
				t.Fatalf("buffer-fill Log: %v", err)
			}
			if err := l.Log(ctx, LoginSuccess, "u2", "", "1.1.1.1", "", "", "", nil, 0); err != nil {
				t.Fatalf("noncritical Log: %v", err)
			}
			if err := l.Log(ctx, ev, "subject-or-owner", "svc-client", "1.1.1.1", "", "", "",
				map[string]interface{}{"reason": "test"}, 0); err != nil {
				t.Fatalf("%s Log: %v", ev, err)
			}

			repo.mu.Lock()
			defer repo.mu.Unlock()
			var wrote, loginWrote int
			for _, e := range repo.entries {
				switch e.EventType {
				case ev:
					wrote++
				case LoginSuccess:
					loginWrote++
				}
			}
			if wrote != 1 {
				t.Fatalf("%s should be written synchronously exactly once, got %d", ev, wrote)
			}
			if loginWrote != 0 {
				t.Fatalf("non-critical LoginSuccess must stay unwritten when the buffer is full, got %d", loginWrote)
			}
			if l.DroppedTotal() != 2 {
				t.Fatalf("both buffer-full events increment DroppedTotal, got %d", l.DroppedTotal())
			}
		})
	}
}
