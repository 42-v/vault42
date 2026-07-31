package honeypot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// apAuditSpy returns a logger that records every entry it is handed, so a test
// can assert what the durable record says rather than that a method was called.
func apAuditSpy(entries *[]*model.AuditEntry) *audit.Logger {
	repo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			*entries = append(*entries, e)
			return nil
		},
	}
	return audit.NewLogger(repo, 0)
}

// The webhook is best-effort; the audit entry is not. An event whose JSON cannot
// be produced must still leave the trigger in the audit log, the only evidence
// that the trap fired, and must not reach the webhook at all. Posting a partially
// encoded body would put a truncated attack report in front of whatever the
// operator has pointed the alert at.
func TestAlerter_UnencodableEventStillAuditsAndSendsNothing(t *testing.T) {
	var posted int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posted++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var entries []*model.AuditEntry
	a := NewAlerter(srv.URL, []string{"trap@example.com"}, apAuditSpy(&entries))

	// time.Time refuses to marshal a year outside [0,9999], so an event carrying
	// a corrupt timestamp cannot be encoded.
	a.Alert(context.Background(), HoneypotEvent{
		Timestamp: time.Date(-1, time.January, 1, 0, 0, 0, 0, time.UTC),
		EventType: "trap_login",
		IP:        "203.0.113.1",
		UserAgent: "curl/8.0",
		Email:     "trap@example.com",
		RiskScore: 90,
	})

	if posted != 0 {
		t.Errorf("the webhook was called %d times with an event that could not be encoded", posted)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want the trap trigger recorded exactly once", len(entries))
	}
	if entries[0].EventType != audit.HoneypotTrigger {
		t.Errorf("audit event type = %q, want %q", entries[0].EventType, audit.HoneypotTrigger)
	}
	if entries[0].IP != "203.0.113.1" {
		t.Errorf("audit entry lost the attacker IP: %q", entries[0].IP)
	}
}
