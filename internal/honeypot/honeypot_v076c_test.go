package honeypot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/tests/mocks"
)

// testAuditLog returns an audit logger backed by a no-op mock repo so that the
// auditLog != nil branches in Alert are exercised.
func testAuditLog() *audit.Logger {
	return audit.NewLogger(&mocks.MockAuditRepo{}, 0)
}

// Alert with an audit logger but no webhook: covers the audit-trigger block
// and the early return when webhookURL is empty.
func TestAlert_AuditOnlyNoWebhook(t *testing.T) {
	a := NewAlerter("", []string{"trap@x.test"}, testAuditLog())
	a.Alert(context.Background(), Event{
		EventType: "trap_login",
		IP:        "10.0.0.9",
		Email:     "trap@x.test",
		RiskScore: 100,
	})
}

// Alert with an audit logger AND a live webhook returning 200: covers the
// audit-trigger block plus the post-dispatch audit block (webhook_status).
func TestAlert_AuditAndWebhookDispatch(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := NewAlerter(srv.URL, nil, testAuditLog())
	a.Alert(context.Background(), Event{
		EventType: "scan_detected",
		IP:        "10.0.0.10",
		UserAgent: "nmap",
		RiskScore: 60,
	})
	if hits != 1 {
		t.Fatalf("webhook hit count = %d, want 1", hits)
	}
}
