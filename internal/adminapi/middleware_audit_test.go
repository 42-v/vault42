package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/tests/mocks"
)

// capturingAudit is an immediate-mode audit sink that refuses Insert when the
// caller's context is already canceled, which is what pgx does with a
// disconnected client. A discarded error here is a missing row.
type capturingAudit struct {
	mocks.MockAuditRepo
	mu      sync.Mutex
	entries []*model.AuditEntry
}

func newCapturingAudit() *capturingAudit {
	c := &capturingAudit{}
	c.InsertFn = func(ctx context.Context, entry *model.AuditEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		cp := *entry
		c.mu.Lock()
		c.entries = append(c.entries, &cp)
		c.mu.Unlock()
		return nil
	}
	return c
}

func (c *capturingAudit) last() *model.AuditEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) == 0 {
		return nil
	}
	return c.entries[len(c.entries)-1]
}

// A viewer probing a write route can cancel the request (or drop the
// connection) the instant the gateway starts handling it. If the denial
// audit uses that canceled context, Insert fails, the error is discarded,
// and the privilege-boundary probe leaves no row — the whole point of AR-16.
func TestRBACCheck_DenialAuditSurvivesCanceledContext(t *testing.T) {
	repo := newCapturingAudit()
	logger := audit.NewLogger(repo, 0)
	admin := &model.AdminUser{ID: "admin-viewer-1", Username: "viewer", Role: string(rbac.RoleViewer)}

	reached := false
	guarded := RBACCheck(rbac.ConfigWrite, logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPut, "/admin/config/some_key", nil).WithContext(ctx)
	req = req.WithContext(WithAdmin(req.Context(), admin))
	req.RemoteAddr = "127.0.0.1:5100"
	req.Header.Set("User-Agent", "rbac-probe/1.0")
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied RBAC check returned %d, want 403", rec.Code)
	}
	if reached {
		t.Fatal("the guarded handler ran despite a permission denial")
	}
	entry := repo.last()
	if entry == nil {
		t.Fatal("permission denial wrote no audit row when the request context was canceled")
	}
	if entry.EventType != audit.AdminAuthzDenied {
		t.Errorf("event %q, want %q", entry.EventType, audit.AdminAuthzDenied)
	}
	if entry.UserID != admin.ID {
		t.Errorf("actor %q, want %q", entry.UserID, admin.ID)
	}
	if entry.IP != req.RemoteAddr {
		t.Errorf("ip %q, want %q", entry.IP, req.RemoteAddr)
	}
	if entry.UserAgent != "rbac-probe/1.0" {
		t.Errorf("user-agent %q, want the request UA", entry.UserAgent)
	}
}

// A revoked (or expired) admin session is looked up before it is refused.
// Writing user_id="" on that path makes every replay look like a token that
// never existed, so the operator cannot tell whose session was being probed.
func TestSessionAuth_RejectedKnownSessionNamesTheAdmin(t *testing.T) {
	repo := newCapturingAudit()
	logger := audit.NewLogger(repo, 0)

	sessions := newFakeSessionRepo()
	token := "tok-revoked-named"
	sessions.sessions["s1"] = &model.AdminSession{
		ID: "s1", AdminID: "admin-victim-9", TokenHash: hashSessionToken(token),
		ExpiresAt: time.Now().Add(time.Hour), Revoked: true,
	}

	reached := false
	guarded := SessionAuth(sessions, newFakeAdminRepo(), logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "session-replay/1.0")
	req.RemoteAddr = "127.0.0.1:5101"
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session returned %d, want 401", rec.Code)
	}
	if reached {
		t.Fatal("the guarded handler ran despite a session rejection")
	}
	entry := repo.last()
	if entry == nil {
		t.Fatal("session rejection wrote no audit row")
	}
	if entry.EventType != audit.AdminSessionRejected {
		t.Errorf("event %q, want %q", entry.EventType, audit.AdminSessionRejected)
	}
	if entry.UserID != "admin-victim-9" {
		t.Errorf("actor %q, want admin-victim-9 (the session's admin, not empty)", entry.UserID)
	}
	if got := entry.Metadata["reason"]; got != "session_revoked" {
		t.Errorf("reason = %v, want session_revoked", got)
	}
	if entry.IP != req.RemoteAddr {
		t.Errorf("ip %q, want %q", entry.IP, req.RemoteAddr)
	}
	if entry.UserAgent != "session-replay/1.0" {
		t.Errorf("user-agent %q, want the request UA", entry.UserAgent)
	}
}

// Same cancel-to-erase-the-trail attack on the session-token gate.
func TestSessionAuth_RejectionAuditSurvivesCanceledContext(t *testing.T) {
	repo := newCapturingAudit()
	logger := audit.NewLogger(repo, 0)

	reached := false
	guarded := SessionAuth(nil, nil, logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+string(make([]byte, 300)))
	req.RemoteAddr = "127.0.0.1:5102"
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("oversize token returned %d, want 401", rec.Code)
	}
	if reached {
		t.Fatal("the guarded handler ran despite a session rejection")
	}
	if repo.last() == nil {
		t.Fatal("session-token rejection wrote no audit row when the request context was canceled")
	}
}
