package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// captureAudit returns an immediate-mode logger that records every entry it is
// handed, so a test can assert not just that a privileged action was audited
// but who the row attributes it to.
func captureAudit(entries *[]*model.AuditEntry) *audit.Logger {
	repo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			*entries = append(*entries, e)
			return nil
		},
	}
	return audit.NewLogger(repo, 0)
}

// actorReq attaches a known admin plus a request IP and user-agent, the three
// facts an audit row must carry to answer "who did this, from where".
func actorReq(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.7:5555"
	r.Header.Set("User-Agent", "audit-probe/1.0")
	return r.WithContext(WithAdmin(r.Context(), &model.AdminUser{
		ID: "adm-actor-1", Username: "actor", Role: "super_admin",
	}))
}

// The role catalog and the bulk-import endpoints mutate authorization state:
// CreateRole/DeleteRole change which strings a user JWT may assert, and
// ImportUsers creates accounts in bulk with pre-set credentials. Each writes an
// audit row on success, but wrote it with an empty actor, IP and user-agent —
// so the record proved something happened while dropping the one fact asked
// first after an incident: which admin did it, from where. The row must
// attribute the action to the authenticated admin.
func TestPrivilegedMutations_AuditAttributeTheActor(t *testing.T) {
	const wantActor = "adm-actor-1"
	const wantIP = "203.0.113.7:5555"
	const wantUA = "audit-probe/1.0"

	assertAttributed := func(t *testing.T, e *model.AuditEntry) {
		t.Helper()
		if e.UserID != wantActor {
			t.Errorf("audit %s: actor = %q, want %q — no record of which admin made the change", e.EventType, e.UserID, wantActor)
		}
		if e.IP != wantIP {
			t.Errorf("audit %s: ip = %q, want %q", e.EventType, e.IP, wantIP)
		}
		if e.UserAgent != wantUA {
			t.Errorf("audit %s: user_agent = %q, want %q", e.EventType, e.UserAgent, wantUA)
		}
	}

	t.Run("role create", func(t *testing.T) {
		var got []*model.AuditEntry
		h := &Handler{
			appRoles: &mocks.MockAppRoleRepo{
				GetFn:    func(context.Context, string) (*model.AppRole, error) { return nil, nil },
				CreateFn: func(context.Context, *model.AppRole) error { return nil },
			},
			auditLog: captureAudit(&got),
		}
		rec := httptest.NewRecorder()
		h.CreateRole(rec, actorReq(http.MethodPost, "/admin/roles", `{"name":"editor"}`))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
		}
		if len(got) != 1 {
			t.Fatalf("audit rows = %d, want 1", len(got))
		}
		assertAttributed(t, got[0])
	})

	t.Run("role delete", func(t *testing.T) {
		var got []*model.AuditEntry
		h := &Handler{
			appRoles: &mocks.MockAppRoleRepo{
				DeleteFn: func(context.Context, string) error { return nil },
			},
			auditLog: captureAudit(&got),
		}
		req := actorReq(http.MethodDelete, "/admin/roles/editor", "")
		req.SetPathValue("name", "editor")
		rec := httptest.NewRecorder()
		h.DeleteRole(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
		}
		if len(got) != 1 {
			t.Fatalf("audit rows = %d, want 1", len(got))
		}
		assertAttributed(t, got[0])
	})

	t.Run("users import", func(t *testing.T) {
		var got []*model.AuditEntry
		h := &Handler{
			users: &mocks.MockUserRepo{
				GetByEmailFn:     func(context.Context, string) (*model.User, error) { return nil, nil },
				CreateImportedFn: func(context.Context, *model.User) error { return nil },
			},
			auditLog: captureAudit(&got),
		}
		rec := httptest.NewRecorder()
		h.ImportUsers(rec, actorReq(http.MethodPost, "/admin/users/import",
			`{"source":"legacy","users":[{"email":"m@example.com"}]}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
		}
		if len(got) != 1 {
			t.Fatalf("audit rows = %d, want 1", len(got))
		}
		assertAttributed(t, got[0])
	})
}
