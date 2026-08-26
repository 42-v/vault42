package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
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
		ID: wantActor, Username: "actor", Role: "super_admin",
	}))
}

// The role catalog and the bulk-import endpoints mutate authorization state:
// CreateRole/DeleteRole change which strings a user JWT may assert, and
// ImportUsers creates accounts in bulk with pre-set credentials. Each writes an
// audit row on success, but wrote it with an empty actor, IP and user-agent
// so the record proved something happened while dropping the one fact asked
// first after an incident: which admin did it, from where. The row must
// attribute the action to the authenticated admin.
// wantActor is UUID-shaped, because audit.audit_log.user_id is UUID. The
// previous value was "adm-actor-1", which the column cannot hold either -- so a
// mock that accepts any string let a handler pass a username here and stay green
// while the real insert failed 22P02 and the row never existed. Asserting the
// shape is what makes this gate about the column rather than about equality.
const wantActor = "7e2f9a10-2222-4000-8000-0000000000ab"

var actorUUIDShape = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func TestPrivilegedMutations_AuditAttributeTheActor(t *testing.T) {
	const wantIP = "203.0.113.7:5555"
	const wantUA = "audit-probe/1.0"

	assertAttributed := func(t *testing.T, e *model.AuditEntry) {
		t.Helper()
		if e.UserID != wantActor {
			t.Errorf("audit %s: actor = %q, want %q, no record of which admin made the change", e.EventType, e.UserID, wantActor)
		}
		// The column is UUID. A username here is not a value it can hold: the
		// insert fails 22P02, the error is discarded as best-effort, and the
		// handler still answers 200 -- so the trail is silently empty for
		// exactly the route somebody would want it for.
		if !actorUUIDShape.MatchString(e.UserID) {
			t.Errorf("audit %s: actor = %q is not UUID-shaped, and audit.audit_log.user_id is "+
				"UUID -- this row cannot be stored", e.EventType, e.UserID)
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

	// The email plane. These four are why the shape assertion above exists: they
	// were the only audit call sites in the package passing a username instead of
	// an id, so every row they wrote failed 22P02 and vanished, while the handler
	// answered 200. email:write rewrites the body of password-reset and
	// verification mail for every user of an app, which makes this the route in
	// the admin API whose trail matters most and the one that had none.
	t.Run("email branding set", func(t *testing.T) {
		var got []*model.AuditEntry
		h := &Handler{emailBranding: newFakeBrandingRepo(), auditLog: captureAudit(&got)}
		rec := httptest.NewRecorder()
		h.PutEmailBranding(rec, withPathValue(
			actorReq(http.MethodPut, "/admin/email-branding/acme", `{"app_name":"Acme"}`),
			map[string]string{"app": "acme"}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
		}
		if len(got) != 1 {
			t.Fatalf("audit rows = %d, want 1", len(got))
		}
		assertAttributed(t, got[0])
	})

	t.Run("email branding delete", func(t *testing.T) {
		var got []*model.AuditEntry
		repo := newFakeBrandingRepo()
		h := &Handler{emailBranding: repo, auditLog: captureAudit(&got)}
		rec := httptest.NewRecorder()
		h.DeleteEmailBranding(rec, withPathValue(
			actorReq(http.MethodDelete, "/admin/email-branding/acme", ""),
			map[string]string{"app": "acme"}))
		if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
		}
		if len(got) != 1 {
			t.Fatalf("audit rows = %d, want 1", len(got))
		}
		assertAttributed(t, got[0])
	})

	t.Run("email template set", func(t *testing.T) {
		var got []*model.AuditEntry
		h := &Handler{emailTemplates: newFakeTemplateRepo(), auditLog: captureAudit(&got)}
		rec := httptest.NewRecorder()
		h.PutEmailTemplate(rec, withPathValue(
			actorReq(http.MethodPut, "/admin/email-templates/acme/verification", `{"subject":"Hi","html_content":"<p>Hi</p>"}`),
			map[string]string{"app": "acme", "name": "verification"}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
		}
		if len(got) != 1 {
			t.Fatalf("audit rows = %d, want 1", len(got))
		}
		assertAttributed(t, got[0])
	})

	t.Run("email template delete", func(t *testing.T) {
		var got []*model.AuditEntry
		h := &Handler{emailTemplates: newFakeTemplateRepo(), auditLog: captureAudit(&got)}
		rec := httptest.NewRecorder()
		h.DeleteEmailTemplate(rec, withPathValue(
			actorReq(http.MethodDelete, "/admin/email-templates/acme/verification", ""),
			map[string]string{"app": "acme", "name": "verification"}))
		if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
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
