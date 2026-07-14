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

// Creating and deleting an application role changes who can do what. Both are audited, and
// the audit write is on the success path — which is precisely the path the existing tests
// never took, because they only ever drove these endpoints with a nil store or a failure.
//
// An unaudited role change is an authorisation change with no record of who made it, which
// is the one question asked first after an incident.
func TestRoleEndpoints_SuccessIsAudited(t *testing.T) {
	var events []string
	auditRepo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			events = append(events, e.EventType)
			return nil
		},
	}

	roles := &mocks.MockAppRoleRepo{
		CreateFn: func(context.Context, *model.AppRole) error { return nil },
		DeleteFn: func(context.Context, string) error { return nil },
		GetFn:    func(context.Context, string) (*model.AppRole, error) { return nil, nil },
	}

	h := &Handler{appRoles: roles, auditLog: audit.NewLogger(auditRepo, 0)}

	t.Run("create", func(t *testing.T) {
		body := strings.NewReader(`{"name":"editor","description":"can edit"}`)
		req := adminCtx(httptest.NewRequest(http.MethodPost, "/admin/roles", body))
		rec := httptest.NewRecorder()

		h.CreateRole(rec, req)

		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("delete", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/admin/roles/editor", nil)
		req.SetPathValue("name", "editor")
		rec := httptest.NewRecorder()

		h.DeleteRole(rec, adminCtx(req))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
		}
	})

	if len(events) < 2 {
		t.Errorf("role changes were not audited: %v — an authorisation change with no record of who made it", events)
	}
}

// Account import is the BeOn3 cutover path: it creates accounts in bulk from a legacy
// system. The import is audited on success, and that record is the only evidence of which
// accounts arrived from where — the provenance that decides, later, whether an imported
// marketing flag may be acted on at all.
//
// An import that ran without leaving that record would put accounts in the vault with no
// documented origin.
func TestImportUsers_SuccessIsAudited(t *testing.T) {
	var events []string
	auditRepo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			events = append(events, e.EventType)
			return nil
		},
	}

	created := 0
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
		CreateImportedFn: func(context.Context, *model.User) error {
			created++
			return nil
		},
	}

	h := &Handler{users: users, auditLog: audit.NewLogger(auditRepo, 0)}

	body := strings.NewReader(`{"source":"legacy","users":[{"email":"migrated@example.com","legacy_id":"L-1"}]}`)
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/admin/import", body))
	rec := httptest.NewRecorder()

	h.ImportUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	if created != 1 {
		t.Fatalf("imported %d accounts, want 1", created)
	}

	found := false
	for _, e := range events {
		if strings.Contains(e, "import") {
			found = true
		}
	}
	if !found {
		t.Errorf("the import left no audit record: %v — accounts would exist with no documented origin", events)
	}
}
