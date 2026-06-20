package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// Roles catalog — error branches not exercised by roles_test.go
// ---------------------------------------------------------------------------

// ListRoles surfaces a repository failure as a 500.
func TestListRoles_RepoError500(t *testing.T) {
	h := roleHandler(&mocks.MockAppRoleRepo{
		ListFn: func(_ context.Context) ([]*model.AppRole, error) { return nil, errors.New("db down") },
	})
	rec := httptest.NewRecorder()
	h.ListRoles(rec, httptest.NewRequest(http.MethodGet, "/admin/roles", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// CreateRole rejects a malformed JSON body with a 400.
func TestCreateRole_InvalidJSON400(t *testing.T) {
	h := roleHandler(&mocks.MockAppRoleRepo{})
	rec := httptest.NewRecorder()
	h.CreateRole(rec, httptest.NewRequest(http.MethodPost, "/admin/roles", strings.NewReader("{not json")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// CreateRole maps a persistence failure on an otherwise-valid role to a 500.
func TestCreateRole_CreateError500(t *testing.T) {
	h := roleHandler(&mocks.MockAppRoleRepo{
		GetFn:    func(_ context.Context, _ string) (*model.AppRole, error) { return nil, nil },
		CreateFn: func(_ context.Context, _ *model.AppRole) error { return errors.New("db down") },
	})
	rec := httptest.NewRecorder()
	h.CreateRole(rec, httptest.NewRequest(http.MethodPost, "/admin/roles", strings.NewReader(`{"name":"beta_tester"}`)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// DeleteRole rejects an empty path name with a 400.
func TestDeleteRole_MissingName400(t *testing.T) {
	h := roleHandler(&mocks.MockAppRoleRepo{})
	req := httptest.NewRequest(http.MethodDelete, "/admin/roles/", nil)
	req.SetPathValue("name", "")
	rec := httptest.NewRecorder()
	h.DeleteRole(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// DeleteRole maps a non-reserved repository failure to a 500.
func TestDeleteRole_RepoError500(t *testing.T) {
	h := roleHandler(&mocks.MockAppRoleRepo{
		DeleteFn: func(_ context.Context, _ string) error { return errors.New("db down") },
	})
	req := httptest.NewRequest(http.MethodDelete, "/admin/roles/beta_tester", nil)
	req.SetPathValue("name", "beta_tester")
	rec := httptest.NewRecorder()
	h.DeleteRole(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// ImportUsers — error branches not exercised by import_test.go
// ---------------------------------------------------------------------------

// ImportUsers rejects a malformed JSON body with a 400.
func TestImportUsers_InvalidJSON400(t *testing.T) {
	h := importHandler(&mocks.MockUserRepo{})
	rec, _ := doImport(t, h, "{not json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// ImportUsers rejects a batch over the per-request cap with a 400.
func TestImportUsers_BatchTooLarge400(t *testing.T) {
	h := importHandler(&mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) { return nil, nil },
	})
	var b strings.Builder
	b.WriteString(`{"users":[`)
	for i := 0; i <= maxImportBatch; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"email":"user@example.com"}`)
	}
	b.WriteString(`]}`)
	rec, _ := doImport(t, h, b.String())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// ImportUsers reports a per-row create failure without failing the batch.
func TestImportUsers_CreateFailureReportedPerRow(t *testing.T) {
	h := importHandler(&mocks.MockUserRepo{
		GetByEmailFn:     func(_ context.Context, _ string) (*model.User, error) { return nil, nil },
		CreateImportedFn: func(_ context.Context, _ *model.User) error { return errors.New("db down") },
	})
	rec, out := doImport(t, h, `{"users":[{"email":"alice@example.com"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if out["imported"].(float64) != 0 {
		t.Fatalf("create failure must not count as imported, got %v", out["imported"])
	}
	if !strings.Contains(rec.Body.String(), "create_failed") {
		t.Fatalf("per-row error should be create_failed: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListUsers — query routing branches
// ---------------------------------------------------------------------------

// ListUsers returns an empty list (not an error) for a missing query.
func TestListUsers_EmptyQueryReturnsEmpty(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.ListUsers(rec, httptest.NewRequest(http.MethodGet, "/admin/users", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"users":[]`) {
		t.Fatalf("empty query should yield empty list: %s", rec.Body.String())
	}
}

// ListUsers treats a query that is neither a UUID nor an email as no match.
func TestListUsers_FreeformQueryNoMatch(t *testing.T) {
	called := false
	users := &mocks.MockUserRepo{
		GetByIDFn:    func(_ context.Context, _ string) (*model.User, error) { called = true; return nil, nil },
		GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) { called = true; return nil, nil },
	}
	h := newTestHandler(nil, users, nil, nil)
	rec := httptest.NewRecorder()
	h.ListUsers(rec, httptest.NewRequest(http.MethodGet, "/admin/users?q=plainword", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if called {
		t.Fatal("freeform query must not trigger a repository lookup")
	}
}

// ---------------------------------------------------------------------------
// LockUser — guard and repository error branches
// ---------------------------------------------------------------------------

// LockUser rejects an empty path id with a 400.
func TestLockUser_MissingID400_More(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	r := withActor(httptest.NewRequest(http.MethodPost, "/admin/users//lock", strings.NewReader(`{}`)))
	h.LockUser(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// LockUser maps a repository failure to a 500.
func TestLockUser_RepoError500_More(t *testing.T) {
	users := &mocks.MockUserRepo{
		LockUntilFn: func(_ context.Context, _ string, _ time.Time) error { return errors.New("db down") },
	}
	h := newTestHandler(nil, users, nil, nil)
	rec := httptest.NewRecorder()
	r := withActor(httptest.NewRequest(http.MethodPost, "/admin/users/u1/lock", strings.NewReader(`{"duration":"1h"}`)))
	r.SetPathValue("id", "u1")
	h.LockUser(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// QueryAudit — target user filter is threaded into the repository call
// ---------------------------------------------------------------------------

// QueryAudit forwards the user_id and event_type filters to the repository.
func TestQueryAudit_TargetFilterForwarded(t *testing.T) {
	var captured repository.AuditFilter
	auditRepo := &mocks.MockAuditRepo{QueryFn: func(_ context.Context, f repository.AuditFilter) ([]*model.AuditEntry, error) {
		captured = f
		return nil, nil
	}}
	h := newTestHandler(nil, nil, nil, auditRepo)
	rec := httptest.NewRecorder()
	h.QueryAudit(rec, httptest.NewRequest(http.MethodGet, "/admin/audit?user_id=u-42&event_type=login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if captured.UserID != "u-42" || captured.EventType != "login" {
		t.Fatalf("filter not forwarded: %+v", captured)
	}
}

// ---------------------------------------------------------------------------
// List endpoints — repository error mapping to 500
// ---------------------------------------------------------------------------

// ListClients maps a repository failure to a 500.
func TestListClients_RepoError500(t *testing.T) {
	clients := &mocks.MockClientRepo{ListFn: func(_ context.Context) ([]*model.Client, error) { return nil, errors.New("db down") }}
	h := newTestHandler(nil, nil, clients, nil)
	rec := httptest.NewRecorder()
	h.ListClients(rec, withActor(httptest.NewRequest(http.MethodGet, "/admin/clients", nil)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// GetConfig maps a repository failure to a 500.
func TestGetConfig_RepoError500(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	h.adminConfig = &mocks.MockAdminConfigRepo{ListFn: func(_ context.Context) (map[string]string, error) {
		return nil, errors.New("db down")
	}}
	rec := httptest.NewRecorder()
	h.GetConfig(rec, withActor(httptest.NewRequest(http.MethodGet, "/admin/config", nil)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// UpdateConfig rejects a path key that violates the key format with a 400.
func TestUpdateConfig_InvalidKeyFormat400(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	r := withActor(jsonReq(http.MethodPut, "/admin/config/key", `{"value":"x"}`))
	r.SetPathValue("key", "bad key")
	h.UpdateConfig(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// UpdateConfig maps a persistence failure on a valid key to a 500.
func TestUpdateConfig_SetError500(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	h.adminConfig = &mocks.MockAdminConfigRepo{SetFn: func(_ context.Context, _, _ string) error { return errors.New("db down") }}
	rec := httptest.NewRecorder()
	r := withActor(jsonReq(http.MethodPut, "/admin/config/feature_flag", `{"value":"on"}`))
	r.SetPathValue("key", "feature_flag")
	h.UpdateConfig(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// DeleteConfig maps a persistence failure to a 500.
func TestDeleteConfig_RepoError500(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	h.adminConfig = &mocks.MockAdminConfigRepo{DeleteFn: func(_ context.Context, _ string) error { return errors.New("db down") }}
	rec := httptest.NewRecorder()
	r := withActor(httptest.NewRequest(http.MethodDelete, "/admin/config/feature_flag", nil))
	r.SetPathValue("key", "feature_flag")
	h.DeleteConfig(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// RevokeAdmin refuses an actor revoking their own account with a 400.
func TestRevokeAdmin_SelfRevoke400(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	actor := &model.AdminUser{ID: "self-id", Username: "actor", Role: "super_admin"}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/admins/self-id/revoke", nil).
		WithContext(WithAdmin(context.Background(), actor))
	r.SetPathValue("id", "self-id")
	h.RevokeAdmin(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// RevokeAdmin maps a repository failure to a 500.
func TestRevokeAdmin_RepoError500(t *testing.T) {
	h := newTestHandler(&fakeAdminRepo{errRevoke: errors.New("db down")}, nil, nil, nil)
	rec := httptest.NewRecorder()
	r := withActor(httptest.NewRequest(http.MethodPost, "/admin/admins/other-id/revoke", nil))
	r.SetPathValue("id", "other-id")
	h.RevokeAdmin(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
