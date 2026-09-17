package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/tests/mocks"
)

// rolesHandler wires a handler whose user exists and whose catalog holds the
// four names these tests assign from.
func rolesHandler(t *testing.T, users *mocks.MockUserRepo, catalog *mocks.MockAppRoleRepo) (*Handler, *[]*model.AuditEntry) {
	t.Helper()
	var captured []*model.AuditEntry
	auditRepo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			captured = append(captured, e)
			return nil
		},
	}
	if users == nil {
		users = &mocks.MockUserRepo{}
	}
	if users.GetByIDFn == nil {
		users.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "u@example.com", Roles: []string{"user"}}, nil
		}
	}
	if catalog == nil {
		catalog = &mocks.MockAppRoleRepo{}
	}
	if catalog.ListNamesFn == nil {
		catalog.ListNamesFn = func(context.Context) ([]string, error) {
			return []string{"user", "viewer", "moderator", "premium_user"}, nil
		}
	}
	// NewHandler directly rather than newTestHandler: that helper builds its own
	// logger and would drop the rows these tests read.
	h := NewHandler(users, &mocks.MockClientRepo{}, &mocks.MockRefreshTokenRepo{}, auditRepo,
		newFakeAdminRepo(), newFakeSessionRepo(), &mocks.MockAdminConfigRepo{}, nil,
		audit.NewLogger(auditRepo, 0), make([]byte, 32), "")
	h.SetAppRoleRepo(catalog)
	return h, &captured
}

func rolesReq(id, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/admin/users/"+id+"/roles", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if id != "" {
		r.SetPathValue("id", id)
	}
	return r.WithContext(WithAdmin(r.Context(), &model.AdminUser{
		ID: "adm-1", Username: "root", Role: string(rbac.RoleSuperAdmin),
	}))
}

func TestSetUserRoles_ReplacesTheSetAndAuditsBothSides(t *testing.T) {
	var got []string
	users := &mocks.MockUserRepo{
		SetRolesFn: func(_ context.Context, _ string, roles []string) error {
			got = roles
			return nil
		},
	}
	h, captured := rolesHandler(t, users, nil)

	rec := httptest.NewRecorder()
	h.SetUserRoles(rec, rolesReq("user-1", `{"roles":["moderator","premium_user"]}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if len(got) != 2 || got[0] != "moderator" || got[1] != "premium_user" {
		t.Fatalf("wrote %v", got)
	}

	// The row has to answer "who changed it and from what", because the users
	// table already answers "what is it now".
	if len(*captured) != 1 {
		t.Fatalf("recorded %d audit entries, want 1", len(*captured))
	}
	e := (*captured)[0]
	if e.EventType != audit.AdminUserRolesSet {
		t.Errorf("event = %q", e.EventType)
	}
	if e.UserID != "adm-1" {
		t.Errorf("actor = %q, want the admin", e.UserID)
	}
	from, _ := e.Metadata["from"].([]string)
	to, _ := e.Metadata["to"].([]string)
	if len(from) != 1 || from[0] != "user" {
		t.Errorf("from = %v, want the roles the user had", e.Metadata["from"])
	}
	if len(to) != 2 {
		t.Errorf("to = %v", e.Metadata["to"])
	}
}

// An empty set is a legitimate request: it is how an admin removes every role.
func TestSetUserRoles_AcceptsAnEmptySet(t *testing.T) {
	called := false
	users := &mocks.MockUserRepo{
		SetRolesFn: func(_ context.Context, _ string, roles []string) error {
			called = true
			if len(roles) != 0 {
				t.Errorf("roles = %v, want empty", roles)
			}
			return nil
		},
	}
	h, _ := rolesHandler(t, users, nil)
	rec := httptest.NewRecorder()
	h.SetUserRoles(rec, rolesReq("user-1", `{"roles":[]}`))
	if rec.Code != http.StatusOK || !called {
		t.Fatalf("status = %d called = %v", rec.Code, called)
	}
}

// A repeated name is not an error -- the caller asked for a set and sent a list
// -- but it must not reach the column twice, because nothing downstream
// deduplicates and the claim would carry it twice too.
func TestSetUserRoles_DeduplicatesInOrder(t *testing.T) {
	var got []string
	users := &mocks.MockUserRepo{
		SetRolesFn: func(_ context.Context, _ string, roles []string) error { got = roles; return nil },
	}
	h, _ := rolesHandler(t, users, nil)
	rec := httptest.NewRecorder()
	h.SetUserRoles(rec, rolesReq("user-1", `{"roles":["moderator","user","moderator"]}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if len(got) != 2 || got[0] != "moderator" || got[1] != "user" {
		t.Fatalf("wrote %v, want [moderator user]", got)
	}
}

func TestSetUserRoles_RefusesTheNamesItMust(t *testing.T) {
	cases := []struct {
		name, body, wantCode string
		status               int
	}{
		{"admin tier", `{"roles":["admin"]}`, "reserved_role_name", http.StatusBadRequest},
		{"super_admin tier", `{"roles":["super_admin"]}`, "reserved_role_name", http.StatusBadRequest},
		{"off catalog", `{"roles":["not_in_catalog"]}`, "unknown_role", http.StatusBadRequest},
		{"bad shape", `{"roles":["Moderator"]}`, "invalid_role_name", http.StatusBadRequest},
		{"empty name", `{"roles":[""]}`, "invalid_role_name", http.StatusBadRequest},
		{"not json", `{`, "invalid_request", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			users := &mocks.MockUserRepo{
				SetRolesFn: func(context.Context, string, []string) error {
					t.Fatal("a refused request reached the repository")
					return nil
				},
			}
			h, _ := rolesHandler(t, users, nil)
			rec := httptest.NewRecorder()
			h.SetUserRoles(rec, rolesReq("user-1", tc.body))
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantCode) {
				t.Fatalf("body = %s, want %s", rec.Body.String(), tc.wantCode)
			}
		})
	}
}

func TestSetUserRoles_RefusesAnOversizedSet(t *testing.T) {
	names := make([]string, 0, maxRolesPerUser+1)
	for i := 0; i <= maxRolesPerUser; i++ {
		names = append(names, `"user"`)
	}
	h, _ := rolesHandler(t, nil, nil)
	rec := httptest.NewRecorder()
	h.SetUserRoles(rec, rolesReq("user-1", `{"roles":[`+strings.Join(names, ",")+`]}`))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "too_many_roles") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

// Assigning a name the catalog does not hold is worse than refusing it:
// RoleCatalog.Filter is fail-open and drops unknown names at issuance, so the
// role would sit in the users table looking granted and never reach a token.
// With no catalog wired there is nothing to check against, so the route is
// unavailable rather than permissive.
func TestSetUserRoles_RequiresTheCatalog(t *testing.T) {
	h := newTestHandler(nil, &mocks.MockUserRepo{}, nil, nil)
	rec := httptest.NewRecorder()
	h.SetUserRoles(rec, rolesReq("user-1", `{"roles":["user"]}`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "roles_catalog_unavailable") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestSetUserRoles_UnknownUserIs404(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) { return nil, nil },
	}
	h, _ := rolesHandler(t, users, nil)
	rec := httptest.NewRecorder()
	h.SetUserRoles(rec, rolesReq("ghost", `{"roles":["user"]}`))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

func TestSetUserRoles_MissingIDIs400(t *testing.T) {
	h, _ := rolesHandler(t, nil, nil)
	rec := httptest.NewRecorder()
	h.SetUserRoles(rec, rolesReq("", `{"roles":["user"]}`))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "missing_id") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestSetUserRoles_StoreFailuresAre500(t *testing.T) {
	t.Run("catalog read", func(t *testing.T) {
		catalog := &mocks.MockAppRoleRepo{
			ListNamesFn: func(context.Context) ([]string, error) { return nil, errors.New("boom") },
		}
		h, _ := rolesHandler(t, nil, catalog)
		rec := httptest.NewRecorder()
		h.SetUserRoles(rec, rolesReq("user-1", `{"roles":["user"]}`))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})
	t.Run("user lookup", func(t *testing.T) {
		users := &mocks.MockUserRepo{
			GetByIDFn: func(context.Context, string) (*model.User, error) { return nil, errors.New("boom") },
		}
		h, _ := rolesHandler(t, users, nil)
		rec := httptest.NewRecorder()
		h.SetUserRoles(rec, rolesReq("user-1", `{"roles":["user"]}`))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})
	t.Run("write", func(t *testing.T) {
		users := &mocks.MockUserRepo{
			SetRolesFn: func(context.Context, string, []string) error { return errors.New("boom") },
		}
		h, _ := rolesHandler(t, users, nil)
		rec := httptest.NewRecorder()
		h.SetUserRoles(rec, rolesReq("user-1", `{"roles":["user"]}`))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})
}
