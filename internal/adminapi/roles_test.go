package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

func roleHandler(repo repository.AppRoleRepository) *Handler {
	h := &Handler{}
	if repo != nil {
		h.SetAppRoleRepo(repo)
	}
	return h
}

func TestAdminListRoles(t *testing.T) {
	h := roleHandler(&mocks.MockAppRoleRepo{
		ListFn: func(_ context.Context) ([]*model.AppRole, error) {
			return []*model.AppRole{{Name: "moderator", Namespace: "beon3"}, {Name: "user", Reserved: true}}, nil
		},
	})
	rec := httptest.NewRecorder()
	h.ListRoles(rec, httptest.NewRequest(http.MethodGet, "/admin/roles", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "moderator") || !strings.Contains(rec.Body.String(), "user") {
		t.Fatalf("catalog missing from response: %s", rec.Body.String())
	}
}

func TestAdminRoles_NilCatalogUnavailable(t *testing.T) {
	rec := httptest.NewRecorder()
	roleHandler(nil).ListRoles(rec, httptest.NewRequest(http.MethodGet, "/admin/roles", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil catalog should be 503, got %d", rec.Code)
	}
}

func TestAdminCreateRole(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		existing *model.AppRole
		want     int
	}{
		{"valid", `{"name":"beta_tester","namespace":"beon3"}`, nil, http.StatusCreated},
		{"invalid name", `{"name":"Bad Name"}`, nil, http.StatusBadRequest},
		{"reserved admin name", `{"name":"admin"}`, nil, http.StatusBadRequest},
		{"reserved super_admin", `{"name":"super_admin"}`, nil, http.StatusBadRequest},
		{"duplicate", `{"name":"moderator"}`, &model.AppRole{Name: "moderator"}, http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var created bool
			h := roleHandler(&mocks.MockAppRoleRepo{
				GetFn:    func(_ context.Context, _ string) (*model.AppRole, error) { return tt.existing, nil },
				CreateFn: func(_ context.Context, _ *model.AppRole) error { created = true; return nil },
			})
			rec := httptest.NewRecorder()
			h.CreateRole(rec, httptest.NewRequest(http.MethodPost, "/admin/roles", strings.NewReader(tt.body)))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want == http.StatusCreated && !created {
				t.Error("Create should have been called")
			}
			if tt.want != http.StatusCreated && created {
				t.Error("Create must NOT be called on rejected input")
			}
		})
	}
}

func TestAdminDeleteRole(t *testing.T) {
	t.Run("reserved refused", func(t *testing.T) {
		h := roleHandler(&mocks.MockAppRoleRepo{
			DeleteFn: func(_ context.Context, _ string) error { return repository.ErrRoleReserved },
		})
		req := httptest.NewRequest(http.MethodDelete, "/admin/roles/user", nil)
		req.SetPathValue("name", "user")
		rec := httptest.NewRecorder()
		h.DeleteRole(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("reserved delete should be 403, got %d", rec.Code)
		}
	})
	t.Run("custom deleted", func(t *testing.T) {
		h := roleHandler(&mocks.MockAppRoleRepo{
			DeleteFn: func(_ context.Context, _ string) error { return nil },
		})
		req := httptest.NewRequest(http.MethodDelete, "/admin/roles/beta_tester", nil)
		req.SetPathValue("name", "beta_tester")
		rec := httptest.NewRecorder()
		h.DeleteRole(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("custom delete should be 200, got %d", rec.Code)
		}
	})
}
