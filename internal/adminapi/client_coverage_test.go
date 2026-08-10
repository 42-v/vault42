package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

func TestGetClient(t *testing.T) {
	tests := []struct {
		name string
		id   string
		mock *mocks.MockClientRepo
		want int
	}{
		{
			name: "found",
			id:   "c1",
			mock: &mocks.MockClientRepo{GetByIDFn: func(context.Context, string) (*model.Client, error) {
				return &model.Client{ID: "c1", Name: "frontend"}, nil
			}},
			want: http.StatusOK,
		},
		{
			name: "not found",
			id:   "ghost",
			mock: &mocks.MockClientRepo{GetByIDFn: func(context.Context, string) (*model.Client, error) {
				return nil, nil
			}},
			want: http.StatusNotFound,
		},
		{
			name: "repo error",
			id:   "c1",
			mock: &mocks.MockClientRepo{GetByIDFn: func(context.Context, string) (*model.Client, error) {
				return nil, errors.New("db down")
			}},
			want: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{clients: tt.mock}
			r := withPathValue(adminReq(http.MethodGet, "/admin/clients/"+tt.id, ""), map[string]string{"id": tt.id})
			rec := httptest.NewRecorder()
			h.GetClient(rec, r)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}

	t.Run("missing id", func(t *testing.T) {
		h := &Handler{clients: &mocks.MockClientRepo{}}
		rec := httptest.NewRecorder()
		h.GetClient(rec, withPathValue(adminReq(http.MethodGet, "/x", ""), map[string]string{"id": ""}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("missing id = %d, want 400", rec.Code)
		}
	})
}

func TestListClients(t *testing.T) {
	t.Run("returns client views", func(t *testing.T) {
		h := &Handler{clients: &mocks.MockClientRepo{ListFn: func(context.Context) ([]*model.Client, error) {
			return []*model.Client{
				{ID: "c1", Name: "frontend", Role: "frontend", Scopes: []string{"user:read"}, Active: true},
				{ID: "c2", Name: "worker", Role: "service"},
			}, nil
		}}}
		rec := httptest.NewRecorder()
		h.ListClients(rec, adminReq(http.MethodGet, "/admin/clients", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "frontend") || !strings.Contains(body, "worker") {
			t.Errorf("body missing clients: %s", body)
		}
	})

	t.Run("repo error is 500", func(t *testing.T) {
		h := &Handler{clients: &mocks.MockClientRepo{ListFn: func(context.Context) ([]*model.Client, error) {
			return nil, errors.New("db down")
		}}}
		rec := httptest.NewRecorder()
		h.ListClients(rec, adminReq(http.MethodGet, "/admin/clients", ""))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})
}

func TestRotateClientSecret(t *testing.T) {
	t.Run("success returns a new secret", func(t *testing.T) {
		updated := false
		h := &Handler{
			clients: &mocks.MockClientRepo{
				GetByIDFn: func(context.Context, string) (*model.Client, error) {
					return &model.Client{ID: "c1", Name: "frontend"}, nil
				},
				UpdateFn: func(context.Context, *model.Client) error { updated = true; return nil },
			},
			auditLog: testAuditLogger(),
		}
		rec := httptest.NewRecorder()
		h.RotateClientSecret(rec, withPathValue(adminReq(http.MethodPost, "/x", ""), map[string]string{"id": "c1"}))
		if rec.Code != http.StatusOK || !updated {
			t.Fatalf("status = %d, updated = %v", rec.Code, updated)
		}
	})

	t.Run("missing id and not found", func(t *testing.T) {
		h := &Handler{clients: &mocks.MockClientRepo{GetByIDFn: func(context.Context, string) (*model.Client, error) { return nil, nil }}, auditLog: testAuditLogger()}
		rec := httptest.NewRecorder()
		h.RotateClientSecret(rec, withPathValue(adminReq(http.MethodPost, "/x", ""), map[string]string{"id": ""}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("missing id = %d, want 400", rec.Code)
		}
		rec = httptest.NewRecorder()
		h.RotateClientSecret(rec, withPathValue(adminReq(http.MethodPost, "/x", ""), map[string]string{"id": "ghost"}))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("not found = %d, want 404", rec.Code)
		}
	})
}

func TestRevokeClient(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		called := false
		h := &Handler{
			clients:  &mocks.MockClientRepo{DeactivateFn: func(context.Context, string) error { called = true; return nil }},
			auditLog: testAuditLogger(),
		}
		rec := httptest.NewRecorder()
		h.RevokeClient(rec, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"id": "c1"}))
		if rec.Code != http.StatusOK || !called {
			t.Fatalf("status = %d, deactivate called = %v", rec.Code, called)
		}
	})

	t.Run("missing id", func(t *testing.T) {
		h := &Handler{clients: &mocks.MockClientRepo{}, auditLog: testAuditLogger()}
		rec := httptest.NewRecorder()
		h.RevokeClient(rec, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"id": ""}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("missing id = %d, want 400", rec.Code)
		}
	})

	t.Run("repo error", func(t *testing.T) {
		h := &Handler{
			clients:  &mocks.MockClientRepo{DeactivateFn: func(context.Context, string) error { return errors.New("db down") }},
			auditLog: testAuditLogger(),
		}
		rec := httptest.NewRecorder()
		h.RevokeClient(rec, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"id": "c1"}))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("repo error = %d, want 500", rec.Code)
		}
	})
}
