package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

func importHandler(users *mocks.MockUserRepo) *Handler {
	return &Handler{users: users}
}

func doImport(t *testing.T, h *Handler, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/users/import", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ImportUsers(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestImportUsers(t *testing.T) {
	t.Run("imports new accounts and strips admin roles", func(t *testing.T) {
		var created []*model.User
		h := importHandler(&mocks.MockUserRepo{
			GetByEmailFn:     func(_ context.Context, _ string) (*model.User, error) { return nil, nil },
			CreateImportedFn: func(_ context.Context, u *model.User) error { created = append(created, u); return nil },
		})
		body := `{"source":"legacy","users":[
			{"email":"A@legacy.test","roles":["moderator","admin"],"banned":true,"ban_reason":"x","legacy_id":"00000000-0000-0000-0000-000000000009"}
		]}`
		rec, out := doImport(t, h, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if out["imported"].(float64) != 1 {
			t.Fatalf("expected 1 imported, got %v", out["imported"])
		}
		if len(created) != 1 {
			t.Fatalf("expected 1 CreateImported, got %d", len(created))
		}
		u := created[0]
		if u.Email != "a@legacy.test" {
			t.Errorf("email should be lowercased: %q", u.Email)
		}
		if len(u.Roles) != 1 || u.Roles[0] != "moderator" {
			t.Errorf("admin role must be stripped, got %v", u.Roles)
		}
		if u.ImportedFrom != "legacy" || !u.Banned {
			t.Errorf("provenance/flags lost: %+v", u)
		}
	})

	t.Run("skips existing email (idempotent)", func(t *testing.T) {
		var createCalls int
		h := importHandler(&mocks.MockUserRepo{
			GetByEmailFn:     func(_ context.Context, _ string) (*model.User, error) { return &model.User{ID: "exists"}, nil },
			CreateImportedFn: func(_ context.Context, _ *model.User) error { createCalls++; return nil },
		})
		rec, out := doImport(t, h, `{"users":[{"email":"dup@x.test"}]}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d", rec.Code)
		}
		if out["imported"].(float64) != 0 || createCalls != 0 {
			t.Fatalf("existing email must be skipped, not created (imported=%v calls=%d)", out["imported"], createCalls)
		}
	})

	t.Run("invalid email reported per-row", func(t *testing.T) {
		h := importHandler(&mocks.MockUserRepo{})
		rec, out := doImport(t, h, `{"users":[{"email":"not-an-email"}]}`)
		if rec.Code != http.StatusOK || out["imported"].(float64) != 0 {
			t.Fatalf("invalid email should import 0 (status=%d out=%v)", rec.Code, out)
		}
	})

	t.Run("empty batch rejected", func(t *testing.T) {
		h := importHandler(&mocks.MockUserRepo{})
		rec, _ := doImport(t, h, `{"users":[]}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("empty batch should be 400, got %d", rec.Code)
		}
	})
}
