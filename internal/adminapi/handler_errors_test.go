package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// The admin gateway is the break-glass surface: it is what an operator reaches
// for during an incident. A list endpoint that swallows a repository failure and
// returns an empty 200 tells them "there are no active admin sessions" or "there
// are no clients" — which is exactly the wrong answer to be given while
// responding to a compromise.
func TestAdminListEndpoints_SurfaceRepositoryFailures(t *testing.T) {
	boom := errors.New("db down")

	t.Run("ListSessions", func(t *testing.T) {
		h := &Handler{
			sessions: &stubAdminSessionRepo{
				listActiveFn: func(context.Context) ([]*model.AdminSession, error) { return nil, boom },
			},
		}
		rec := httptest.NewRecorder()
		h.ListSessions(rec, httptest.NewRequest(http.MethodGet, "/admin/sessions", nil))

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500 — a failed lookup must not read as 'no active sessions'", rec.Code)
		}
	})

	t.Run("ListClients", func(t *testing.T) {
		h := &Handler{
			clients: &mocks.MockClientRepo{
				ListFn: func(context.Context) ([]*model.Client, error) { return nil, boom },
			},
		}
		rec := httptest.NewRecorder()
		h.ListClients(rec, httptest.NewRequest(http.MethodGet, "/admin/clients", nil))

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", rec.Code)
		}
	})
}

// An empty result is not a failure, and must not be reported as one — nor may it
// serialise as a null that a client would choke on.
func TestAdminListEndpoints_EmptyIsNotAnError(t *testing.T) {
	t.Run("ListSessions", func(t *testing.T) {
		h := &Handler{
			sessions: &stubAdminSessionRepo{
				listActiveFn: func(context.Context) ([]*model.AdminSession, error) { return nil, nil },
			},
		}
		rec := httptest.NewRecorder()
		h.ListSessions(rec, httptest.NewRequest(http.MethodGet, "/admin/sessions", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if body := rec.Body.String(); !contains(body, "[]") {
			t.Errorf("empty session list did not serialise as []: %s", body)
		}
	})
}

// stubAdminSessionRepo: no shared mock exists for this repo.
type stubAdminSessionRepo struct {
	listActiveFn func(context.Context) ([]*model.AdminSession, error)
}

func (s *stubAdminSessionRepo) Create(context.Context, *model.AdminSession) error { return nil }
func (s *stubAdminSessionRepo) GetByTokenHash(context.Context, string) (*model.AdminSession, error) {
	return nil, nil
}
func (s *stubAdminSessionRepo) ListByAdmin(context.Context, string) ([]*model.AdminSession, error) {
	return nil, nil
}
func (s *stubAdminSessionRepo) ListActive(ctx context.Context) ([]*model.AdminSession, error) {
	if s.listActiveFn != nil {
		return s.listActiveFn(ctx)
	}
	return nil, nil
}
func (s *stubAdminSessionRepo) Revoke(context.Context, string) error            { return nil }
func (s *stubAdminSessionRepo) RevokeAllForAdmin(context.Context, string) error { return nil }
func (s *stubAdminSessionRepo) RevokeAll(context.Context) error                 { return nil }
func (s *stubAdminSessionRepo) DeleteExpired(context.Context) (int64, error)    { return 0, nil }

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
