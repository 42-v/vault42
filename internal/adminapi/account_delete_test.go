package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

func newTestErasureService(users *mocks.MockUserRepo) *service.ErasureService {
	return service.NewErasureService(
		users, &mocks.MockIdentityRepo{}, &mocks.MockBlobRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockSocialAccountRepo{}, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockAccountRecoveryRepo{}, testAuditLog(), nil, nil,
	)
}

func TestHandler_DeleteUser(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		withErasure bool
		users       *mocks.MockUserRepo
		want        int
	}{
		{"missing id", "", true, nil, http.StatusBadRequest},
		{"erasure unavailable", "u1", false, nil, http.StatusServiceUnavailable},
		{
			name: "not found", id: "u1", withErasure: true,
			users: &mocks.MockUserRepo{GetByIDFn: func(context.Context, string) (*model.User, error) { return nil, nil }},
			want:  http.StatusNotFound,
		},
		{
			name: "success", id: "u1", withErasure: true,
			users: &mocks.MockUserRepo{GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "user@example.com"}, nil
			}},
			want: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := tt.users
			if users == nil {
				users = &mocks.MockUserRepo{}
			}
			h := newTestHandler(nil, users, nil, nil)
			if tt.withErasure {
				h.SetErasureService(newTestErasureService(users))
			}

			rec := httptest.NewRecorder()
			r := withActor(httptest.NewRequest(http.MethodDelete, "/admin/users/"+tt.id, nil))
			if tt.id != "" {
				r.SetPathValue("id", tt.id)
			}
			h.DeleteUser(rec, r)

			if rec.Code != tt.want {
				t.Errorf("code=%d want=%d body=%s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestHandler_DeleteUser_Cascades(t *testing.T) {
	scrubbed := false
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
		SoftDeleteScrubFn: func(context.Context, string, string) error {
			scrubbed = true
			return nil
		},
	}
	h := newTestHandler(nil, users, nil, nil)
	h.SetErasureService(newTestErasureService(users))

	rec := httptest.NewRecorder()
	r := withActor(httptest.NewRequest(http.MethodDelete, "/admin/users/u1", nil))
	r.SetPathValue("id", "u1")
	h.DeleteUser(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !scrubbed {
		t.Error("expected the user row to be scrubbed/soft-deleted")
	}
}
