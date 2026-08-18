package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// An operator must not be able to impose a state they cannot read back.
//
// POST /admin/users/{id}/require-password-reset writes must_reset_password and
// .../clear-password-reset withdraws it, and for both of them GET
// /admin/users/{id} answered as though nothing had happened. Both routes are
// audited, so the state was recoverable -- by replaying an audit log, which is
// not what "read the user" means, and which an operator resolving an escalation
// at three in the morning is not going to do.
//
// Driven through the write routes rather than by setting the field, so a change
// to what the routes write is caught here rather than leaving a test that agrees
// with itself.
func TestAdminImposedPasswordResetIsReadableBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route func(h *Handler, w http.ResponseWriter, r *http.Request)
		want  bool
	}{
		{"imposed", (*Handler).RequirePasswordReset, true},
		{"withdrawn", (*Handler).ClearPasswordReset, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := &model.User{
				ID:            "00000000-0000-0000-0000-0000000000a1",
				Email:         "subject@x.test",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				// Start on the opposite side of the flag, so a route that
				// writes nothing at all cannot pass by leaving it where it was.
				MustResetPassword: !tc.want,
			}
			users := &mocks.MockUserRepo{
				GetByIDFn: func(_ context.Context, _ string) (*model.User, error) { return user, nil },
				SetMustResetPwFn: func(_ context.Context, _ string, required bool) error {
					user.MustResetPassword = required
					return nil
				},
			}
			h := newTestHandler(nil, users, nil, nil)

			write := httptest.NewRequest(http.MethodPost, "/admin/users/"+user.ID+"/x", nil)
			write.SetPathValue("id", user.ID)
			wrec := httptest.NewRecorder()
			tc.route(h, wrec, withActor(write))
			if wrec.Code != http.StatusOK {
				t.Fatalf("write route returned %d, want 200: %s", wrec.Code, wrec.Body.String())
			}

			read := httptest.NewRequest(http.MethodGet, "/admin/users/"+user.ID, nil)
			read.SetPathValue("id", user.ID)
			rrec := httptest.NewRecorder()
			h.GetUser(rrec, withActor(read))
			if rrec.Code != http.StatusOK {
				t.Fatalf("GetUser returned %d, want 200: %s", rrec.Code, rrec.Body.String())
			}

			var body map[string]any
			if err := json.Unmarshal(rrec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode GetUser body: %v", err)
			}
			got, present := body["must_reset_password"]
			if !present {
				t.Fatalf("GET /admin/users/{id} does not carry must_reset_password at all, so an "+
					"operator who just called the %s route cannot see what they did. Body: %s",
					tc.name, rrec.Body.String())
			}
			if got != tc.want {
				t.Errorf("must_reset_password = %v after the %s route, want %v", got, tc.name, tc.want)
			}
		})
	}
}

// The lookup answers with the same record, so an operator who searches by email
// rather than by id is not shown a different account state.
func TestAdminUserLookupCarriesTheSameStateAsTheDetailRead(t *testing.T) {
	user := &model.User{
		ID:                "00000000-0000-0000-0000-0000000000a2",
		Email:             "subject@x.test",
		EmailVerified:     true,
		CreatedAt:         time.Now(),
		MustResetPassword: true,
	}
	users := &mocks.MockUserRepo{
		GetByIDFn:    func(_ context.Context, _ string) (*model.User, error) { return user, nil },
		GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) { return user, nil },
	}
	h := newTestHandler(nil, users, nil, nil)

	rec := httptest.NewRecorder()
	h.ListUsers(rec, withActor(httptest.NewRequest(http.MethodGet, "/admin/users?q=subject@x.test", nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("ListUsers returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode ListUsers body: %v", err)
	}
	if len(body.Users) != 1 {
		t.Fatalf("lookup returned %d users, want 1: %s", len(body.Users), rec.Body.String())
	}
	if got, present := body.Users[0]["must_reset_password"]; !present || got != true {
		t.Errorf("the lookup reports must_reset_password=%v (present=%v) for an account under a "+
			"forced reset, so the two admin reads disagree about the same account",
			got, present)
	}
}
