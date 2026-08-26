package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// The routes behind this guard write personal data that an erasure has already
// scrubbed, into stores the database cannot check for itself.
//
// identity.profiles is keyed by an unlinkable pseudonym -- no user_id, no
// foreign key -- which is exactly what makes it pseudonymous and also what makes
// SQL unable to see that the subject is gone. PUT /user/identity therefore
// recreated a name, a date of birth, a billing address and a VAT id on a
// tombstoned subject, and the handler never resolved the user at all, so nothing
// in the request path knew.
//
// PUT /user/profile is deliberately not behind this: auth.users states the rule
// in its own UPDATE. A guard that duplicates one the database already enforces
// costs a round trip and hides where the real invariant lives.

func liveAccountRequest(t *testing.T, subject string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/user/identity", nil)
	ctx := context.WithValue(req.Context(), ClaimsKey, &vaultcrypto.VaultClaims{RegisteredClaims: vjwt.RegisteredClaims{Subject: subject}})
	return req.WithContext(ctx)
}

func runLiveAccount(t *testing.T, users *mocks.MockUserRepo, req *http.Request) (int, bool) {
	t.Helper()
	var reached bool
	h := RequireLiveAccount(users)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, reached
}

func TestRequireLiveAccount_RefusesAnErasedSubject(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			// What SoftDeleteScrub leaves: the row survives so foreign keys stay
			// valid, with the personal columns cleared and the tombstone set.
			return &model.User{ID: id, Email: "deleted-" + id + "@deleted.invalid", Deleted: true}, nil
		},
	}
	code, reached := runLiveAccount(t, users, liveAccountRequest(t, "erased-user"))
	if code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}
	if reached {
		t.Error("the handler ran for an erased subject. The status code is not the point " +
			"on its own: what matters is that the write never happens.")
	}
}

func TestRequireLiveAccount_AllowsALiveSubject(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "alice@example.com"}, nil
		},
	}
	code, reached := runLiveAccount(t, users, liveAccountRequest(t, "user-1"))
	if code != http.StatusOK || !reached {
		t.Fatalf("a live subject was refused: status = %d, reached = %v", code, reached)
	}
}

// Fail closed. A database that cannot answer is not permission to write personal
// data back onto a subject that may have been erased.
func TestRequireLiveAccount_FailsClosed(t *testing.T) {
	cases := []struct {
		name string
		repo *mocks.MockUserRepo
	}{
		{"lookup error", &mocks.MockUserRepo{
			GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
				return nil, errors.New("connection refused")
			},
		}},
		{"no such user", &mocks.MockUserRepo{
			GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
				return nil, nil
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, reached := runLiveAccount(t, tc.repo, liveAccountRequest(t, "user-1"))
			if code != http.StatusUnauthorized || reached {
				t.Fatalf("status = %d, reached = %v; want 401 and no handler", code, reached)
			}
		})
	}
}

// No claims means the guard is mounted somewhere Auth is not, which is a wiring
// mistake. It must refuse rather than dereference nil.
func TestRequireLiveAccount_RefusesWithoutClaims(t *testing.T) {
	var looked bool
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
			looked = true
			return &model.User{}, nil
		},
	}
	req := httptest.NewRequest(http.MethodPut, "/user/identity", nil)
	code, reached := runLiveAccount(t, users, req)
	if code != http.StatusUnauthorized || reached {
		t.Fatalf("status = %d, reached = %v; want 401 and no handler", code, reached)
	}
	if looked {
		t.Error("looked a subject up with no claims to name one")
	}
}
