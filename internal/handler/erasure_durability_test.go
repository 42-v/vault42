package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// An access token outlives the erasure that invalidated it.
//
// middleware.Auth validates signature, issuer, audience and token type and never
// touches the database, so nothing on an authenticated route knows the account
// was erased. DELETE /user/account revokes the refresh families, which stops
// renewal, but the access token already in the client's hands keeps working for
// the rest of its TTL -- and PUT /user/profile wrote display_name and avatar_url
// straight back onto the tombstoned row.
//
// That is not the accepted staleness. docs/security.md AR-5 accepts that roles
// on an issued token are up to one TTL out of date; it does not say an issued
// token may write. The distinction is that erasure is supposed to be terminal:
// SoftDeleteScrub overwrites the email with a tombstone and clears every other
// personal column, and a caller who can put a display name back has undone the
// part of Article 17 that the user actually asked for.
//
// The tree already holds this invariant one table over. insertRefreshRowSQL in
// internal/repository/postgres/refresh_token.go carries
// "AND EXISTS (SELECT 1 FROM auth.users WHERE id = $2 AND deleted = FALSE)"
// under a comment headed "SECURITY INVARIANT (erasure completeness)".
// auth.users is the other table the erasure scrubs, and it had no such guard.
func TestUpdateProfile_AnErasedAccountCannotWriteItselfBack(t *testing.T) {
	const erased = "erased-user"

	var wrote bool
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			// Exactly what SoftDeleteScrub leaves behind: the row is still
			// there, so foreign keys stay valid, with the personal columns
			// cleared and the tombstone set.
			return &model.User{
				ID:          id,
				Email:       "deleted-" + id + "@deleted.invalid",
				DisplayName: "",
				Deleted:     true,
			}, nil
		},
		UpdateFn: func(_ context.Context, _ *model.User) error {
			wrote = true
			return nil
		},
	}
	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodPut, "/user/profile",
		jsonBody(t, map[string]string{"display_name": "Victim Real Name"}))
	req = setAuthContext(req, erased)
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an erased account was served on a still-live token: got %d, want 401; body: %s",
			rec.Code, rec.Body.String())
	}
	if wrote {
		t.Error("the erased row was written back. The status code is not the point on its own: " +
			"what Article 17 requires is that the write does not happen.")
	}
}

// The same account before erasure still works, so the guard above is the
// tombstone and not something broader.
func TestUpdateProfile_ALiveAccountIsUnaffected(t *testing.T) {
	var got string
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "alice@example.com"}, nil
		},
		UpdateFn: func(_ context.Context, u *model.User) error {
			got = u.DisplayName
			return nil
		},
	}
	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodPut, "/user/profile",
		jsonBody(t, map[string]string{"display_name": "Alice"}))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a live account was refused: got %d; body: %s", rec.Code, rec.Body.String())
	}
	if got != "Alice" {
		t.Fatalf("display name written = %q, want %q", got, "Alice")
	}
}
