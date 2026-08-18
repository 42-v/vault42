package adminapi

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// The motivating case for must_reset_password is a migration whose password
// hashes vault42 cannot verify, so the import is where the flag is normally set:
// the operator knows, at the moment they submit the batch, that these accounts
// have no usable credential. Setting it here costs no UPDATE at all -- the value
// is written with the row -- which is why the import path can carry it while
// migration 039 keeps the column's UPDATE out of the application role's reach.

func TestImportUsers_CarriesTheForcedResetFlag(t *testing.T) {
	var created []*model.User
	h := importHandler(&mocks.MockUserRepo{
		GetByEmailFn:     func(_ context.Context, _ string) (*model.User, error) { return nil, nil },
		CreateImportedFn: func(_ context.Context, u *model.User) error { created = append(created, u); return nil },
	})

	body := `{"source":"legacy","users":[
		{"email":"hashed@legacy.test","must_reset_password":true},
		{"email":"plain@legacy.test"}
	]}`
	rec, out := doImport(t, h, body)

	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(created) != 2 {
		t.Fatalf("expected 2 CreateImported calls, got %d", len(created))
	}
	if !created[0].MustResetPassword {
		t.Error("the imported account was not flagged, so its unverifiable legacy hash becomes a " +
			"permanent silent refusal instead of a reset mail")
	}
	if created[1].MustResetPassword {
		t.Error("an account the batch did not flag came out flagged: the whole import would be " +
			"put through a password reset nobody asked for")
	}
	if got := out["must_reset_password"]; got != float64(1) {
		t.Errorf("response must_reset_password = %v, want 1: the operator has no other way to see "+
			"how many accounts the batch put into the state", got)
	}
}
