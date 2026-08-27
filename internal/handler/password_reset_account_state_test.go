package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// A reset link outlives the account it was mailed for.
//
// ResetRequest already declines to mail one to a deleted, banned or disabled
// account. ResetConfirm -- the half that actually writes a password -- accepted
// any token that resolved, and the token lives in the cache for an hour that
// erasure never shortens: ErasureService holds no cache reference and deletes
// no "reset:" key.
//
// So the sequence is: request a reset, erase the account, and the mailed link
// still works. What it writes is the point. A fresh Argon2id hash lands on the
// tombstone and a password_history row is inserted for a user id whose history
// the cascade deleted seconds earlier -- after the account_erased audit row.
// Migration 031 NULLs that hash while writing the tombstone and calls it "the
// worst item here ... still crackable offline and still tells an attacker what
// to try elsewhere". This route put a live one back.
//
// A banned or disabled account is the same request with a different ending: it
// clears must_reset_password and import_pending and retires every lockout
// counter for an account the platform has refused.

// resetConfirmOn drives POST /auth/password/reset/confirm against one account
// and reports whether the password write was attempted.
func resetConfirmOn(t *testing.T, user *model.User) (*httptest.ResponseRecorder, bool) {
	t.Helper()

	var wrote bool
	cache := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, key string) (string, error) {
			if strings.HasPrefix(key, "reset:") {
				return user.ID, nil
			}
			return "", nil
		},
	}
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
			u := *user
			return &u, nil
		},
		UpdatePasswordFn: func(_ context.Context, _, _ string) error {
			wrote = true
			return nil
		},
	}
	h := NewPasswordHandler(
		users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{}, newTestAuditLogger(), cache,
		"https://vault.test", "TestVault", "", 15, nil, false,
	)

	body := strings.NewReader(`{"token":"magic-token-abc","password":"aNewStrongPassword!123"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	rec := httptest.NewRecorder()
	h.ResetConfirm(rec, req)
	return rec, wrote
}

func TestResetConfirm_RefusesAnAccountTheStateGatesRefuse(t *testing.T) {
	for _, tc := range []struct {
		name string
		user *model.User
		why  string
	}{
		{
			"erased", &model.User{ID: "u-1", Deleted: true},
			"the hash migration 031 NULLs on the tombstone would be written back live, and a " +
				"password_history row inserted for a history the cascade already deleted",
		},
		{
			"banned", &model.User{ID: "u-1", Banned: true},
			"the account the platform sanctioned would get a working password, and the same " +
				"request retires its lockout counters",
		},
		{
			"disabled", &model.User{ID: "u-1", Disabled: true},
			"an account switched off would be handed a way back in",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, wrote := resetConfirmOn(t, tc.user)

			if wrote {
				t.Errorf("the password was written for an %s account: %s", tc.name, tc.why)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			// The same code the missing-token path gives, deliberately: a
			// distinct one would make this route an oracle for which addresses
			// have been erased or banned.
			if !strings.Contains(rec.Body.String(), "invalid_or_expired_token") {
				t.Errorf("body = %s, want invalid_or_expired_token so the refusal reveals nothing "+
					"about why", rec.Body.String())
			}
		})
	}
}

// The gate must not close on an ordinary account, or every reset in the product
// stops working -- which is the failure mode of a fix like this.
func TestResetConfirm_StillServesALiveAccount(t *testing.T) {
	rec, wrote := resetConfirmOn(t, &model.User{ID: "u-1", Email: "rider@example.test"})
	if !wrote {
		t.Error("a live account's reset did not write a password")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}
