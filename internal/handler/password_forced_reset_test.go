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

// Completing the reset is the only way out of must_reset_password, so
// ResetConfirm has to lift it. If it did not, the account would set a password,
// be told the reset succeeded, and be refused at the next login for the same
// reason as before -- with a fresh mail every hour and no way to escape.

// forcedResetConfirm drives POST /auth/password/reset/confirm for one account and
// reports whether each flag was cleared.
type forcedResetConfirmResult struct {
	rec           *httptest.ResponseRecorder
	clearedImport bool
	clearedForced bool
	auditActions  []string
}

func runForcedResetConfirm(t *testing.T, user *model.User, clearErr error) forcedResetConfirmResult {
	t.Helper()

	cache := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, key string) (string, error) {
			if strings.HasPrefix(key, "reset:") {
				return user.ID, nil
			}
			return "", nil
		},
	}
	out := forcedResetConfirmResult{}
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
			u := *user
			return &u, nil
		},
		ClearImportPendingFn: func(_ context.Context, _ string) error {
			out.clearedImport = true
			return nil
		},
		ClearMustResetPwFn: func(_ context.Context, id string) error {
			if id != user.ID {
				t.Errorf("the flag was cleared on %q, not on the account that reset (%q)", id, user.ID)
			}
			out.clearedForced = true
			return clearErr
		},
	}
	auditRepo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			if action, ok := e.Metadata["action"].(string); ok {
				out.auditActions = append(out.auditActions, action)
			}
			return nil
		},
	}
	h := NewPasswordHandler(
		users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{}, newTestAuditLoggerWithRepo(auditRepo), cache,
		"https://vault.test", "TestVault", "", 15, nil, false,
	)

	body := strings.NewReader(`{"token":"magic-token-abc","password":"aNewStrongPassword!123"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	out.rec = httptest.NewRecorder()
	h.ResetConfirm(out.rec, req)
	return out
}

func TestResetConfirm_ClearsAForcedPasswordReset(t *testing.T) {
	out := runForcedResetConfirm(t, &model.User{
		ID: "u-forced", Email: "rider@legacy.test", MustResetPassword: true,
	}, nil)

	if out.rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", out.rec.Code, out.rec.Body.String())
	}
	if !out.clearedForced {
		t.Error("the forced reset was never lifted, so the account is refused at the next login " +
			"despite having just set a password")
	}
	var sawAction bool
	for _, a := range out.auditActions {
		if a == "forced_reset_completed" {
			sawAction = true
		}
	}
	if !sawAction {
		t.Errorf("audit actions = %v, want one naming the forced reset: the state change has to "+
			"be readable in the trail, not only its cause", out.auditActions)
	}
}

// The flag is not touched on an account that never carried it: the write is a
// privileged one (migration 039) and an unconditional UPDATE would make every
// ordinary reset issue it.
func TestResetConfirm_LeavesAnUnflaggedAccountAlone(t *testing.T) {
	out := runForcedResetConfirm(t, &model.User{ID: "u-plain", Email: "plain@example.com"}, nil)

	if out.rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", out.rec.Code, out.rec.Body.String())
	}
	if out.clearedForced {
		t.Error("an ordinary password reset wrote the forced-reset column")
	}
}

// An account can be both an unclaimed import and under a forced reset. One reset
// link leaves both states, or the user completes a reset and is bounced straight
// back into the other one.
func TestResetConfirm_ClearsBothStatesInOneRoundTrip(t *testing.T) {
	out := runForcedResetConfirm(t, &model.User{
		ID: "u-both", Email: "rider@legacy.test", ImportPending: true, MustResetPassword: true,
	}, nil)

	if out.rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", out.rec.Code, out.rec.Body.String())
	}
	if !out.clearedImport || !out.clearedForced {
		t.Errorf("import cleared = %v, forced reset cleared = %v: the account is still stuck in "+
			"whichever one was missed", out.clearedImport, out.clearedForced)
	}
}

// Fail closed, exactly as the import claim does: reporting success while the flag
// stands tells the user they are done when the next login will refuse them.
func TestResetConfirm_FailsClosedWhenTheFlagCannotBeCleared(t *testing.T) {
	out := runForcedResetConfirm(t, &model.User{
		ID: "u-forced", Email: "rider@legacy.test", MustResetPassword: true,
	}, context.DeadlineExceeded)

	if out.rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: the reset reported success while the account stays "+
			"locked out of password login (%s)", out.rec.Code, out.rec.Body.String())
	}
	if strings.Contains(out.rec.Body.String(), "password_reset_complete") {
		t.Errorf("body = %s, which claims the reset finished", out.rec.Body.String())
	}
}
