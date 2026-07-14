package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// The profile response tells the user whether their account has a second factor and which
// ones. A client uses it to decide whether to nag them to enrol one, and a user uses it to
// confirm the key they just registered actually took.
//
// The MFA service was never wired in these tests, so the branch that reads the real status
// never ran — the response would have reported mfa_enabled=false for an account with a
// security key on it, and nobody would have noticed until a user was told to set up the
// factor they already had.
func TestProfile_ReportsEnrolledMFAMethods(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com", EmailVerified: true}, nil
		},
	}
	totp := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{ID: "t-1", UserID: userID, Verified: true}, nil
		},
	}
	mfaSvc := service.NewMFAService(totp, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, false)

	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, mfaSvc)

	req := setAuthContext(httptest.NewRequest(http.MethodGet, "/user/profile", nil), "user-1")
	rec := httptest.NewRecorder()

	h.Profile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp struct {
		MFAEnabled bool     `json:"mfa_enabled"`
		MFAMethods []string `json:"mfa_methods"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !resp.MFAEnabled {
		t.Error("an account with a verified TOTP secret was reported as having no second factor")
	}
	if len(resp.MFAMethods) == 0 {
		t.Error("the enrolled methods were not reported")
	}
}
