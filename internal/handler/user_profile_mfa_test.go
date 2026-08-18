package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// The profile response tells the user whether their account has a second factor and which
// ones. A client uses it to decide whether to nag them to enroll one, and a user uses it to
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

// A user with no second factor still has to get an array back. mfa_methods was
// nil for that user, so the profile answered "mfa_methods": null, which a
// strongly-typed client cannot decode into a list. The same holds when the MFA
// service is not wired at all and when the status lookup fails: the shape of
// the response must not depend on any of that.
func TestProfile_MFAMethodsIsAlwaysAnArray(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
	}

	cases := map[string]*service.MFAService{
		"no factor enrolled": service.NewMFAService(
			&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, false),
		"status lookup fails": service.NewMFAService(
			&mocks.MockTOTPRepo{GetByUserIDFn: func(context.Context, string) (*model.TOTPSecret, error) {
				return nil, errors.New("db down")
			}},
			&mocks.MockWebAuthnRepo{ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
				return nil, errors.New("db down")
			}},
			&mocks.MockBackupCodeRepo{}, false),
		"no MFA service wired": nil,
	}

	for name, svc := range cases {
		t.Run(name, func(t *testing.T) {
			h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, svc)

			rec := httptest.NewRecorder()
			h.Profile(rec, setAuthContext(httptest.NewRequest(http.MethodGet, "/user/profile", nil), "user-1"))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if body := rec.Body.String(); !strings.Contains(body, `"mfa_methods":[]`) {
				t.Errorf("mfa_methods was not an empty array: %s", body)
			}
		})
	}
}

// avatar_url was accepted by PUT /user/profile and returned by the GDPR export,
// but never by the profile itself, so a client could write it and had no way to
// read it back.
func TestProfile_ReturnsTheAvatarURL(t *testing.T) {
	const avatar = "https://cdn.example.com/a/42.png"

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com", AvatarURL: avatar}, nil
		},
	}
	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	rec := httptest.NewRecorder()
	h.Profile(rec, setAuthContext(httptest.NewRequest(http.MethodGet, "/user/profile", nil), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp struct {
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AvatarURL != avatar {
		t.Errorf("avatar_url = %q, want %q", resp.AvatarURL, avatar)
	}
}
