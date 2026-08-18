package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// PUT /user/profile answers with the same ProfileResponse the GET does, and clients
// treat that answer as the new state instead of re-fetching. So the MFA fields have
// to be resolved from the enrolled factors on the write path too, not left at their
// zero values.
//
// Reporting mfa_enabled=false to a user who has TOTP enrolled is not cosmetic: the
// account screen renders "two-factor authentication is off" and offers to set it up,
// immediately after the user changed their display name. The honest reading of that
// screen is that the profile save dropped their second factor.
func TestUpdateProfile_ReportsEnrolledMFA(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com", DisplayName: "Old Name"}, nil
		},
	}
	totpRepo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{ID: "totp-1", UserID: userID, Verified: true}, nil
		},
	}
	mfaSvc := service.NewMFAService(totpRepo, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, false)
	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, mfaSvc)

	req := httptest.NewRequest(http.MethodPut, "/user/profile",
		jsonBody(t, map[string]string{"display_name": "New Name"}))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	var got ProfileResponse
	decodeResponse(t, rec, &got)

	if got.DisplayName != "New Name" {
		t.Errorf("display_name = %q, want New Name", got.DisplayName)
	}
	if !got.MFAEnabled {
		t.Error("mfa_enabled = false for a user with a verified TOTP secret — the client would offer to enroll a factor they already have")
	}
	if len(got.MFAMethods) != 1 || got.MFAMethods[0] != "totp" {
		t.Errorf("mfa_methods = %v, want [totp]", got.MFAMethods)
	}
}

// The MFA lookup here is advisory: it is guarded by err == nil so a failure leaves the
// flags alone rather than failing the profile save. What it must not do is claim a
// second factor it could not confirm — a client that saw mfa_enabled=true from a failed
// lookup would stop prompting an account that has nothing enrolled.
func TestUpdateProfile_MFAStatusFailureClaimsNoFactor(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
	}
	// MFAService.GetStatus only errors when both primary lookups fail.
	totpRepo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(context.Context, string) (*model.TOTPSecret, error) {
			return nil, errAcctEntropy
		},
	}
	webauthnRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return nil, errAcctEntropy
		},
	}
	mfaSvc := service.NewMFAService(totpRepo, webauthnRepo, &mocks.MockBackupCodeRepo{}, false)
	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, mfaSvc)

	req := httptest.NewRequest(http.MethodPut, "/user/profile",
		jsonBody(t, map[string]string{"display_name": "New Name"}))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	var got ProfileResponse
	decodeResponse(t, rec, &got)

	if got.MFAEnabled {
		t.Error("mfa_enabled = true although the MFA status lookup failed")
	}
	if len(got.MFAMethods) != 0 {
		t.Errorf("mfa_methods = %v, want none after a failed lookup", got.MFAMethods)
	}
}
