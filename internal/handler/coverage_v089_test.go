package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// writeUploadError: service-error -> HTTP status mapping (blob.go:351)
// ---------------------------------------------------------------------------

func TestWriteUploadError_StatusMapping_v089(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	tests := []struct {
		name     string
		err      error
		wantCode int
		wantErr  string
	}{
		{"too_small", service.ErrBlobTooSmall, http.StatusBadRequest, "blob_too_small"},
		{"too_large", service.ErrBlobTooLarge, http.StatusRequestEntityTooLarge, "blob_too_large"},
		{"quota_exceeded", service.ErrQuotaExceeded, http.StatusConflict, "quota_exceeded"},
		{"default_internal", service.ErrBlobNotFound, http.StatusInternalServerError, "internal_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.writeUploadError(rec, tt.err)

			if rec.Code != tt.wantCode {
				t.Fatalf("code=%d want=%d", rec.Code, tt.wantCode)
			}
			var res map[string]string
			decodeResponse(t, rec, &res)
			if res["error"] != tt.wantErr {
				t.Fatalf("error=%q want=%q", res["error"], tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EmailOTPHandler.Resend: error + success branches (email_otp.go:60)
// ---------------------------------------------------------------------------

// newTestEmailOTPAuthService builds an AuthService wired for the email-OTP
// resend flow. mfaSvc/required control whether email-OTP is a permitted factor;
// emailSendErr lets a test force the SendEmailOTP failure branch.
func newTestEmailOTPAuthService(t *testing.T, users *mocks.MockUserRepo, required bool, emailSendErr error) *service.AuthService {
	t.Helper()
	tokenSvc, _ := newTestTokenService(t)
	// No enrolled strong factors => email-OTP is the only fallback when required.
	mfaSvc := service.NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(context.Context, string) (*model.TOTPSecret, error) { return nil, nil },
		},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) { return nil, nil },
		},
		&mocks.MockBackupCodeRepo{
			ListUnusedByUserFn: func(context.Context, string) ([]*model.BackupCode, error) { return nil, nil },
		},
		required,
	)
	mockCache := &mocks.MockCache{
		SetFn: func(context.Context, string, string, time.Duration) error { return nil },
	}
	emailSender := &mocks.MockEmailSender{
		SendFn: func(context.Context, string, string, string, string) error { return emailSendErr },
	}
	return service.NewAuthService(
		users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, mfaSvc, newTestAuditLogger(), nil, mockCache, emailSender,
		"https://vault.test", "TestVault", "", 15, false, []byte("hmac-secret"),
	)
}

func TestEmailOTPResend_Success_v089(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
	}
	authSvc := newTestEmailOTPAuthService(t, users, true, nil)
	h := NewEmailOTPHandler(authSvc, users, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/resend", nil)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Resend(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var res map[string]string
	decodeResponse(t, rec, &res)
	if res["status"] != "sent" {
		t.Fatalf("expected status=sent, got %q", res["status"])
	}
}

func TestEmailOTPResend_UserNotFound_v089(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) { return nil, nil },
	}
	authSvc := newTestEmailOTPAuthService(t, users, true, nil)
	h := NewEmailOTPHandler(authSvc, users, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/resend", nil)
	req = setAuthContext(req, "ghost")
	rec := httptest.NewRecorder()

	h.Resend(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var res map[string]string
	decodeResponse(t, rec, &res)
	if res["error"] != "unauthorized" {
		t.Fatalf("expected error=unauthorized, got %q", res["error"])
	}
}

// Resend maps any SendEmailOTP failure to 500. With required=false the email-OTP
// gate fails (ErrEmailOTPNotAllowed), exercising the internal_error branch.
func TestEmailOTPResend_NotAllowed_v089(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
	}
	authSvc := newTestEmailOTPAuthService(t, users, false, nil) // MFA not required => not allowed
	h := NewEmailOTPHandler(authSvc, users, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/resend", nil)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Resend(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var res map[string]string
	decodeResponse(t, rec, &res)
	if res["error"] != "internal_error" {
		t.Fatalf("expected error=internal_error, got %q", res["error"])
	}
}

// Email send failure (allowed path but sender errors) also maps to 500.
func TestEmailOTPResend_SendFailure_v089(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
	}
	authSvc := newTestEmailOTPAuthService(t, users, true, context.DeadlineExceeded)
	h := NewEmailOTPHandler(authSvc, users, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/resend", nil)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Resend(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// NewPasswordHandler: hibpEnabled+nil-client guard forces breach check off
// (password.go:55, lines 67-69). Proven behaviorally: ResetConfirm would
// dereference a nil *HIBPClient at password.go:288 if the guard didn't disable it.
// ---------------------------------------------------------------------------

func TestNewPasswordHandler_HIBPNilClientGuard_v089(t *testing.T) {
	token := "reset-token-hibp-guard"
	cacheKey := "reset:" + vaultcrypto.SHA256Hex(token)

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
		UpdatePasswordFn: func(context.Context, string, string) error { return nil },
	}
	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, key string) (string, error) {
			if key == cacheKey {
				return "user-123", nil
			}
			return "", cache.ErrNotFound
		},
		SetFn: func(context.Context, string, string, time.Duration) error { return nil },
		GetFn: func(context.Context, string) (string, error) { return "", cache.ErrNotFound },
	}

	// hibpEnabled=true but hibp client is nil: the constructor MUST flip
	// hibpEnabled to false, otherwise ResetConfirm panics on h.hibp.IsBreached.
	h := NewPasswordHandler(
		users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{}, newTestAuditLogger(), mockCache,
		"https://vault.test", "TestVault", "", 15,
		nil,  // hibp client nil
		true, // hibpEnabled requested
	)

	body := jsonBody(t, map[string]string{
		"token":    token,
		"password": "aBrandNewStrongP@ss1",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.ResetConfirm(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (breach check must be disabled), got %d; body: %s", rec.Code, rec.Body.String())
	}
	var res map[string]string
	decodeResponse(t, rec, &res)
	if res["status"] != "password_reset_complete" {
		t.Fatalf("expected status=password_reset_complete, got %q", res["status"])
	}
}

// ---------------------------------------------------------------------------
// VerifyFinish: WebAuthn not configured -> 501 (webauthn.go:197-201)
// ---------------------------------------------------------------------------

func TestWebAuthnVerifyFinish_NotConfigured_v089(t *testing.T) {
	// Pass a nil *webauthn.WebAuthn so the h.wan == nil guard fires.
	h := NewWebAuthnHandler(&mocks.MockWebAuthnRepo{}, &mocks.MockUserRepo{}, &mocks.MockCache{},
		(*webauthn.WebAuthn)(nil), nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/finish", nil)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.VerifyFinish(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var res map[string]string
	decodeResponse(t, rec, &res)
	if res["error"] != "webauthn_not_configured" {
		t.Fatalf("expected error=webauthn_not_configured, got %q", res["error"])
	}
}
