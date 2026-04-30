package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/tests/mocks"
)

func TestEmailOTPVerify_InvalidCode(t *testing.T) {
	h := NewEmailOTPHandler(nil, &mocks.MockUserRepo{}, false)

	// Missing code
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/verify", nil)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()
	h.Verify(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing body, got %d", rec.Code)
	}

	// Code too short
	body := jsonBody(t, map[string]string{"code": "123"})
	req = httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/verify", body)
	req = setAuthContext(req, "user-1")
	rec = httptest.NewRecorder()
	h.Verify(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short code, got %d", rec.Code)
	}

	// Code with letters
	body = jsonBody(t, map[string]string{"code": "12ab56"})
	req = httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/verify", body)
	req = setAuthContext(req, "user-1")
	rec = httptest.NewRecorder()
	h.Verify(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-numeric code, got %d", rec.Code)
	}
}

func TestEmailOTPVerify_Unauthorized(t *testing.T) {
	h := NewEmailOTPHandler(nil, &mocks.MockUserRepo{}, false)

	body := jsonBody(t, map[string]string{"code": "123456"})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/verify", body)
	// No auth context set
	rec := httptest.NewRecorder()
	h.Verify(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestEmailOTPResend_Unauthorized(t *testing.T) {
	h := NewEmailOTPHandler(nil, &mocks.MockUserRepo{}, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/resend", nil)
	rec := httptest.NewRecorder()
	h.Resend(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
