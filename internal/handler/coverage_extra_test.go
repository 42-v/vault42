package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserHandler_UpdateProfile_NoClaims401(t *testing.T) {
	h := &UserHandler{}
	r := httptest.NewRequest(http.MethodPut, "/user/profile", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.UpdateProfile(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuthHandler_ConfirmPassword_NoClaims401(t *testing.T) {
	h := &AuthHandler{}
	r := httptest.NewRequest(http.MethodPost, "/auth/confirm-password",
		strings.NewReader(`{"password":"x"}`))
	rec := httptest.NewRecorder()
	h.ConfirmPassword(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestWebAuthnHandler_DeleteCredential_NoClaims401(t *testing.T) {
	h := &WebAuthnHandler{}
	r := httptest.NewRequest(http.MethodDelete, "/auth/webauthn/credentials/x", nil)
	rec := httptest.NewRecorder()
	h.DeleteCredential(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestBlobHandler_UploadNamed_NoClaims401(t *testing.T) {
	h := &BlobHandler{}
	r := httptest.NewRequest(http.MethodPut, "/blobs/named/x", strings.NewReader("data"))
	rec := httptest.NewRecorder()
	h.UploadNamed(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
