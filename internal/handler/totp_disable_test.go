package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTOTPHandler_Disable_NoClaims401(t *testing.T) {
	h := &TOTPHandler{}
	r := httptest.NewRequest(http.MethodDelete, "/auth/2fa/totp", nil)
	rec := httptest.NewRecorder()
	h.Disable(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
