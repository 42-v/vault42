package handler

import (
	"net/http"

	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

// EmailOTPHandler handles email one-time password endpoints.
type EmailOTPHandler struct {
	authSvc       *service.AuthService
	users         repository.UserRepository
	secureCookies bool
}

// NewEmailOTPHandler creates a new email OTP handler.
func NewEmailOTPHandler(authSvc *service.AuthService, users repository.UserRepository, secureCookies bool) *EmailOTPHandler {
	return &EmailOTPHandler{authSvc: authSvc, users: users, secureCookies: secureCookies}
}

// Verify handles POST /auth/2fa/email-otp/verify.
func (h *EmailOTPHandler) Verify(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil || !isValidTOTPCode(req.Code) {
		WriteError(w, http.StatusBadRequest, "invalid_code")
		return
	}

	if err := h.authSvc.VerifyEmailOTP(r.Context(), claims.Subject, req.Code); err != nil {
		WriteError(w, http.StatusUnauthorized, "invalid_code")
		return
	}

	// If this is a 2FA challenge (login flow), issue real tokens
	if completeMFAIfChallenge(w, r, claims, h.authSvc, h.secureCookies) {
		return
	}

	WriteJSON(w, http.StatusOK, VerifiedResponse{Verified: true})
}

// Resend handles POST /auth/2fa/email-otp/resend.
func (h *EmailOTPHandler) Resend(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.users.GetByID(r.Context(), claims.Subject)
	if err != nil || user == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.authSvc.SendEmailOTP(r.Context(), claims.Subject, user.Email); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "sent"})
}
