package handler

import (
	"net/http"

	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/service"
)

// MFAHandler handles MFA status endpoints.
type MFAHandler struct {
	mfaSvc *service.MFAService
}

// NewMFAHandler creates a new MFA handler.
func NewMFAHandler(mfaSvc *service.MFAService) *MFAHandler {
	return &MFAHandler{mfaSvc: mfaSvc}
}

// Status handles GET /auth/2fa/status.
func (h *MFAHandler) Status(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	status, err := h.mfaSvc.GetStatus(r.Context(), claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, status)
}
