package handler

import (
	"errors"
	"net/http"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

// AccountHandler handles self-service account deletion (GDPR erasure).
type AccountHandler struct {
	erasure  *service.ErasureService
	users    repository.UserRepository
	auditLog *audit.Logger
	pepper   string
}

// NewAccountHandler creates a new account handler.
func NewAccountHandler(erasure *service.ErasureService, users repository.UserRepository, auditLog *audit.Logger, pepper string) *AccountHandler {
	return &AccountHandler{erasure: erasure, users: users, auditLog: auditLog, pepper: pepper}
}

// Delete handles DELETE /user/account. The caller must be authenticated and
// must re-confirm their password in the request body (defense in depth — a
// stolen access token alone cannot erase the account). On success the account
// is erased and an encrypted recovery record is escrowed (when configured).
func (h *AccountHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Password == "" {
		WriteError(w, http.StatusUnauthorized, "password_required")
		return
	}

	user, err := h.users.GetByID(r.Context(), claims.Subject)
	if err != nil || user == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	valid, verifyErr := vaultcrypto.VerifyPassword(req.Password, user.PasswordHash, h.pepper)
	if errors.Is(verifyErr, vaultcrypto.ErrArgon2Overloaded) {
		WriteError(w, http.StatusServiceUnavailable, "server_busy")
		return
	}
	if verifyErr != nil || !valid {
		if h.auditLog != nil {
			h.auditLog.Log(r.Context(), audit.LoginFailure, claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort
				r.Header.Get("User-Agent"), "", "", map[string]interface{}{"reason": "account_delete_wrong_password"}, 20)
		}
		WriteError(w, http.StatusUnauthorized, "invalid_password")
		return
	}

	if err := h.erasure.DeleteAccount(r.Context(), claims.Subject, "self", "user_request"); err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			WriteError(w, http.StatusNotFound, "not_found")
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "deleted"})
}
