package handler

import (
	"net/http"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

const backupCodeCount = 10

// BackupCodeHandler handles backup code generation and verification.
type BackupCodeHandler struct {
	backupRepo    repository.BackupCodeRepository
	hmacKey       []byte
	authSvc       *service.AuthService
	secureCookies bool
}

// NewBackupCodeHandler creates a new backup code handler.
func NewBackupCodeHandler(repo repository.BackupCodeRepository, hmacKey []byte, authSvc *service.AuthService, secureCookies bool) *BackupCodeHandler {
	return &BackupCodeHandler{backupRepo: repo, hmacKey: hmacKey, authSvc: authSvc, secureCookies: secureCookies}
}

// Generate handles POST /auth/2fa/backup-codes.
func (h *BackupCodeHandler) Generate(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Delete existing backup codes
	if err := h.backupRepo.DeleteAllForUser(r.Context(), claims.Subject); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Generate new codes
	codes := make([]string, backupCodeCount)
	var dbCodes []*model.BackupCode
	now := time.Now()

	for i := 0; i < backupCodeCount; i++ {
		code, err := vaultcrypto.RandomHex(8) // 16 hex chars, 64-bit entropy
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		codes[i] = code

		hash := vaultcrypto.HMACSign([]byte(code), h.hmacKey)
		id, err := vaultcrypto.RandomUUID()
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		dbCodes = append(dbCodes, &model.BackupCode{
			ID:        id,
			UserID:    claims.Subject,
			CodeHash:  hash,
			CreatedAt: now,
		})
	}

	if err := h.backupRepo.CreateBatch(r.Context(), dbCodes); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, BackupCodesResponse{
		Codes:   codes,
		Warning: "Save these codes. They will not be shown again.",
	})
}

// Verify handles POST /auth/2fa/backup-code/verify.
// Accepts a backup code and completes the MFA login flow if the token is a 2FA challenge.
func (h *BackupCodeHandler) Verify(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Per-account lockout gate (audit H2) — shared with TOTP/password failures.
	if h.authSvc != nil && h.authSvc.MFAVerifyLocked(r.Context(), claims.Subject) {
		WriteError(w, http.StatusTooManyRequests, "account_locked")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Code == "" {
		WriteError(w, http.StatusBadRequest, "code_required")
		return
	}

	// Retrieve unused codes for this user
	codes, err := h.backupRepo.ListUnusedByUser(r.Context(), claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Constant-time: verify against all codes to prevent timing leaks on index position
	var matchedID string
	for _, c := range codes {
		if vaultcrypto.HMACVerify([]byte(req.Code), h.hmacKey, c.CodeHash) {
			matchedID = c.ID
		}
	}

	if matchedID == "" {
		if h.authSvc != nil {
			h.authSvc.RecordMFAFailure(r.Context(), claims.Subject, middleware.ClientIP(r), r.Header.Get("User-Agent"))
		}
		WriteError(w, http.StatusUnauthorized, "invalid_backup_code")
		return
	}

	// Mark the code as used (CAS: prevents double-spend race)
	used, err := h.backupRepo.MarkUsed(r.Context(), matchedID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if !used {
		WriteError(w, http.StatusConflict, "backup_code_already_used")
		return
	}

	// If this is a 2FA challenge (login flow), issue real tokens
	if completeMFAIfChallenge(w, r, claims, h.authSvc, h.secureCookies) {
		return
	}

	WriteJSON(w, http.StatusOK, VerifiedResponse{Verified: true})
}
