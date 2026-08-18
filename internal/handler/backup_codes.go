package handler

import (
	"net/http"
	"time"

	"github.com/42-v/vault42/internal/audit"
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
	auditLog      *audit.Logger
}

// NewBackupCodeHandler creates a new backup code handler.
func NewBackupCodeHandler(repo repository.BackupCodeRepository, hmacKey []byte, authSvc *service.AuthService, secureCookies bool) *BackupCodeHandler {
	return &BackupCodeHandler{backupRepo: repo, hmacKey: hmacKey, authSvc: authSvc, secureCookies: secureCookies}
}

// SetAuditLog attaches the audit logger. Called once at wiring time; a nil
// logger is ignored.
func (h *BackupCodeHandler) SetAuditLog(l *audit.Logger) {
	if l != nil {
		h.auditLog = l
	}
}

// logEvent records a backup-code lifecycle event against the user's trail.
//
// Generation is the quietest way to take an account: it hands the caller ten
// standing bypasses of every other factor and invalidates whatever the owner
// had written down, and until 1.0.0 it left no record at all. Redemption needs
// the same treatment, because a code spent from an unfamiliar address is the
// signal that separates "the owner lost their phone" from "someone else had the
// list", and only failed attempts were ever recorded.
//
// Best-effort on purpose. A trail that can refuse a code the user just spent
// would convert an audit outage into an authentication outage.
func (h *BackupCodeHandler) logEvent(r *http.Request, event, userID string, meta map[string]interface{}) {
	if h.auditLog == nil {
		return
	}
	h.auditLog.Log(r.Context(), event, userID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
		r.Header.Get("User-Agent"), "", "", meta, 0)
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

	// The count is recorded, never the codes: they are the factor itself, and
	// audit rows outlive account erasure. Their hashes are already in the
	// backup-code table if anyone needs to prove which set was issued.
	h.logEvent(r, audit.TwoFASetup, claims.Subject, map[string]interface{}{
		"method": "backup_code",
		"action": "enrolled",
		"count":  backupCodeCount,
	})

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
		// Code is one unused 16-hex backup code from POST
		// /auth/2fa/backup-codes. Required. Empty is 400 code_required.
		// A miss is 401 invalid_backup_code and records an MFA failure.
		// Comparison is HMAC-SHA256 of the guess against every unused
		// CodeHash.
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

	// Recorded before the login is completed and regardless of how it ends. The
	// code was spent here; whether the session that follows is issued or refused
	// by account policy is a separate fact the login path records for itself,
	// and folding the two together would lose every redemption that happened
	// against a banned or locked account.
	h.logEvent(r, audit.TwoFAVerify, claims.Subject, map[string]interface{}{"method": "backup_code"})

	// If this is a 2FA challenge (login flow), issue real tokens
	if completeMFAIfChallenge(w, r, claims, h.authSvc, h.secureCookies, service.MFACompletion{Method: service.MethodBackupCode}) {
		return
	}

	WriteJSON(w, http.StatusOK, VerifiedResponse{Verified: true})
}
