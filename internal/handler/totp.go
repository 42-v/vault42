package handler

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

// TOTPHandler handles TOTP 2FA endpoints.
type TOTPHandler struct {
	totpRepo      repository.TOTPRepository
	masterKey     []byte
	issuer        string
	cache         cache.Cache
	authSvc       *service.AuthService
	secureCookies bool
	auditLog      *audit.Logger
}

// NewTOTPHandler creates a new TOTP handler.
func NewTOTPHandler(repo repository.TOTPRepository, masterKey []byte, issuer string, c cache.Cache, authSvc *service.AuthService, secureCookies bool) *TOTPHandler {
	return &TOTPHandler{totpRepo: repo, masterKey: masterKey, issuer: issuer, cache: c, authSvc: authSvc, secureCookies: secureCookies}
}

// SetAuditLog attaches the audit logger. Called once at wiring time; a nil
// logger is ignored.
func (h *TOTPHandler) SetAuditLog(l *audit.Logger) {
	if l != nil {
		h.auditLog = l
	}
}

// logEvent records a TOTP lifecycle event against the user's trail.
//
// Enrolling a second factor, proving it and taking it away are the three moves
// an account takeover makes, and none of them used to leave a row: only MFA
// failures were recorded, as login_failure with reason mfa_failed. So a stolen
// session could bind its own authenticator to the account and the trail ran
// straight from the last successful login to the owner's lockout with nothing
// in between, which reads as an account that was never touched.
//
// Best-effort on purpose. A trail that can refuse a factor the user just proved
// would convert an audit outage into an authentication outage.
func (h *TOTPHandler) logEvent(r *http.Request, event, userID string, meta map[string]interface{}) {
	if h.auditLog == nil {
		return
	}
	h.auditLog.Log(r.Context(), event, userID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
		r.Header.Get("User-Agent"), "", "", meta, 0)
}

// Setup handles POST /auth/2fa/totp/setup.
func (h *TOTPHandler) Setup(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Check if already set up
	existing, _ := h.totpRepo.GetByUserID(r.Context(), claims.Subject)
	if existing != nil && existing.Verified {
		WriteError(w, http.StatusConflict, "totp_already_setup")
		return
	}

	// Delete any unverified setup
	if existing != nil {
		// Cleanup of unverified TOTP; failure doesn't compromise security.
		_ = h.totpRepo.DeleteByUserID(r.Context(), claims.Subject)
	}

	// Generate secret
	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Encrypt secret before storage (AAD binds ciphertext to user)
	encrypted, err := vaultcrypto.Encrypt([]byte(secret), h.masterKey, []byte(claims.Subject))
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if err := h.totpRepo.Create(r.Context(), &model.TOTPSecret{
		ID:        id,
		UserID:    claims.Subject,
		SecretEnc: hex.EncodeToString(encrypted),
		Verified:  false,
		CreatedAt: time.Now(),
	}); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	if err := revokeSessionsAfterFactorChange(r, h.authSvc, claims.Subject, "totp", "enrolled"); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	otpURL := vaultcrypto.BuildOTPAuthURL(secret, h.issuer, claims.Subject)

	WriteJSON(w, http.StatusOK, TOTPSetupResponse{
		Secret: secret,
		OTPURL: otpURL,
	})
}

// Verify handles POST /auth/2fa/totp/verify.
func (h *TOTPHandler) Verify(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Per-account lockout gate: the per-IP rate limit alone is defeated by IP
	// rotation, so without this a TOTP code is brute-forceable in the challenge
	// window (audit H2).
	if h.authSvc != nil && h.authSvc.MFAVerifyLocked(r.Context(), claims.Subject) {
		WriteError(w, http.StatusTooManyRequests, "account_locked")
		return
	}

	var input struct {
		// Code is the 6-digit TOTP value from the authenticator.
		// Required. Not exactly 6 ASCII digits is 400 invalid_code. A
		// wrong value records an MFA failure and returns 401
		// invalid_code. Reuse of the same step is 429
		// totp_code_already_used.
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &input); err != nil || !isValidTOTPCode(input.Code) {
		WriteError(w, http.StatusBadRequest, "invalid_code")
		return
	}

	totp, err := h.totpRepo.GetByUserID(r.Context(), claims.Subject)
	if err != nil || totp == nil {
		WriteError(w, http.StatusNotFound, "totp_not_setup")
		return
	}

	// Decrypt secret
	encBytes, err := hex.DecodeString(totp.SecretEnc)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	secretBytes, err := vaultcrypto.Decrypt(encBytes, h.masterKey, []byte(claims.Subject))
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	secret := string(secretBytes)

	// Validate code
	step, err := vaultcrypto.ValidateTOTPCode(secret, input.Code, time.Now())
	if err != nil || step < 0 {
		if h.authSvc != nil {
			h.authSvc.RecordMFAFailure(r.Context(), claims.Subject, middleware.ClientIP(r), r.Header.Get("User-Agent"))
		}
		WriteError(w, http.StatusUnauthorized, "invalid_code")
		return
	}

	// Atomically mark code as used to prevent TOTP replay (same code in same time step).
	// SetIfNotExists returns false if the key already existed → code was already used.
	// TTL covers the TOTP period (30s) plus skew window (±1 period = 90s total).
	cacheKey := fmt.Sprintf("totp_used:%s:%d", claims.Subject, step)
	ok, _ := h.cache.SetIfNotExists(r.Context(), cacheKey, "1", 90*time.Second)
	if !ok {
		WriteError(w, http.StatusTooManyRequests, "totp_code_already_used")
		return
	}

	// If not yet verified, mark as verified
	if !totp.Verified {
		// Next verify attempt will retry; not a security concern.
		_ = h.totpRepo.MarkVerified(r.Context(), totp.ID)
		// This is the moment the factor starts guarding the account, so it is
		// the enrollment an investigator looks for after a takeover. Setup
		// alone proves nothing: an unverified secret never gates a login and is
		// deleted by the next setup call.
		h.logEvent(r, audit.TwoFASetup, claims.Subject, map[string]interface{}{
			"method": "totp",
			"action": "enrolled",
		})
	}

	// Recorded before the login is completed and regardless of how it ends. The
	// code was proved here; whether the session that follows is issued or
	// refused by account policy is a separate fact the login path records for
	// itself, and folding the two together would lose every verification that
	// happened against a banned or locked account.
	h.logEvent(r, audit.TwoFAVerify, claims.Subject, map[string]interface{}{"method": "totp"})

	// If this is a 2FA challenge (login flow), issue real tokens
	if completeMFAIfChallenge(w, r, claims, h.authSvc, h.secureCookies) {
		return
	}

	WriteJSON(w, http.StatusOK, VerifiedResponse{Verified: true})
}

// Disable handles DELETE /auth/2fa/totp.
// Requires recent password confirmation.
func (h *TOTPHandler) Disable(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	totp, err := h.totpRepo.GetByUserID(r.Context(), claims.Subject)
	if err != nil || totp == nil {
		WriteError(w, http.StatusNotFound, "totp_not_setup")
		return
	}

	if err := h.totpRepo.DeleteByUserID(r.Context(), claims.Subject); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Stripping a factor off an account is the step that turns a borrowed
	// session into a permanent one, so it needs a row of its own. It is filed
	// under the enrollment event with action=removed because the vocabulary in
	// internal/audit has no removal constant; a query for factor changes must
	// therefore read the action key rather than the event type alone.
	h.logEvent(r, audit.TwoFASetup, claims.Subject, map[string]interface{}{
		"method": "totp",
		"action": "removed",
	})

	// After the trail, so a factor removal is recorded whether or not the
	// containment behind it lands.
	if err := revokeSessionsAfterFactorChange(r, h.authSvc, claims.Subject, "totp", "removed"); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "totp_disabled"})
}

// isValidTOTPCode checks that the code is exactly 6 ASCII digits.
func isValidTOTPCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
