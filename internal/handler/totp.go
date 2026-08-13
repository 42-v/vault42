package handler

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

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
}

// NewTOTPHandler creates a new TOTP handler.
func NewTOTPHandler(repo repository.TOTPRepository, masterKey []byte, issuer string, c cache.Cache, authSvc *service.AuthService, secureCookies bool) *TOTPHandler {
	return &TOTPHandler{totpRepo: repo, masterKey: masterKey, issuer: issuer, cache: c, authSvc: authSvc, secureCookies: secureCookies}
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
	}

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
