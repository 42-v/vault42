package adminapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/internal/repository"
)

// AuthHandler handles admin authentication (login, logout, TOTP setup).
type AuthHandler struct {
	admins     repository.AdminUserRepository
	sessions   repository.AdminSessionRepository
	auditLog   *audit.Logger
	masterKey  []byte
	pepper     string
	sessionTTL time.Duration
	maxFailed  int
	lockoutDur time.Duration
}

// NewAuthHandler creates a new admin authentication handler.
// pepper is the optional HMAC-pepper applied to admin passwords; it must match
// the user-side service's pepper so hash formats stay compatible. Empty = no pepper.
func NewAuthHandler(
	admins repository.AdminUserRepository,
	sessions repository.AdminSessionRepository,
	auditLog *audit.Logger,
	masterKey []byte,
	pepper string,
	sessionTTL time.Duration,
	maxFailed int,
	lockoutDur time.Duration,
) *AuthHandler {
	return &AuthHandler{
		admins:     admins,
		sessions:   sessions,
		auditLog:   auditLog,
		masterKey:  masterKey,
		pepper:     pepper,
		sessionTTL: sessionTTL,
		maxFailed:  maxFailed,
		lockoutDur: lockoutDur,
	}
}

// loginRequest is the request body for POST /admin/auth/login.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code,omitempty"`
}

// loginResponse is the response body for a successful login.
type loginResponse struct {
	Token       string    `json:"token"`
	ExpiresAt   string    `json:"expires_at"`
	Admin       adminInfo `json:"admin"`
	Requires2FA bool      `json:"requires_2fa,omitempty"`
}

type adminInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	TOTP     bool   `json:"totp_configured"`
}

// Login handles POST /admin/auth/login.
// Authenticates with username + password + optional TOTP code.
// Anti-enumeration: always runs Argon2id even for non-existent users.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if req.Username == "" || req.Password == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_credentials")
		return
	}

	ctx := r.Context()
	clientIP := r.RemoteAddr

	admin, err := h.admins.GetByUsername(ctx, req.Username)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Anti-enumeration: run dummy hash for non-existent users
	if admin == nil {
		_, _ = vaultcrypto.VerifyPassword(req.Password, vaultcrypto.DummyHash, h.pepper)
		_ = h.auditLog.Log(ctx, audit.AdminLoginFailure, "", "", clientIP, r.UserAgent(), "", "", map[string]interface{}{
			"reason":   "user_not_found",
			"username": req.Username,
		}, 5)
		httputil.WriteError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	// Check account lockout
	if admin.LockedUntil != nil && time.Now().Before(*admin.LockedUntil) {
		_ = h.auditLog.Log(ctx, audit.AdminLoginFailure, admin.ID, "", clientIP, r.UserAgent(), "", "", map[string]interface{}{
			"reason": "account_locked",
		}, 3)
		httputil.WriteError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	// Verify password
	valid, err := vaultcrypto.VerifyPassword(req.Password, admin.PasswordHash, h.pepper)
	if err != nil || !valid {
		h.handleFailedLogin(ctx, admin, clientIP, r.UserAgent())
		httputil.WriteError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	// Verify TOTP if configured — always require code, never reveal password-correctness
	if admin.TOTPVerified && admin.TOTPSecretEnc != "" {
		if req.TOTPCode == "" {
			// Return same error as invalid password — never reveal "password OK but TOTP missing"
			h.handleFailedLogin(ctx, admin, clientIP, r.UserAgent())
			httputil.WriteError(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}

		secret, err := decryptTOTPSecret(admin.TOTPSecretEnc, h.masterKey, admin.ID)
		if err != nil {
			log.Printf("admin-gateway: failed to decrypt TOTP secret for %s: %v", admin.Username, err)
			httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}

		counter, err := vaultcrypto.ValidateTOTPCode(secret, req.TOTPCode, time.Now())
		if err != nil || counter < 0 {
			h.handleFailedLogin(ctx, admin, clientIP, r.UserAgent())
			httputil.WriteError(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}

		// TOTP replay prevention: reject codes that have already been used
		if counter <= admin.LastTOTPCounter {
			h.handleFailedLogin(ctx, admin, clientIP, r.UserAgent())
			httputil.WriteError(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}

		// Record the accepted counter to prevent replay
		_ = h.admins.UpdateLastTOTPCounter(ctx, admin.ID, counter)
	}

	// Create session
	tokenBytes, err := vaultcrypto.RandomBytes(64)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	token := hex.EncodeToString(tokenBytes)
	tokenHash := hashSessionToken(token)

	sessionID, err := vaultcrypto.RandomUUID()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	now := time.Now()
	expiresAt := now.Add(h.sessionTTL)

	session := &model.AdminSession{
		ID:        sessionID,
		AdminID:   admin.ID,
		TokenHash: tokenHash,
		IP:        clientIP,
		UserAgent: r.UserAgent(),
		CreatedAt: now,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	if err := h.sessions.Create(ctx, session); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Update last login
	_ = h.admins.UpdateLastLogin(ctx, admin.ID)

	_ = h.auditLog.Log(ctx, audit.AdminLogin, admin.ID, "", clientIP, r.UserAgent(), "", "", map[string]interface{}{
		"username": admin.Username,
		"role":     admin.Role,
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, loginResponse{
		Token:     token,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		Admin: adminInfo{
			ID:       admin.ID,
			Username: admin.Username,
			Role:     admin.Role,
			TOTP:     admin.TOTPVerified,
		},
		Requires2FA: !admin.TOTPVerified,
	})
}

// Logout handles POST /admin/auth/logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.sessions.Revoke(r.Context(), session.ID); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	admin := GetAdmin(r.Context())
	adminID := ""
	if admin != nil {
		adminID = admin.ID
	}
	_ = h.auditLog.Log(r.Context(), audit.AdminLogout, adminID, "", r.RemoteAddr, r.UserAgent(), "", "", nil, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// Status handles GET /admin/status.
func (h *AuthHandler) Status(w http.ResponseWriter, r *http.Request) {
	admin := GetAdmin(r.Context())
	if admin == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"admin": adminInfo{
			ID:       admin.ID,
			Username: admin.Username,
			Role:     admin.Role,
			TOTP:     admin.TOTPVerified,
		},
		"requires_2fa": !admin.TOTPVerified,
	})
}

// TOTPSetup handles POST /admin/admins/me/totp/setup.
func (h *AuthHandler) TOTPSetup(w http.ResponseWriter, r *http.Request) {
	admin := GetAdmin(r.Context())
	if admin == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if admin.TOTPVerified {
		httputil.WriteError(w, http.StatusConflict, "totp_already_configured")
		return
	}

	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Encrypt and store, AAD-bound to admin.ID (A-4)
	encSecret, err := encryptTOTPSecret(secret, h.masterKey, admin.ID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	admin.TOTPSecretEnc = encSecret
	admin.TOTPVerified = false
	if err := h.admins.Update(r.Context(), admin); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Build otpauth URI
	otpauthURI := fmt.Sprintf("otpauth://totp/Vault%%20Admin:%s?secret=%s&issuer=Vault%%20Admin&algorithm=SHA1&digits=6&period=30",
		admin.Username, secret)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"secret":      secret,
		"otpauth_uri": otpauthURI,
	})
}

// TOTPVerify handles POST /admin/admins/me/totp/verify.
func (h *AuthHandler) TOTPVerify(w http.ResponseWriter, r *http.Request) {
	admin := GetAdmin(r.Context())
	if admin == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if admin.TOTPVerified {
		httputil.WriteError(w, http.StatusConflict, "totp_already_verified")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if admin.TOTPSecretEnc == "" {
		httputil.WriteError(w, http.StatusBadRequest, "totp_not_setup")
		return
	}

	secret, err := decryptTOTPSecret(admin.TOTPSecretEnc, h.masterKey, admin.ID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	counter, err := vaultcrypto.ValidateTOTPCode(secret, req.Code, time.Now())
	if err != nil || counter < 0 {
		httputil.WriteError(w, http.StatusUnauthorized, "invalid_code")
		return
	}

	// TOTP replay prevention: reject codes that have already been used
	if counter <= admin.LastTOTPCounter {
		httputil.WriteError(w, http.StatusUnauthorized, "invalid_code")
		return
	}
	_ = h.admins.UpdateLastTOTPCounter(r.Context(), admin.ID, counter)

	admin.TOTPVerified = true
	if err := h.admins.Update(r.Context(), admin); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	_ = h.auditLog.Log(r.Context(), audit.TwoFASetup, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"method": "totp",
		"admin":  true,
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "totp_verified"})
}

// EnsureFirstAdmin creates a super_admin account on first boot if no admins exist.
// The password is generated randomly and printed to stdout (one-time).
// pepper is applied to the password hash (must match the value the gateway
// runtime uses; empty for no pepper).
func EnsureFirstAdmin(ctx context.Context, admins repository.AdminUserRepository, pepper string) error {
	count, err := admins.Count(ctx)
	if err != nil {
		return fmt.Errorf("count admins: %w", err)
	}
	if count > 0 {
		return nil
	}

	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		return fmt.Errorf("generate UUID: %w", err)
	}

	passwordBytes, err := vaultcrypto.RandomBytes(32)
	if err != nil {
		return fmt.Errorf("generate password: %w", err)
	}
	password := hex.EncodeToString(passwordBytes)

	hash, err := vaultcrypto.HashPassword(password, pepper)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	now := time.Now()
	admin := &model.AdminUser{
		ID:           id,
		Username:     "admin",
		PasswordHash: hash,
		Role:         string(rbac.RoleSuperAdmin),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := admins.Create(ctx, admin); err != nil {
		return fmt.Errorf("create first admin: %w", err)
	}

	log.Println("════════════════════════════════════════════════════════════════")
	log.Println("  FIRST BOOT: super_admin account created")
	log.Printf("  Username: admin")
	log.Printf("  Password: %s", password)
	log.Println("  ⚠ This password will NOT be shown again. Save it now.")
	log.Println("  ⚠ You must set up TOTP on first login.")
	log.Println("════════════════════════════════════════════════════════════════")

	return nil
}

func (h *AuthHandler) handleFailedLogin(ctx context.Context, admin *model.AdminUser, ip, ua string) {
	newCount, err := h.admins.IncrementFailedLogin(ctx, admin.ID)
	if err != nil {
		// On error, fall back to in-memory count (best-effort lockout)
		newCount = admin.FailedLoginCount + 1
	}
	if newCount >= h.maxFailed {
		lockUntil := time.Now().Add(h.lockoutDur)
		_ = h.admins.LockUntil(ctx, admin.ID, lockUntil)
		_ = h.auditLog.Log(ctx, audit.AdminLockout, admin.ID, "", ip, ua, "", "", map[string]interface{}{
			"username":     admin.Username,
			"failed_count": newCount,
			"locked_until": lockUntil.Format(time.RFC3339),
		}, 8)
	}

	_ = h.auditLog.Log(ctx, audit.AdminLoginFailure, admin.ID, "", ip, ua, "", "", map[string]interface{}{
		"username": admin.Username,
		"reason":   "wrong_password",
	}, 5)
}

func hashSessionToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// encryptTOTPSecret AEAD-encrypts the TOTP secret with adminID as AAD so
// the ciphertext is bound to a specific admin record. A DB-level swap of one
// admin's TOTP ciphertext into another's row will fail decryption (A-4).
func encryptTOTPSecret(secret string, masterKey []byte, adminID string) (string, error) {
	enc, err := vaultcrypto.Encrypt([]byte(secret), masterKey, []byte(adminID))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(enc), nil
}

// decryptTOTPSecret reverses encryptTOTPSecret. AAD must match — a row-swap
// attack (one admin's ciphertext moved to another admin's row) fails here.
func decryptTOTPSecret(encHex string, masterKey []byte, adminID string) (string, error) {
	enc, err := hex.DecodeString(encHex)
	if err != nil {
		return "", err
	}
	dec, err := vaultcrypto.Decrypt(enc, masterKey, []byte(adminID))
	if err != nil {
		return "", err
	}
	return string(dec), nil
}
