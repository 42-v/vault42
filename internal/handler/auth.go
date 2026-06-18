// Package handler implements HTTP handlers for the Vault auth service,
// including authentication, OAuth2 social login, TOTP and WebAuthn 2FA,
// password management, user profiles, client credentials, and health checks.
package handler

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

const refreshTokenCookie = "__Host-refresh_token" // #nosec G101 -- cookie name constant, not a credential

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	auth          *service.AuthService
	users         repository.UserRepository
	cache         cache.Cache
	auditLog      *audit.Logger
	pepper        string
	secureCookies bool
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(auth *service.AuthService, users repository.UserRepository, c cache.Cache, auditLog *audit.Logger, pepper string, secureCookies bool) *AuthHandler {
	return &AuthHandler{auth: auth, users: users, cache: c, auditLog: auditLog, pepper: pepper, secureCookies: secureCookies}
}

// Register handles POST /auth/register.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var input service.RegisterInput
	if err := decodeJSON(r, &input); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	_, err := h.auth.Register(r.Context(), input, middleware.ClientIP(r))
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidInput):
			WriteError(w, http.StatusBadRequest, "invalid_input")
		case errors.Is(err, service.ErrEmailTaken):
			// Return identical response to prevent user enumeration
			WriteJSON(w, http.StatusCreated, StatusMessageResponse{
				Status:  "verification_email_sent",
				Message: "If this email is not already registered, a verification email has been sent.",
			})
			return
		case errors.Is(err, service.ErrPasswordTooShort):
			WriteError(w, http.StatusBadRequest, "password_too_short")
		case errors.Is(err, service.ErrPasswordBreached):
			WriteError(w, http.StatusBadRequest, "password_breached")
		case errors.Is(err, vaultcrypto.ErrArgon2Overloaded):
			WriteError(w, http.StatusServiceUnavailable, "server_busy")
		default:
			WriteError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	WriteJSON(w, http.StatusCreated, StatusMessageResponse{
		Status:  "verification_email_sent",
		Message: "If this email is not already registered, a verification email has been sent.",
	})
}

// Login handles POST /auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var input service.LoginInput
	if err := decodeJSON(r, &input); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	ip := middleware.ClientIP(r)
	ua := r.Header.Get("User-Agent")
	input.Fingerprint = vaultcrypto.FingerprintInput{
		AcceptLanguage: r.Header.Get("Accept-Language"),
		TLSFingerprint: middleware.TLSFingerprint(r),
	}

	result, err := h.auth.Login(r.Context(), input, ip, ua)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			WriteError(w, http.StatusUnauthorized, "invalid_credentials")
		case errors.Is(err, service.ErrAccountLocked):
			WriteError(w, http.StatusForbidden, "account_locked")
		case errors.Is(err, service.ErrAccountBanned):
			WriteError(w, http.StatusForbidden, "account_banned")
		case errors.Is(err, service.ErrAccountDisabled):
			WriteError(w, http.StatusForbidden, "account_disabled")
		case errors.Is(err, service.ErrTooManySessions):
			WriteError(w, http.StatusTooManyRequests, "too_many_sessions")
		case errors.Is(err, vaultcrypto.ErrArgon2Overloaded):
			WriteError(w, http.StatusServiceUnavailable, "server_busy")
		default:
			WriteError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	// Imported account first login: no session issued — a magic claim link was
	// emailed. 202 Accepted with the flag, no token fields.
	if result.ImportClaimRequired {
		WriteJSON(w, http.StatusAccepted, map[string]any{"import_claim_required": true})
		return
	}

	// Set refresh token as HttpOnly cookie (only when tokens were issued, not on 2FA challenge)
	if result.RefreshToken != "" {
		setRefreshCookie(w, result.RefreshToken, h.secureCookies, result.CookieMaxAge)
	}

	WriteJSON(w, http.StatusOK, result)
}

// Refresh handles POST /auth/refresh.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "missing_refresh_token")
		return
	}

	ip := middleware.ClientIP(r)
	ua := r.Header.Get("User-Agent")
	fpInput := vaultcrypto.FingerprintInput{
		AcceptLanguage: r.Header.Get("Accept-Language"),
		TLSFingerprint: middleware.TLSFingerprint(r),
	}

	result, err := h.auth.Refresh(r.Context(), cookie.Value, ip, ua, fpInput)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrReplayDetected):
			clearRefreshCookie(w, h.secureCookies)
			WriteError(w, http.StatusUnauthorized, "replay_detected")
		case errors.Is(err, service.ErrTokenExpired):
			clearRefreshCookie(w, h.secureCookies)
			WriteError(w, http.StatusUnauthorized, "token_expired")
		case errors.Is(err, service.ErrTokenInvalid):
			clearRefreshCookie(w, h.secureCookies)
			WriteError(w, http.StatusUnauthorized, "invalid_token")
		default:
			WriteError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	setRefreshCookie(w, result.RefreshToken, h.secureCookies, result.CookieMaxAge)
	WriteJSON(w, http.StatusOK, result)
}

// Logout handles POST /auth/logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	ip := middleware.ClientIP(r)
	ua := r.Header.Get("User-Agent")

	if err := h.auth.Logout(r.Context(), claims.Subject, ip, ua); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	clearRefreshCookie(w, h.secureCookies)
	WriteJSON(w, http.StatusOK, StatusResponse{Status: "logged_out"})
}

// VerifyEmail handles GET /auth/verify-email?token=xxx.
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		WriteError(w, http.StatusBadRequest, "missing_token")
		return
	}

	tokenHash := vaultcrypto.SHA256Hex(token)
	cacheKey := "verify:" + tokenHash

	// Atomic get-and-delete to prevent TOCTOU race on token reuse
	userID, err := h.cache.GetAndDelete(r.Context(), cacheKey)
	if err != nil || userID == "" {
		WriteError(w, http.StatusBadRequest, "invalid_or_expired_token")
		return
	}

	if err := h.users.VerifyEmail(r.Context(), userID); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.Registration, userID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "",
			map[string]interface{}{"action": "email_verified"}, 0)
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "email_verified"})
}

// ConfirmPassword handles POST /auth/confirm.
// Verifies the user's password and grants a 5-minute elevated access window
// for sensitive operations (TOTP setup, backup codes, security key management).
func (h *AuthHandler) ConfirmPassword(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Password string `json:"password"` // #nosec G117 -- password field in request DTO, not stored
	}
	if err := decodeJSON(r, &req); err != nil || req.Password == "" {
		WriteError(w, http.StatusBadRequest, "password_required")
		return
	}

	user, err := h.users.GetByID(r.Context(), claims.Subject)
	if err != nil || user == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Check lockout counter to prevent brute-force via confirm endpoint
	confirmLockoutKey := "confirm_lockout:" + claims.Subject
	if val, _ := h.cache.Get(r.Context(), confirmLockoutKey); val != "" {
		var n int
		fmt.Sscanf(val, "%d", &n) // #nosec G104 -- parse failure returns 0, which means not locked
		if n >= 5 {
			WriteError(w, http.StatusTooManyRequests, "too_many_attempts")
			return
		}
	}

	valid, verifyErr := vaultcrypto.VerifyPassword(req.Password, user.PasswordHash, h.pepper)
	if errors.Is(verifyErr, vaultcrypto.ErrArgon2Overloaded) {
		WriteError(w, http.StatusServiceUnavailable, "server_busy")
		return
	}
	if verifyErr != nil || !valid {
		// Increment confirm-specific lockout counter (15-minute window)
		h.cache.Increment(r.Context(), confirmLockoutKey, 15*time.Minute) // #nosec G104 -- best-effort lockout counter
		if h.auditLog != nil {
			h.auditLog.Log(r.Context(), audit.LoginFailure, claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
				r.Header.Get("User-Agent"), "", "",
				map[string]interface{}{"reason": "confirm_wrong_password"}, 20)
		}
		WriteError(w, http.StatusUnauthorized, "invalid_password")
		return
	}

	// Clear confirm lockout counter on success
	h.cache.Delete(r.Context(), confirmLockoutKey) // #nosec G104 -- best-effort counter reset

	// Set a 5-minute confirmation window. Key is per-user so password-change
	// can invalidate it with a single Delete (A-8). Value is the issuing JWT's
	// JTI so the middleware can reject confirms used outside the originating
	// access token's lifetime — preserves the JTI binding M-3 added.
	cacheKey := "confirm:" + claims.Subject
	if err := h.cache.Set(r.Context(), cacheKey, claims.ID, 5*time.Minute); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.LoginSuccess, claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "",
			map[string]interface{}{"action": "password_confirmed"}, 0)
	}

	WriteJSON(w, http.StatusOK, ConfirmPasswordResponse{
		Confirmed: true,
		ExpiresIn: 300,
	})
}

func setRefreshCookie(w http.ResponseWriter, token string, secure bool, maxAge int) {
	// #nosec G124 -- Secure is derived from TLS state at runtime; HttpOnly + SameSite=Strict pinned.
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
}

func clearRefreshCookie(w http.ResponseWriter, secure bool) {
	// #nosec G124 -- Secure is derived from TLS state at runtime; HttpOnly + SameSite=Strict pinned.
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
