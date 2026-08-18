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

// LoginStatusScope is the scope a client credential must carry before
// POST /auth/login will tell it why a login was refused rather than answering the
// ordinary 401.
//
// It is its own scope, on the reasoning MintScope records: reusing an existing
// one would mean a client granted the service-document store or the KMS oracle
// silently acquired the ability to read account state as well. Migration 039
// lists it among auth.capability_scopes(), so it reaches a client row through the
// admin plane and never through a seed file.
const LoginStatusScope = "login:status"

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	auth          *service.AuthService
	users         repository.UserRepository
	cache         cache.Cache
	auditLog      *audit.Logger
	pepper        string
	secureCookies bool
	// clients backs the optional client-credential authentication on
	// POST /auth/login. Nil is a working deployment: nothing can then hold
	// LoginStatusScope, so every caller gets the public answer.
	clients repository.ClientRepository
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(auth *service.AuthService, users repository.UserRepository, c cache.Cache, auditLog *audit.Logger, pepper string, secureCookies bool, clients repository.ClientRepository) *AuthHandler {
	return &AuthHandler{auth: auth, users: users, cache: c, auditLog: auditLog, pepper: pepper, secureCookies: secureCookies, clients: clients}
}

// clientMayLearnLoginStatus authenticates the OPTIONAL client credentials on a
// login request and reports whether the caller may be told the distinct refusal
// (service.ErrPasswordResetRequired) instead of the ordinary invalid_credentials.
//
// Optional is the whole of the difference from POST /client/token, and it is a
// property this function has to preserve: it returns a boolean and never an
// error, so no outcome of client authentication can decide a user's login. A
// request with no credentials, an unknown client, a deactivated one, a wrong
// secret and a client without the scope all mean the same thing here -- answer
// as if no client had asked -- and a correct password still logs the user in.
//
// The credential checks themselves follow ClientHandler.Token exactly, because
// the credential is the same credential: HTTP Basic or body parameters through
// parseClientCredentials, an Argon2 burn on the unknown-client and inactive-client
// paths so those do not answer faster than a wrong secret, and an audit row for
// every rejection so a brute force through this endpoint leaves the same trail it
// leaves through the token endpoint.
//
// Two deliberate departures:
//
//   - An overloaded Argon2 semaphore is not a 503 here. It means only that the
//     caller could not be authenticated in time, so the login continues, unchanged,
//     towards its own verification (which will answer 503 itself if the pressure
//     lasts). Turning a user's login into a 503 because a client credential could
//     not be checked would be exactly the coupling this function refuses.
//   - No burn happens when the request carries no credentials at all. A public
//     login costs what it always cost; only a caller that chose to present a
//     credential pays for verifying it.
func (h *AuthHandler) clientMayLearnLoginStatus(r *http.Request) bool {
	if h.clients == nil {
		return false
	}
	clientID, clientSecret, ok := parseClientCredentials(r)
	if !ok {
		return false
	}

	client, err := h.clients.GetByID(r.Context(), clientID)
	if err != nil || client == nil {
		if _, dummyErr := vaultcrypto.VerifyPassword("dummy", vaultcrypto.DummyHash); errors.Is(dummyErr, vaultcrypto.ErrArgon2Overloaded) {
			return false
		}
		auditClientAuthFailure(h.auditLog, r, clientID, "unknown_client")
		return false
	}
	if !client.Active {
		if _, dummyErr := vaultcrypto.VerifyPassword(clientSecret, client.SecretHash); errors.Is(dummyErr, vaultcrypto.ErrArgon2Overloaded) {
			return false
		}
		auditClientAuthFailure(h.auditLog, r, client.ID, "inactive_client")
		return false
	}
	valid, verifyErr := vaultcrypto.VerifyPassword(clientSecret, client.SecretHash)
	if errors.Is(verifyErr, vaultcrypto.ErrArgon2Overloaded) {
		return false
	}
	if verifyErr != nil || !valid {
		auditClientAuthFailure(h.auditLog, r, client.ID, "wrong_secret")
		return false
	}

	for _, s := range client.Scopes {
		if s == LoginStatusScope {
			return true
		}
	}
	// Authenticated but not authorized. Audited under its own reason: a
	// first-party client that started asking for a status it was never granted
	// is either misconfigured or not the client it claims to be, and neither is
	// visible in the response, which is identical to the public one.
	auditClientAuthFailure(h.auditLog, r, client.ID, "scope_not_granted")
	return false
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

	// Optional client-credential authentication. It decides one thing only: does
	// this caller get to be told WHY a login was refused. It cannot decide
	// whether the login succeeds, and the body cannot assert it -- DiscloseStatus
	// is json:"-" and the decoder above rejects unknown fields, so the only way
	// in is a verified client secret carrying LoginStatusScope.
	input.DiscloseStatus = h.clientMayLearnLoginStatus(r)

	result, err := h.auth.Login(r.Context(), input, ip, ua)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			WriteError(w, http.StatusUnauthorized, "invalid_credentials")
		// 403 rather than 401: the account exists, this is a refusal by policy,
		// and it is not a credential the caller can correct by retrying -- the
		// same shape as account_banned, account_disabled and account_locked. The
		// code says a reset was required and mailed and nothing else: not the
		// address, not the account id, and not whether the password was right,
		// which this branch never checked.
		case errors.Is(err, service.ErrPasswordResetRequired):
			WriteError(w, http.StatusForbidden, "password_reset_required")
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
		// Refresh re-reads account state and refuses a banned, disabled or
		// locked account, which is what makes a ban take effect on a session
		// already holding a valid refresh token. These three fell through to
		// 500, so the control worked and then reported itself as a server
		// fault: a bulk ban spiked the 5xx rate, and the caller could not tell
		// a refusal by policy from a vault42 that was broken. The cookie is
		// cleared with them, because a refresh token belonging to a banned
		// account is not one the browser should keep presenting.
		case errors.Is(err, service.ErrAccountLocked):
			clearRefreshCookie(w, h.secureCookies)
			WriteError(w, http.StatusForbidden, "account_locked")
		case errors.Is(err, service.ErrAccountBanned):
			clearRefreshCookie(w, h.secureCookies)
			WriteError(w, http.StatusForbidden, "account_banned")
		case errors.Is(err, service.ErrAccountDisabled):
			clearRefreshCookie(w, h.secureCookies)
			WriteError(w, http.StatusForbidden, "account_disabled")
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
		// Password is the account password, required to open the 5-minute
		// elevated-access window used by TOTP setup, WebAuthn
		// register/delete and backup-code generation. Empty or a missing
		// body is 400 password_required. A wrong value increments a
		// per-user confirm lockout (5 failures / 15 minutes) and returns
		// 401 invalid_password.
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
