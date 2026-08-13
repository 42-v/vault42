package handler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/email"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

var (
	errPasswordRecentlyUsed = errors.New("password recently used")
	errPasswordBreached     = errors.New("password found in breach database")
)

// PasswordHandler handles password reset endpoints.
type PasswordHandler struct {
	users       repository.UserRepository
	pwHistory   repository.PasswordHistoryRepository
	tokens      repository.RefreshTokenRepository
	sender      email.Sender
	mailer      *email.Mailer
	auditLog    *audit.Logger
	cache       cache.Cache
	origin      string
	appName     string
	pepper      string
	minLength   int
	hibp        *service.HIBPClient
	hibpEnabled bool
}

// PasswordResetRequestInput represents the reset request payload.
type PasswordResetRequestInput struct {
	// Email is the account to send a reset link to. Required. The response
	// is identical whether the address exists or not, so this field cannot
	// be used as an enumeration oracle.
	Email string `json:"email"`
}

// PasswordResetConfirmInput represents the reset confirmation payload.
type PasswordResetConfirmInput struct {
	// Token is the single-use value from the reset email. Required.
	// Unknown, expired or already-used values all return
	// invalid_or_expired_token.
	Token string `json:"token"`
	// Password is the new password. Required. Minimum 15 characters
	// (NIST SP 800-63B); a match against the last 5 hashes is
	// password_recently_used. Completing the reset revokes every refresh
	// family for the account.
	Password string `json:"password"` // #nosec G117 -- password field in request DTO, not stored
}

// NewPasswordHandler creates a new password handler.
func NewPasswordHandler(
	users repository.UserRepository,
	pwHistory repository.PasswordHistoryRepository,
	tokens repository.RefreshTokenRepository,
	sender email.Sender,
	auditLog *audit.Logger,
	c cache.Cache,
	origin, appName, pepper string,
	minLength int,
	hibp *service.HIBPClient,
	hibpEnabled bool,
) *PasswordHandler {
	if hibpEnabled && hibp == nil {
		log.Println("WARNING: HIBP breach check enabled but client is nil — breach checks will be skipped")
		hibpEnabled = false
	}
	return &PasswordHandler{
		users:       users,
		pwHistory:   pwHistory,
		tokens:      tokens,
		sender:      sender,
		mailer:      email.NewMailer(nil, sender, nil, email.Branding{AppName: appName}, nil),
		auditLog:    auditLog,
		cache:       c,
		origin:      origin,
		appName:     appName,
		pepper:      pepper,
		minLength:   minLength,
		hibp:        hibp,
		hibpEnabled: hibpEnabled,
	}
}

// SetMailer upgrades the handler's mailer to enable per-app white-label branding
// and template overrides. Called once at wiring time; a nil mailer is ignored.
func (h *PasswordHandler) SetMailer(m *email.Mailer) {
	if m != nil {
		h.mailer = m
	}
}

// ResetRequest handles POST /auth/password/reset.
func (h *PasswordHandler) ResetRequest(w http.ResponseWriter, r *http.Request) {
	var input PasswordResetRequestInput
	if err := decodeJSON(r, &input); err != nil || input.Email == "" {
		WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	// Capture request context values before the goroutine (request ctx
	// is canceled after response). Audit fields are read synchronously.
	ip := middleware.ClientIP(r)
	ua := r.Header.Get("User-Agent")

	// Always return success to prevent user enumeration
	defer func() {
		WriteJSON(w, http.StatusOK, StatusResponse{
			Status: "If that email exists, a reset link has been sent.",
		})
	}()

	user, err := h.users.GetByEmail(r.Context(), input.Email)
	if err != nil || user == nil {
		// Constant-time: verify against dummy hash to match the found-user path timing.
		// ErrArgon2Overloaded is intentionally discarded here: the deferred response always
		// returns 200 regardless, so no user enumeration signal is possible.
		// Result discarded; deferred 200 prevents enumeration.
		_, _ = vaultcrypto.VerifyPassword("dummy", vaultcrypto.DummyHash, h.pepper)
		return
	}

	// Generate reset token
	token, err := vaultcrypto.RandomHex(32)
	if err != nil {
		return
	}

	// Store token hash → user ID in cache (1 hour TTL) and reverse mapping for invalidation on password change.
	tokenHash := vaultcrypto.SHA256Hex(token)
	if h.cache != nil {
		h.cache.Set(r.Context(), "reset:"+tokenHash, user.ID, time.Hour)        // #nosec G104 -- cache failure is non-fatal; reset just won't work
		h.cache.Set(r.Context(), "pwreset_user:"+user.ID, tokenHash, time.Hour) // #nosec G104 -- reverse mapping for invalidation
	}

	// Send email asynchronously to prevent timing leaks from SMTP latency.
	// Use Background ctx since the request ctx is canceled after response.
	if h.sender != nil {
		resetURL := h.origin + "/reset-password?token=" + token
		app := email.AppFromContext(r.Context())
		go func() { // #nosec G118 -- intentional: email send outlives HTTP request, uses Background ctx
			// Email send is best-effort; failure logged inside Send.
			_ = h.mailer.Send(context.Background(), app, email.TemplatePasswordReset, user.Email, email.TemplateData{
				URL: resetURL,
			})
		}()
	}

	// Audit log
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.PasswordReset, user.ID, "", ip, // #nosec G104 -- audit is best-effort, never blocks auth flow
			ua, "", "", map[string]any{"action": "requested"}, 0)
	}
}

// ResetConfirm handles POST /auth/password/reset/confirm.
func (h *PasswordHandler) ResetConfirm(w http.ResponseWriter, r *http.Request) {
	var input PasswordResetConfirmInput
	if err := decodeJSON(r, &input); err != nil || input.Token == "" || input.Password == "" {
		WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if utf8.RuneCountInString(input.Password) < h.minLength {
		WriteError(w, http.StatusBadRequest, "password_too_short")
		return
	}

	// Atomic get-and-delete to prevent TOCTOU race on token reuse
	tokenHash := vaultcrypto.SHA256Hex(input.Token)
	userID, err := h.cache.GetAndDelete(r.Context(), "reset:"+tokenHash)
	if err != nil || userID == "" {
		WriteError(w, http.StatusBadRequest, "invalid_or_expired_token")
		return
	}

	// Fetch user
	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil || user == nil {
		WriteError(w, http.StatusBadRequest, "invalid_or_expired_token")
		return
	}

	if err := h.updatePassword(r.Context(), user.ID, input.Password); err != nil {
		switch {
		case errors.Is(err, errPasswordBreached):
			WriteError(w, http.StatusBadRequest, "password_breached")
		case errors.Is(err, errPasswordRecentlyUsed):
			WriteError(w, http.StatusBadRequest, "password_recently_used")
		case errors.Is(err, vaultcrypto.ErrArgon2Overloaded):
			WriteError(w, http.StatusServiceUnavailable, "server_busy")
		default:
			WriteError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	// Clear lockout state so the user can login immediately after reset.
	// Both cache-based counter and DB failed_login_count must be cleared.
	if h.cache != nil {
		h.cache.Delete(r.Context(), fmt.Sprintf("lockout:%s", user.ID)) // #nosec G104 -- best-effort lockout clear
	}
	if err := h.users.ResetFailedLogin(r.Context(), user.ID); err != nil {
		log.Printf("password: failed to reset lockout for user %s after password reset: %v", user.ID, err)
	}

	// Claim an imported account: setting a password via the magic link clears
	// import_pending so future logins verify the new Argon2 password normally.
	// Idempotent no-op for native accounts.
	if user.ImportPending {
		if err := h.users.ClearImportPending(r.Context(), user.ID); err != nil {
			// Fail closed: don't report success while the account is still
			// import_pending (the next login would re-trigger the magic-link flow
			// despite the password now being set). import_pending stays true, so
			// re-logging-in re-issues a fresh claim link — recoverable.
			log.Printf("password: failed to clear import_pending for user %s: %v", user.ID, err)
			WriteError(w, http.StatusInternalServerError, "import_claim_failed")
			return
		}
	}

	// Audit log
	if h.auditLog != nil {
		action := "confirmed"
		if user.ImportPending {
			action = "import_claimed"
		}
		h.auditLog.Log(r.Context(), audit.PasswordReset, user.ID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", map[string]interface{}{"action": action}, 0)
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "password_reset_complete"})
}

// ChangePassword handles POST /user/password (change password when logged in).
func (h *PasswordHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &input); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if utf8.RuneCountInString(input.NewPassword) < h.minLength {
		WriteError(w, http.StatusBadRequest, "password_too_short")
		return
	}

	user, err := h.users.GetByID(r.Context(), claims.Subject)
	if err != nil || user == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Verify current password
	valid, verifyErr := vaultcrypto.VerifyPassword(input.CurrentPassword, user.PasswordHash, h.pepper)
	if errors.Is(verifyErr, vaultcrypto.ErrArgon2Overloaded) {
		WriteError(w, http.StatusServiceUnavailable, "server_busy")
		return
	}
	if !valid {
		WriteError(w, http.StatusUnauthorized, "invalid_current_password")
		return
	}

	if err := h.updatePassword(r.Context(), user.ID, input.NewPassword); err != nil {
		switch {
		case errors.Is(err, errPasswordBreached):
			WriteError(w, http.StatusBadRequest, "password_breached")
		case errors.Is(err, errPasswordRecentlyUsed):
			WriteError(w, http.StatusBadRequest, "password_recently_used")
		case errors.Is(err, vaultcrypto.ErrArgon2Overloaded):
			WriteError(w, http.StatusServiceUnavailable, "server_busy")
		default:
			WriteError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	// Audit log
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.PasswordChange, user.ID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", nil, 0)
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "password_changed"})
}

// updatePassword checks HIBP breach database, history, hashes, stores, records history, and revokes sessions.
func (h *PasswordHandler) updatePassword(ctx context.Context, userID, newPassword string) error {
	if h.hibpEnabled && h.hibp.IsBreached(newPassword) {
		return errPasswordBreached
	}

	if h.pwHistory != nil {
		history, _ := h.pwHistory.GetRecentByUser(ctx, userID, 5)
		for _, entry := range history {
			if match, _ := vaultcrypto.VerifyPassword(newPassword, entry.PasswordHash, h.pepper); match {
				return errPasswordRecentlyUsed
			}
		}
	}

	hash, err := vaultcrypto.HashPassword(newPassword, h.pepper)
	if err != nil {
		return err
	}

	if err := h.users.UpdatePassword(ctx, userID, hash); err != nil {
		return err
	}

	if histID, err := vaultcrypto.RandomUUID(); err == nil {
		h.pwHistory.Create(ctx, &model.PasswordHistory{ // #nosec G104 -- password history is best-effort; failure doesn't compromise security
			ID: histID, UserID: userID, PasswordHash: hash, CreatedAt: time.Now(),
		})
	}

	if h.tokens != nil {
		if err := h.tokens.RevokeAllForUser(ctx, userID); err != nil {
			log.Printf("CRITICAL: failed to revoke sessions after password change for user %s: %v", userID, err)
			return fmt.Errorf("revoke sessions: %w", err)
		}
	}

	// Invalidate any pending password reset token for this user
	if h.cache != nil {
		if tokenHash, err := h.cache.GetAndDelete(ctx, "pwreset_user:"+userID); err == nil && tokenHash != "" {
			h.cache.Delete(ctx, "reset:"+tokenHash) // #nosec G104 -- best-effort invalidation
		}
		// A-8: drop the confirm-state cache so any pending elevated window
		// dies with the password change. Per-user key (post-A-8 layout) lets
		// us do this with a single Delete.
		h.cache.Delete(ctx, "confirm:"+userID) // #nosec G104 -- best-effort invalidation
	}

	return nil
}
