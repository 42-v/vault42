package handler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/deferwork"
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
	// Password is the new password. Required. Shorter than the
	// configured minimum (VAULT_PASSWORD_MIN_LENGTH / h.minLength,
	// default 15 runes) is 400 password_too_short. A match against
	// the last 5 hashes is 400 password_recently_used. A HIBP hit is
	// 400 password_breached. Completing the reset revokes every
	// refresh family for the account.
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

// refusedByAccountState reports whether the password-reset flow must decline to
// act on this account at all.
//
// One definition, because the two halves of the flow have to agree and they did
// not. ResetRequest declined to mail a link to a deleted, banned or disabled
// account; ResetConfirm, which is the half that writes a password, checked only
// that a row came back. Two copies of a predicate are two chances to update one
// of them, and the copy that was missing was the one guarding the write.
//
// A nil user is included so the callers cannot forget it separately.
func refusedByAccountState(u *model.User) bool {
	return u == nil || u.Deleted || u.Banned || u.Disabled
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

	// Always return the same response so the body is not an enumeration signal.
	defer func() {
		WriteJSON(w, http.StatusOK, StatusResponse{
			Status: "If that email exists, a reset link has been sent.",
		})
	}()

	// Spend the same dominant work on every request so response TIMING is not an
	// enumeration signal either: one Argon2 verification (the ~50ms cost that a
	// login would pay, and the only large, reliable timing component here) and one
	// token generation, whether or not the address maps to an eligible account.
	// Only an existing, non-deleted, non-banned, non-disabled account then has the
	// token stored and mailed. A locked-out account is still eligible: resetting
	// the password is a legitimate way out of a failed-login lockout. The residual
	// difference from the store/audit writes on the eligible path is sub-millisecond
	// and dominated by the shared Argon2 cost. ErrArgon2Overloaded is discarded: the
	// deferred 200 is returned regardless, so no path reveals more than another.
	_, _ = vaultcrypto.VerifyPassword("dummy", vaultcrypto.DummyHash, h.pepper)
	token, tokenErr := vaultcrypto.RandomHex(32)

	// Folded, because the column only ever holds a folded address and the query
	// is an exact match.
	//
	// This was the one email lookup that passed its input through raw. Register
	// folds at auth.go:447, Login at :780, the OAuth callback and admin import
	// do the same, so auth.users.email cannot contain a capital -- and
	// "Alice@example.com" from a phone keyboard, or a pasted address with a
	// trailing space, simply missed the row.
	//
	// Nothing said so. The deferred response above answers "if that email
	// exists, a reset link has been sent" either way, which is the right
	// anti-enumeration behavior and is exactly what hid this: no mail was
	// queued, no audit row was written, and the user saw success. The person it
	// happens to is the one locked out by the failed-login counter, for whom
	// this route is the documented way back in.
	//
	// Named addr, not email: this file imports a package called email.
	addr := strings.ToLower(strings.TrimSpace(input.Email))

	user, err := h.users.GetByEmail(r.Context(), addr)
	if err != nil || refusedByAccountState(user) || tokenErr != nil {
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
		deferwork.Go(func(ctx context.Context) {
			// Email send is best-effort; failure logged inside Send.
			_ = h.mailer.Send(ctx, app, email.TemplatePasswordReset, user.Email, email.TemplateData{
				URL: resetURL,
			})
		})
	}

	// Audit log
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.PasswordReset, user.ID, "", ip, // #nosec G104 -- audit is best-effort, never blocks auth flow
			ua, "", "", map[string]any{"action": "requested"})
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

	// Fetch user, and refuse the same states ResetRequest refuses.
	//
	// This half had no gate. ResetRequest declines to mail a link to a deleted,
	// banned or disabled account (the predicate above), and this route -- the
	// one that actually writes a password -- accepted any token that resolved.
	// The token lives in the cache for an hour and erasure never deletes it, so
	// the window is real rather than theoretical: request a reset, erase the
	// account, and the mailed link still worked for the rest of the hour.
	//
	// What it wrote is the part that matters. updatePassword stores a fresh
	// Argon2id hash and inserts a password_history row for a user id whose
	// history the erasure cascade had just deleted -- onto a tombstone, after
	// the account_erased audit row was written. Migration 031 NULLs that hash
	// while writing the tombstone and calls it "the worst item here ... still
	// crackable offline and still tells an attacker what to try elsewhere".
	// This route put a live one back.
	//
	// A banned or disabled account fared no better: the same request clears
	// must_reset_password and import_pending and retires every lockout counter
	// for an account the platform has refused.
	//
	// The response is the invalid_or_expired_token the missing-token path
	// gives, deliberately. A distinct code here would make this route an oracle
	// for which addresses have been erased or banned.
	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil || refusedByAccountState(user) {
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

	// Clear every lockout standing against this account, so the reset is a way
	// out rather than a step that appears to do nothing.
	//
	// Three pieces of state, not one, and this used to reach one of them. The
	// account-wide cache counter, the durable failed_login_count, and the
	// per-(account, source address) counters — one key per address, with nothing
	// to enumerate them, so ClearAccountLockout retires them by generation rather
	// than by deletion. Clearing only the first two left the user refused from the
	// machine they were locked out on, behind the error a wrong password gets, so
	// the reasonable conclusion was that the reset had failed and the reasonable
	// next step was to reset again, which cleared nothing.
	//
	// It must reach every address, not the one this request came from: the reset
	// link is usually opened on a different device from the one that got locked
	// out.
	if h.cache != nil {
		if err := service.ClearAccountLockout(r.Context(), h.cache, user.ID); err != nil {
			log.Printf("password: failed to clear the lockout for user %s after password reset: %v", user.ID, err)
		}
	}
	if err := h.users.ResetFailedLogin(r.Context(), user.ID); err != nil {
		log.Printf("password: failed to reset the stored failed-login count for user %s after password reset: %v", user.ID, err)
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

	// Lift a forced password reset (migration 039): setting a new password through
	// the reset link is the event the flag was waiting for, and it is the only way
	// out of the state. Idempotent no-op for an account that never carried it --
	// the column is a privileged write, so an unconditional UPDATE would put every
	// ordinary reset through the guard for nothing.
	//
	// Fail closed, exactly as the import claim above does and for the same reason:
	// reporting success while the flag stands tells the user they are finished
	// when the next login will refuse them, mail them another link, and say
	// nothing about why. The flag stays set, so the next login re-issues a link
	// and the account is recoverable.
	if user.MustResetPassword {
		if err := h.users.ClearMustResetPassword(r.Context(), user.ID); err != nil {
			log.Printf("password: failed to clear must_reset_password for user %s: %v", user.ID, err)
			WriteError(w, http.StatusInternalServerError, "forced_reset_clear_failed")
			return
		}
		// Its own audit row rather than a field on the one below. That row
		// describes the reset; this one describes the account-state change the
		// reset caused, which is what an operator reading the lifecycle of the
		// flag is looking for -- set at import, lifted here.
		if h.auditLog != nil {
			h.auditLog.Log(r.Context(), audit.PasswordReset, user.ID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
				r.Header.Get("User-Agent"), "", "", map[string]interface{}{
					"action": "forced_reset_completed",
					"reason": "password_reset_confirmed",
				})
		}
	}

	// Audit log
	if h.auditLog != nil {
		action := "confirmed"
		if user.ImportPending {
			action = "import_claimed"
		}
		h.auditLog.Log(r.Context(), audit.PasswordReset, user.ID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", map[string]interface{}{"action": action})
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
		// CurrentPassword is the password currently stored on the
		// account. Required. A mismatch is 401 invalid_current_password.
		CurrentPassword string `json:"current_password"`
		// NewPassword is the replacement. Required. Shorter than the
		// configured minimum (default 15 runes) is 400
		// password_too_short. A match against the last 5 hashes is 400
		// password_recently_used. A HIBP hit is 400 password_breached.
		// Success revokes every refresh family for the account.
		NewPassword string `json:"new_password"`
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
			r.Header.Get("User-Agent"), "", "", nil)
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
