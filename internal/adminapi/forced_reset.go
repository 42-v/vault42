package adminapi

import (
	"encoding/json"
	"net/http"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/sanitize"
)

// The operator's forced-password-reset lever (auth.users.must_reset_password,
// migration 039).
//
// While the flag is set, the account's stored password does not sign it in:
// POST /auth/login verifies nothing, mails a reset link out of band and answers
// the ordinary 401 invalid_credentials, byte for byte what a wrong password
// answers. The distinct 403 password_reset_required exists only for a
// first-party client that authenticated with client credentials carrying
// login:status. Completing the reset lifts the flag; so does the second route
// here.
//
// POST /admin/users/import could already create an account in the state, which
// covers the migration that motivated the flag -- a source system whose password
// hashes vault42 cannot verify. Nothing could put an account that already exists
// into it, so the general case the flag was built for had no write surface.
// These two routes are that surface, and they are shaped after
// POST /admin/users/{id}/lock and /unlock: the same reversible pair on the same
// resource, the same operator tier, the same audit-and-report conventions.

// maxResetReasonLen bounds the operator's free-text reason in runes.
//
// The value lands in a JSONB metadata column on a row that outlives the account
// under Art. 17(3)(b)/(e), so it is bounded rather than trusted: a caller
// holding users:reset should not be able to push an arbitrary payload into the
// audit store one request at a time. Two hundred runes is a sentence, which is
// what a reason is; anything longer belongs in the incident ticket the reason
// should be naming.
const maxResetReasonLen = 200

// The reasons recorded when the caller supplies none. They name the action
// rather than leaving the field absent, so a query over the trail filtering on
// reason never silently skips a forced reset that was imposed from a bare curl.
const (
	defaultRequireResetReason = "admin_forced_reset"
	defaultClearResetReason   = "admin_forced_reset_lifted"
)

// forcedResetRequest is the body both routes accept.
type forcedResetRequest struct {
	// Reason is why the operator is moving the flag, recorded on the audit row.
	// It is optional for the reason clampLockDuration exists on the lock route:
	// this is reached from scripts and from a bare curl, and refusing the
	// request over a missing body would mean an operator responding to a
	// suspected credential compromise gets a 400 instead of a contained account.
	Reason string `json:"reason"`
}

// resetReason reads the operator's reason out of the request body, falling back
// to the given default for an absent, unparseable or blank one.
//
// The value is passed through sanitize.String, the tree's one free-text
// sanitizer: it trims, neutralizes the markup characters that make an audit row
// render as something other than text, and truncates on a rune boundary.
func resetReason(r *http.Request, fallback string) string {
	var req forcedResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return fallback
	}
	if reason := sanitize.String(req.Reason, maxResetReasonLen); reason != "" {
		return reason
	}
	return fallback
}

// liveUser resolves {id} to an account a forced password reset can mean
// something on, writing the refusal itself and reporting false when it cannot.
//
// Both routes read before they write, which LockUser does not: LockUser hands an
// unknown id straight to the repository, the UPDATE matches no row, and the
// operator is told the account is locked. The two routes that do look --
// GET /admin/users/{id} and DELETE /admin/users/{id} -- answer 404
// user_not_found, and that is the code used here, so an operator who mistypes an
// id learns it from this route rather than from the account that never got
// reset.
//
// An erased account takes the same answer. Its row survives as a tombstone
// carrying a deleted-<id>@<domain>.invalid address; Login refuses it on
// account_deleted well before the forced-reset branch, and there is no mailbox
// left for the reset link. Setting the flag there would write a column that can
// never be read and report success for it.
func (h *Handler) liveUser(w http.ResponseWriter, r *http.Request) (*model.User, bool) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_id")
		return nil, false
	}

	user, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		// Not 404: telling an operator the account is gone when the database is
		// merely unreachable invites them to go looking for an erasure that
		// never happened.
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return nil, false
	}
	if user == nil || user.Deleted {
		httputil.WriteError(w, http.StatusNotFound, "user_not_found")
		return nil, false
	}
	return user, true
}

// RequirePasswordReset handles POST /admin/users/{id}/require-password-reset.
// It imposes a forced password reset on an existing account and terminates the
// sessions that account already holds.
//
// The revocation is deliberate and is reported rather than performed quietly.
// POST /auth/refresh does not consult must_reset_password -- the flag gates the
// password, and a refresh presents a token instead -- so without it a user who
// is already signed in keeps rotating their family indefinitely and never meets
// the reset. The route would then refuse a login nobody was about to attempt
// while the access it was imposed against continued: a control that reports
// containment it does not deliver, which is the defect LockUser and
// RevokeAllSessions were each fixed for. The response and the audit row both
// carry sessions_revoked so the operator reads the blast radius off the answer.
//
// Best-effort, and after the flag is written, for LockUser's reason: the
// demand has already committed, and failing the request here would tell the
// operator no reset was imposed when one was.
func (h *Handler) RequirePasswordReset(w http.ResponseWriter, r *http.Request) {
	user, ok := h.liveUser(w, r)
	if !ok {
		return
	}
	reason := resetReason(r, defaultRequireResetReason)

	if err := h.users.SetMustResetPassword(r.Context(), user.ID, true); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// The nil check is not defensive noise: this repository arrives as a
	// positional argument and cmd/admin-gateway has passed nil for it before, on
	// LockUser, where the dereference landed after the write had committed. A
	// missing repository reports sessions_revoked=false, which is the honest
	// answer and the one this function already knows how to give.
	revoked := true
	if h.tokens == nil {
		revoked = false
	} else if err := h.tokens.RevokeAllForUser(r.Context(), user.ID); err != nil {
		revoked = false
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminUserResetRequired, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"target_user":      user.ID,
		"reason":           reason,
		"sessions_revoked": revoked,
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":           "password_reset_required",
		"sessions_revoked": revoked,
	})
}

// ClearPasswordReset handles POST /admin/users/{id}/clear-password-reset. It
// withdraws a forced password reset, returning the account to the ordinary
// password gate.
//
// It revokes nothing, and the asymmetry with the route above is the whole of the
// reasoning: imposing the flag says what is already issued is not to be trusted,
// lifting it says the account is ordinary again. Signing the holder out on the
// way to telling them so would be a containment action attached to the one verb
// here that is not one.
//
// Lifting restores the ordinary password gate; it does not open it. An account
// imported with a hash vault42 cannot parse still has no password that verifies,
// so a mistaken lift leaves that account shut rather than open.
//
// It goes through SetMustResetPassword rather than ClearMustResetPassword, which
// clears the same column, because that method also stamps updated_at: a column
// the web server holds and the admin gateway does not, so calling it from here
// fails the whole statement with 42501. The two statements exist because the two
// roles hold different grants, not because the two directions differ.
func (h *Handler) ClearPasswordReset(w http.ResponseWriter, r *http.Request) {
	user, ok := h.liveUser(w, r)
	if !ok {
		return
	}
	reason := resetReason(r, defaultClearResetReason)

	if err := h.users.SetMustResetPassword(r.Context(), user.ID, false); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminUserResetCleared, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"target_user": user.ID,
		"reason":      reason,
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "password_reset_not_required"})
}
