package adminapi

import (
	"net/http"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/httputil"
)

// The operator's ban lever (auth.users.banned and ban_reason, migration 004;
// writable by this plane since 043).
//
// The read side has always worked. Login answers 403 account_banned, so do the
// OAuth2 authorize path, the MFA continuation and the password-reset confirm,
// and the frontend renders error.account_banned in every locale it ships. What
// did not exist was a writer: 004 granted the columns to vault_app, 024 revoked
// them and recorded that ban_reason then had no writer at all, and the only
// thing that has set either since is POST /admin/users/import, which carries the
// flag in its INSERT. An account could arrive banned from a legacy platform and
// never be banned or unbanned afterwards.
//
// These two routes are that writer, shaped after the reversible pairs already
// on this resource -- lock/unlock and the forced-reset pair -- with the same
// operator tier, the same reason handling and the same audit conventions.
//
// A ban is not a longer lock. A lock expires on its own; a ban holds until an
// operator lifts it, and it says the account is sanctioned rather than
// temporarily contained. That is why it has its own error code at login, its own
// audit events, and a reason that is stored on the account rather than only in
// the trail: an operator reading the record has to be able to see why.

// The reasons recorded when the caller supplies none. They name the action
// rather than leaving the field absent, so a query over the trail filtering on
// reason never silently skips a ban imposed from a bare curl.
const (
	defaultBanReason   = "admin_ban"
	defaultUnbanReason = "admin_ban_lifted"
)

// BanUser handles POST /admin/users/{id}/ban. It sanctions an existing account
// and terminates the sessions that account already holds.
//
// The revocation is not optional garnish. Nothing on the refresh path consults
// banned -- POST /auth/refresh checks the token, not the account's sanction --
// so without it an attacker or a user holding a live refresh family keeps
// rotating it indefinitely and never meets the ban. The route would then refuse
// a login nobody was about to attempt while the access it was imposed against
// continued: a control that reports containment it does not deliver, which is
// the defect LockUser, RevokeAllSessions and RequirePasswordReset were each
// fixed for in turn. The response and the audit row both carry sessions_revoked
// so the operator reads the blast radius off the answer.
//
// Best-effort, and after the ban is written, for LockUser's reason: the sanction
// has already committed, and failing the request here would tell the operator no
// ban was imposed when one was. The nil check on the token repository is not
// defensive noise -- it arrives as a positional argument, cmd/admin-gateway has
// passed nil for it before, and the dereference landed after the write had
// committed on exactly this kind of route.
func (h *Handler) BanUser(w http.ResponseWriter, r *http.Request) {
	user, ok := h.liveUser(w, r)
	if !ok {
		return
	}
	reason := adminReason(r, defaultBanReason)

	if err := h.users.SetBanned(r.Context(), user.ID, true, reason); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	revoked := true
	if h.tokens == nil {
		revoked = false
	} else if err := h.tokens.RevokeAllForUser(r.Context(), user.ID); err != nil {
		revoked = false
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminUserBan, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"target_user":      user.ID,
		"reason":           reason,
		"sessions_revoked": revoked,
	})

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":           "banned",
		"sessions_revoked": revoked,
	})
}

// UnbanUser handles POST /admin/users/{id}/unban. It lifts a ban, returning the
// account to whatever other state it was in.
//
// It revokes nothing, and the asymmetry with the route above is the whole of the
// reasoning: imposing a sanction says the access already issued is not to be
// trusted, lifting one says the account is ordinary again. Signing the holder
// out on the way to telling them so would attach a containment action to the one
// verb here that is not one.
//
// Lifting a ban does not open the account. A banned account may also be locked,
// disabled, awaiting a forced reset or soft-deleted, and each of those gates is
// read independently at login -- so unbanning an account that is also disabled
// leaves it shut, which is correct. The response says the ban is lifted, not
// that the account can sign in.
//
// The reason recorded here is why the ban was lifted. The reason it was imposed
// is on the imposing audit row and stays there; auth.users.ban_reason is
// cleared with the flag, because a reason attached to a sanction that is no
// longer in force reads as one that is.
func (h *Handler) UnbanUser(w http.ResponseWriter, r *http.Request) {
	user, ok := h.liveUser(w, r)
	if !ok {
		return
	}
	reason := adminReason(r, defaultUnbanReason)

	if err := h.users.SetBanned(r.Context(), user.ID, false, ""); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminUserUnban, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"target_user": user.ID,
		"reason":      reason,
	})

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "not_banned"})
}
