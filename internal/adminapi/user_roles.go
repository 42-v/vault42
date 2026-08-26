package adminapi

import (
	"encoding/json"
	"net/http"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/seed"
)

// maxRolesPerUser bounds the set an admin may impose. The column is a TEXT[]
// with no length limit and the value reaches a signed token, where every entry
// costs bytes in every request the holder makes afterwards. Thirty-two is far
// above any real vocabulary -- the seeded catalog has seven -- and low enough
// that a paste accident is a 400 rather than a token nobody can use.
const maxRolesPerUser = 32

// SetUserRoles handles PUT /admin/users/{id}/roles.
//
// Roles reached auth.users at exactly one place before this: the INSERT in
// POST /admin/users/import. After that they were frozen, and an operator who
// imported a user with the wrong roles, or a platform promoting somebody
// afterwards, had nowhere to go but SQL. GET/POST/DELETE /admin/roles is the
// catalog -- which names exist -- and has never been the assignment.
//
// It replaces the whole set rather than adding or removing one name. The column
// is a TEXT[] the statement overwrites, so a grant-one/revoke-one pair would be
// a read-modify-write across two requests, and two admins editing one user
// would silently lose an edit. A PUT of the full set says what the caller
// believes the answer is, and the last writer wins visibly.
func (h *Handler) SetUserRoles(w http.ResponseWriter, r *http.Request) {
	// The catalog is required, not optional. Assigning a name the catalog does
	// not hold is worse than refusing it: RoleCatalog.Filter drops unknown names
	// at token issuance and is fail-open, so the role would sit in the users
	// table looking granted and never appear in a single token.
	if h.appRoles == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "roles_catalog_unavailable")
		return
	}

	user, ok := h.liveUser(w, r)
	if !ok {
		return
	}

	var req struct {
		Roles []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(req.Roles) > maxRolesPerUser {
		httputil.WriteError(w, http.StatusBadRequest, "too_many_roles")
		return
	}

	catalog, err := h.appRoles.ListNames(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	known := make(map[string]bool, len(catalog))
	for _, name := range catalog {
		known[name] = true
	}

	// Deduplicated in order. A repeated name is not an error -- the caller
	// asked for a set and sent a list -- but it must not reach the column
	// twice, because nothing downstream deduplicates and the claim would carry
	// it twice too.
	seen := make(map[string]bool, len(req.Roles))
	roles := make([]string, 0, len(req.Roles))
	for _, name := range req.Roles {
		if !roleNameRe.MatchString(name) {
			httputil.WriteError(w, http.StatusBadRequest, "invalid_role_name")
			return
		}
		// Admin-tier names are AdminUser-only. FilterUserRoles would strip
		// these at issuance anyway; refusing here means the operator learns the
		// grant did not happen instead of reading it back from the users table
		// and believing it did.
		//
		// IsReservedAdminRole, not the bare map index the map's own doc comment
		// bans: it case-folds and trims. Unreachable today, because roleNameRe
		// above is ^[a-z][a-z0-9_]{1,63}$ and refuses "Admin" eight lines
		// earlier -- but the ordering of those two checks is the only thing
		// making it unreachable, and nothing states that it has to stay.
		if seed.IsReservedAdminRole(name) {
			httputil.WriteError(w, http.StatusBadRequest, "reserved_role_name")
			return
		}
		if !known[name] {
			httputil.WriteError(w, http.StatusBadRequest, "unknown_role")
			return
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		roles = append(roles, name)
	}

	previous := user.Roles
	if err := h.users.SetRoles(r.Context(), user.ID, roles); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// The tokens the user already holds keep the old claim until they expire.
	// Refresh families are left alone deliberately: a role change is not
	// containment, and revoking every session of somebody who just gained a
	// role would sign them out for a promotion. The lock and forced-reset
	// routes revoke because both are containment; this one is not.
	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminUserRolesSet, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "",
		map[string]interface{}{
			"target_user": user.ID,
			"from":        previous,
			"to":          roles,
		})

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"status": "roles_set",
		"roles":  roles,
	})
}
