package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/seed"
)

// roleNameRe restricts custom role names to lowercase alphanumerics + underscore.
var roleNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)

type roleView struct {
	Name        string    `json:"name"`
	Namespace   string    `json:"namespace"`
	Description string    `json:"description"`
	Reserved    bool      `json:"reserved"`
	CreatedAt   time.Time `json:"created_at"`
}

// ListRoles handles GET /admin/roles — the custom roles catalog.
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	if h.appRoles == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "roles_catalog_unavailable")
		return
	}
	roles, err := h.appRoles.List(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	views := make([]roleView, 0, len(roles))
	for _, role := range roles {
		views = append(views, roleView{role.Name, role.Namespace, role.Description, role.Reserved, role.CreatedAt})
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"roles": views})
}

// CreateRole handles POST /admin/roles — add a custom (non-reserved) role.
func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	if h.appRoles == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "roles_catalog_unavailable")
		return
	}
	var req struct {
		Name        string `json:"name"`
		Namespace   string `json:"namespace"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !roleNameRe.MatchString(req.Name) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_role_name")
		return
	}
	// Admin-tier names are AdminUser-only — never valid catalog (user) roles.
	if seed.ReservedAdminRoles[req.Name] {
		httputil.WriteError(w, http.StatusBadRequest, "reserved_role_name")
		return
	}
	if existing, _ := h.appRoles.Get(r.Context(), req.Name); existing != nil {
		httputil.WriteError(w, http.StatusConflict, "role_exists")
		return
	}
	ns := req.Namespace
	if ns == "" {
		ns = "app"
	}
	role := &model.AppRole{Name: req.Name, Namespace: ns, Description: req.Description, Reserved: false}
	if err := h.appRoles.Create(r.Context(), role); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if h.auditLog != nil {
		actor := GetAdmin(r.Context())
		h.auditLog.Log(r.Context(), "admin:role_create", actor.ID, "", r.RemoteAddr, r.UserAgent(), "", "", // #nosec G104 -- audit is best-effort
			map[string]any{"name": req.Name, "namespace": ns})
	}
	httputil.WriteJSON(w, http.StatusCreated, roleView{role.Name, role.Namespace, role.Description, role.Reserved, role.CreatedAt})
}

// DeleteRole handles DELETE /admin/roles/{name} — remove a non-reserved role.
func (h *Handler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	if h.appRoles == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "roles_catalog_unavailable")
		return
	}
	name := r.PathValue("name")
	if name == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_name")
		return
	}
	if err := h.appRoles.Delete(r.Context(), name); err != nil {
		if errors.Is(err, repository.ErrRoleReserved) {
			httputil.WriteError(w, http.StatusForbidden, "role_reserved")
			return
		}
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if h.auditLog != nil {
		actor := GetAdmin(r.Context())
		h.auditLog.Log(r.Context(), "admin:role_delete", actor.ID, "", r.RemoteAddr, r.UserAgent(), "", "", // #nosec G104 -- audit is best-effort
			map[string]any{"name": name})
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}
