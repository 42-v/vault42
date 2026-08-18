package adminapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/keystore"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

// Handler handles admin API endpoints.
type Handler struct {
	users       repository.UserRepository
	clients     repository.ClientRepository
	tokens      repository.RefreshTokenRepository
	auditRepo   repository.AuditRepository
	admins      repository.AdminUserRepository
	sessions    repository.AdminSessionRepository
	adminConfig repository.AdminConfigRepository
	appRoles    repository.AppRoleRepository
	erasure     *service.ErasureService
	identity    *service.IdentityService
	keyStore    *keystore.KeyStore
	auditLog    *audit.Logger
	masterKey   []byte
	pepper      string

	emailBranding   repository.EmailBrandingRepository
	emailTemplates  repository.EmailTemplateRepository
	maxTemplateSize int
}

// SetEmailRepos wires the per-app email branding + template repositories,
// enabling the /admin/email-branding and /admin/email-templates endpoints.
// Optional (nil → those handlers return 503). maxTemplateSize caps custom
// template body size in bytes; <= 0 disables the size check.
// uuidPattern is the 8-4-4-4-12 hex shape of a user id. Compiled once at
// package init rather than on every admin user search: regexp.MustCompile
// builds an automaton, and building it per request puts that work on the
// request path for nothing.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (h *Handler) SetEmailRepos(branding repository.EmailBrandingRepository, templates repository.EmailTemplateRepository, maxTemplateSize int) {
	h.emailBranding = branding
	h.emailTemplates = templates
	h.maxTemplateSize = maxTemplateSize
}

// SetAppRoleRepo wires the custom-roles catalog repository, enabling the
// /admin/roles endpoints. Optional (nil → those handlers return 503).
func (h *Handler) SetAppRoleRepo(r repository.AppRoleRepository) {
	h.appRoles = r
}

// SetErasureService wires the account-erasure service, enabling the
// DELETE /admin/users/{id} endpoint. Optional (nil → that handler returns 503).
func (h *Handler) SetErasureService(s *service.ErasureService) {
	h.erasure = s
}

// SetIdentityService wires the identity service so account import can persist a
// migrated marketing-consent record. Optional: without it, import still creates
// accounts but drops any marketing preference in the payload rather than storing
// a preference it cannot attach provenance to.
func (h *Handler) SetIdentityService(s *service.IdentityService) {
	h.identity = s
}

// NewHandler creates a new admin API handler.
// pepper is the optional HMAC-pepper applied to admin password hashes
// (must match the user-side service for hash-format parity; empty = none).
func NewHandler(
	users repository.UserRepository,
	clients repository.ClientRepository,
	tokens repository.RefreshTokenRepository,
	auditRepo repository.AuditRepository,
	admins repository.AdminUserRepository,
	sessions repository.AdminSessionRepository,
	adminConfig repository.AdminConfigRepository,
	ks *keystore.KeyStore,
	auditLog *audit.Logger,
	masterKey []byte,
	pepper string,
) *Handler {
	return &Handler{
		users:       users,
		clients:     clients,
		tokens:      tokens,
		auditRepo:   auditRepo,
		admins:      admins,
		sessions:    sessions,
		adminConfig: adminConfig,
		keyStore:    ks,
		auditLog:    auditLog,
		masterKey:   masterKey,
		pepper:      pepper,
	}
}

// ========== Key Management ==========

// ListKeys handles GET /admin/keys.
func (h *Handler) ListKeys(w http.ResponseWriter, r *http.Request) {
	if h.keyStore == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "keystore_not_configured")
		return
	}
	keys, err := h.keyStore.ListKeys(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if keys == nil {
		keys = []keystore.KeyInfo{}
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"keys":  keys,
		"total": len(keys),
	})
}

// RotateKey handles POST /admin/keys/rotate.
func (h *Handler) RotateKey(w http.ResponseWriter, r *http.Request) {
	if h.keyStore == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "keystore_not_configured")
		return
	}
	kid, err := h.keyStore.Rotate(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "key_rotation_failed")
		return
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminKeyRotate, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"kid": kid,
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "rotated", "kid": kid})
}

// RevokeKey handles DELETE /admin/keys/{kid}.
func (h *Handler) RevokeKey(w http.ResponseWriter, r *http.Request) {
	if h.keyStore == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "keystore_not_configured")
		return
	}
	kid := r.PathValue("kid")
	if kid == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_kid")
		return
	}
	if err := h.keyStore.Revoke(r.Context(), kid); err != nil {
		httputil.WriteError(w, http.StatusNotFound, "key_not_found")
		return
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminKeyRevoke, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"kid": kid,
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// ========== User Management ==========

// listUsersResponse wraps paginated user list.
//
// Every admin list endpoint answers with the same four keys: the collection,
// total, limit and offset. total is always present, including on an empty
// result, so a client never has to distinguish "no matches" from "this
// endpoint does not report a total".
type listUsersResponse struct {
	Users  []userSummary `json:"users"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

type userSummary struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	DisplayName   string     `json:"display_name,omitempty"`
	MFARequired   bool       `json:"mfa_required"`
	LockedUntil   *time.Time `json:"locked_until,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// ListUsers handles GET /admin/users.
// Accepts ?q= query param: UUID format → lookup by ID, contains @ → lookup by email.
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePagination(r)

	q := r.URL.Query().Get("q")
	if q == "" {
		httputil.WriteJSON(w, http.StatusOK, listUsersResponse{
			Users:  []userSummary{},
			Limit:  limit,
			Offset: offset,
		})
		return
	}

	var users []userSummary

	if uuidPattern.MatchString(q) {
		user, err := h.users.GetByID(r.Context(), q)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		if user != nil {
			users = append(users, userSummary{
				ID:            user.ID,
				Email:         user.Email,
				EmailVerified: user.EmailVerified,
				DisplayName:   user.DisplayName,
				MFARequired:   user.MFARequired,
				LockedUntil:   user.LockedUntil,
				CreatedAt:     user.CreatedAt,
			})
		}
	} else if strings.Contains(q, "@") {
		user, err := h.users.GetByEmail(r.Context(), q)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		if user != nil {
			users = append(users, userSummary{
				ID:            user.ID,
				Email:         user.Email,
				EmailVerified: user.EmailVerified,
				DisplayName:   user.DisplayName,
				MFARequired:   user.MFARequired,
				LockedUntil:   user.LockedUntil,
				CreatedAt:     user.CreatedAt,
			})
		}
	}

	if users == nil {
		users = []userSummary{}
	}

	total := len(users)
	httputil.WriteJSON(w, http.StatusOK, listUsersResponse{
		Users:  paginate(users, limit, offset),
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

// GetUser handles GET /admin/users/{id}.
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_id")
		return
	}

	user, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if user == nil {
		httputil.WriteError(w, http.StatusNotFound, "user_not_found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, userSummary{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		DisplayName:   user.DisplayName,
		MFARequired:   user.MFARequired,
		LockedUntil:   user.LockedUntil,
		CreatedAt:     user.CreatedAt,
	})
}

// maxLockDuration bounds an admin-imposed account lock (L7): a caller with the
// UsersLock grant must not be able to set an effectively permanent lock.
const maxLockDuration = 30 * 24 * time.Hour

// clampLockDuration parses an admin lock duration, defaulting to 24h for an
// unparseable, non-positive, or absurdly long (>30d) value.
func clampLockDuration(s string) time.Duration {
	dur, err := time.ParseDuration(s)
	if err != nil || dur <= 0 || dur > maxLockDuration {
		return 24 * time.Hour
	}
	return dur
}

// LockUser handles POST /admin/users/{id}/lock.
func (h *Handler) LockUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_id")
		return
	}

	var req struct {
		Duration string `json:"duration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Duration = "24h"
	}
	until := time.Now().Add(clampLockDuration(req.Duration))
	if err := h.users.LockUntil(r.Context(), id, until); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// A lock that leaves live sessions running is not containment. This is the
	// documented first response to a suspected account takeover, and setting
	// locked_until alone only stopped logins that had not happened yet: an
	// attacker holding a refresh token kept rotating it. Refresh now rejects a
	// locked account too, so this revocation is defense in depth rather than the
	// only barrier, but it is what makes containment immediate instead of
	// dependent on when the attacker next rotates.
	//
	// Best-effort by design: the lock itself has already been written, and
	// failing the request here would tell the operator the account is not locked
	// when it is. The audit event records whether the revocation succeeded.
	// The nil check is not defensive noise. This repository arrives as a
	// positional argument, cmd/admin-gateway passed nil for it, and the panic
	// landed here: after the lock had committed, on the one route an operator
	// reaches for during a takeover. Recovery turned it into a 500 that reads as
	// "the lock failed", which invites an unlock. A missing repository now
	// reports revoked=false in the audit row, which is the honest answer and the
	// one this function already knows how to give.
	revoked := true
	if h.tokens == nil {
		revoked = false
	} else if err := h.tokens.RevokeAllForUser(r.Context(), id); err != nil {
		revoked = false
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminUserLock, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"target_user":      id,
		"until":            until.Format(time.RFC3339),
		"sessions_revoked": revoked,
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "locked", "until": until.Format(time.RFC3339)})
}

// UnlockUser handles POST /admin/users/{id}/unlock.
func (h *Handler) UnlockUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_id")
		return
	}

	if err := h.users.Unlock(r.Context(), id); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminUserUnlock, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"target_user": id,
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})
}

// DeleteUser handles DELETE /admin/users/{id}. It erases the user account (GDPR)
// with key-recoverable escrow: when a recovery public key is configured the
// user's email is written to the encrypted, append-only recovery log before the
// PII is cascade-deleted and the user row is scrubbed and soft-deleted.
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_id")
		return
	}
	if h.erasure == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "erasure_unavailable")
		return
	}

	admin := GetAdmin(r.Context())
	if err := h.erasure.DeleteAccount(r.Context(), id, "admin:"+admin.ID, "admin_request"); err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "user_not_found")
			return
		}
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	_ = h.auditLog.Log(r.Context(), audit.AdminUserDelete, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"target_user": id,
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Pagination bounds for admin list endpoints that can return unbounded result
// sets (admin users, active sessions). Enforcing a cap mitigates resource
// exhaustion and oversized responses (OWASP API Security Top 10 — API4/M06).
const (
	defaultListLimit = 50
	maxListLimit     = 100
)

// parsePagination extracts enforced limit/offset query params. An absent or
// invalid limit falls back to defaultListLimit; any limit above maxListLimit is
// clamped down to the cap. An absent or invalid offset is treated as 0.
func parsePagination(r *http.Request) (limit, offset int) {
	q := r.URL.Query()
	limit = defaultListLimit
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

// paginate returns the [offset, offset+limit) window of items, guarding against
// out-of-range offsets. Callers must pass a limit already clamped to maxListLimit
// (parsePagination guarantees this).
func paginate[T any](items []T, limit, offset int) []T {
	if offset >= len(items) {
		return items[:0]
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

// ========== Session Management ==========

// ListSessions handles GET /admin/sessions.
//
// It lists ADMIN sessions, not user sessions: the live roster of every
// currently logged-in admin, with each one's source IP and user agent. That is
// reconnaissance for an attacker holding a lower-tier admin session, which is
// the stated reason internal/rbac/rbac.go keeps admins:manage at super_admin,
// so the route is gated on admins:manage rather than the viewer-tier
// sessions:list it used to take.
//
// Results are paginated via enforced limit/offset query params (default 50,
// max 100) to bound the response size of an unbounded active-session set.
func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := h.sessions.ListActive(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if sessions == nil {
		sessions = []*model.AdminSession{}
	}

	limit, offset := parsePagination(r)
	total := len(sessions)
	sessions = paginate(sessions, limit, offset)

	type sessionView struct {
		ID        string    `json:"id"`
		AdminID   string    `json:"admin_id"`
		IP        string    `json:"ip"`
		UserAgent string    `json:"user_agent,omitempty"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	views := make([]sessionView, 0, len(sessions))
	for _, s := range sessions {
		views = append(views, sessionView{
			ID:        s.ID,
			AdminID:   s.AdminID,
			IP:        s.IP,
			UserAgent: s.UserAgent,
			CreatedAt: s.CreatedAt,
			ExpiresAt: s.ExpiresAt,
		})
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"sessions": views,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	})
}

// RevokeAllSessions handles POST /admin/sessions/revoke-all.
//
// It revokes every USER's refresh tokens service-wide. That is the break-glass
// containment for bulk refresh-token theft, and it is what docs/security.md,
// docs/api.md, the SessionsRevoke permission's own definition in
// internal/rbac/rbac.go and the mitigation named in
// tests/attack/atk_authtok_lock_refresh_test.go all describe.
//
// It used to run UPDATE auth.admin_sessions instead. It touched zero rows in
// auth.refresh_tokens, so the control four documents lean on did not exist: an
// operator responding to mass token theft pressed it, was told
// all_sessions_revoked, and nothing was contained. It also handed an
// operator-tier admin an availability lever over every super_admin, because
// revoking admin sessions logs the whole admin plane out and SessionsRevoke sits
// one tier below the destructive permissions precisely because it was believed
// to revoke user tokens.
//
// Admin sessions are deliberately left alone. Revoking them is a different
// action with a different blast radius and belongs behind its own permission at
// super_admin tier, not smuggled into the user-containment control.
func (h *Handler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	// The nil check is not defensive noise. This repository arrives as a
	// positional argument and cmd/admin-gateway has passed nil for it before, on
	// this same handler. A containment control that answers 200 while holding
	// nothing to revoke through is the defect this function was just fixed for,
	// so an unwired one says so instead of repeating it.
	if h.tokens == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "token_repository_not_configured")
		return
	}
	if err := h.tokens.RevokeAll(r.Context()); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminSessionRevoke, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"scope":  "all",
		"target": "user_refresh_tokens",
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "all_sessions_revoked"})
}

// ========== Audit Log ==========

// auditEntryView is the response projection of an audit row.
//
// FingerprintHash is deliberately absent. It is an HMAC of a device
// fingerprint, so it correlates events across accounts and across users; an
// operator investigating an event needs DeviceID, which identifies the same
// device without being a cross-account correlator.
//
// RiskScore is a hardcoded per-event-type severity tag, not a computed score.
// Treat it as an opaque label: values are not comparable between event types
// and may change as the event catalog grows.
type auditEntryView struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	UserID    string                 `json:"user_id,omitempty"`
	ClientID  string                 `json:"client_id,omitempty"`
	IP        string                 `json:"ip,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	DeviceID  string                 `json:"device_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	RiskScore int                    `json:"risk_score"`
}

// QueryAudit handles GET /admin/audit.
//
// Pagination shares parsePagination with the other admin list endpoints, so one
// default (50) and one cap (maxListLimit) apply across the whole gateway.
//
// total is the number of entries in the returned window: repository.AuditFilter
// has no counterpart that counts matches without returning them. The key is
// fixed here so that adding a true filtered count later changes a value, not the
// response shape.
func (h *Handler) QueryAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, offset := parsePagination(r)
	filter := repository.AuditFilter{
		UserID:    q.Get("user_id"),
		EventType: q.Get("event_type"),
		Limit:     limit,
		Offset:    offset,
	}

	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = &t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = &t
		}
	}

	entries, err := h.auditRepo.Query(r.Context(), filter)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	views := make([]auditEntryView, 0, len(entries))
	for _, e := range entries {
		views = append(views, auditEntryView{
			ID:        e.ID,
			Timestamp: e.Timestamp,
			EventType: e.EventType,
			UserID:    e.UserID,
			ClientID:  e.ClientID,
			IP:        e.IP,
			UserAgent: e.UserAgent,
			DeviceID:  e.DeviceID,
			Metadata:  e.Metadata,
			RiskScore: e.RiskScore,
		})
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"entries": views,
		"total":   len(views),
		"limit":   limit,
		"offset":  offset,
	})
}

// ========== Client Management ==========

// clientView is the response projection of a service client. SecretHash is the
// argon2id hash of the client secret and is never projected: GET on a client
// must not hand an operator's browser offline-crackable credential material.
type clientView struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Role         string    `json:"role"`
	Scopes       []string  `json:"scopes"`
	RedirectURIs []string  `json:"redirect_uris"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func toClientView(c *model.Client) clientView {
	scopes := c.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	redirects := c.RedirectURIs
	if redirects == nil {
		redirects = []string{}
	}
	return clientView{
		ID:           c.ID,
		Name:         c.Name,
		Role:         c.Role,
		Scopes:       scopes,
		RedirectURIs: redirects,
		Active:       c.Active,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}
}

// ListClients handles GET /admin/clients.
func (h *Handler) ListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.clients.List(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	views := make([]clientView, 0, len(clients))
	for _, c := range clients {
		views = append(views, toClientView(c))
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"clients": views,
		"total":   len(views),
	})
}

// GetClient handles GET /admin/clients/{id}.
func (h *Handler) GetClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_id")
		return
	}

	client, err := h.clients.GetByID(r.Context(), id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if client == nil {
		httputil.WriteError(w, http.StatusNotFound, "client_not_found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toClientView(client))
}

// CreateClient handles POST /admin/clients.
func (h *Handler) CreateClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string   `json:"name"`
		Role         string   `json:"role"`
		Scopes       []string `json:"scopes"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.Name == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_name")
		return
	}

	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	secretBytes, err := vaultcrypto.RandomBytes(32)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	secret := hex.EncodeToString(secretBytes)
	secretHash, err := vaultcrypto.HashPassword(secret)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	now := time.Now()
	client := &model.Client{
		ID:           id,
		Name:         req.Name,
		SecretHash:   secretHash,
		Role:         req.Role,
		Scopes:       req.Scopes,
		RedirectURIs: req.RedirectURIs,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := h.clients.Create(r.Context(), client); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminClientCreate, admin.ID, id, r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"client_name": req.Name,
	}, 0)

	httputil.WriteJSON(w, http.StatusCreated, map[string]string{
		"id":     id,
		"name":   req.Name,
		"secret": secret,
	})
}

// RevokeClient handles POST /admin/clients/{id}/revoke.
func (h *Handler) RevokeClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_id")
		return
	}

	if err := h.clients.Deactivate(r.Context(), id); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminClientRevoke, admin.ID, id, r.RemoteAddr, r.UserAgent(), "", "", nil, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// RotateClientSecret handles POST /admin/clients/{id}/rotate.
func (h *Handler) RotateClientSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_id")
		return
	}

	client, err := h.clients.GetByID(r.Context(), id)
	if err != nil || client == nil {
		httputil.WriteError(w, http.StatusNotFound, "client_not_found")
		return
	}

	secretBytes, err := vaultcrypto.RandomBytes(32)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	secret := hex.EncodeToString(secretBytes)
	secretHash, err := vaultcrypto.HashPassword(secret)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	client.SecretHash = secretHash
	client.UpdatedAt = time.Now()
	if err := h.clients.Update(r.Context(), client); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminClientRotate, admin.ID, id, r.RemoteAddr, r.UserAgent(), "", "", nil, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"status": "rotated",
		"secret": secret,
	})
}

// ========== Config Management ==========

// redactedConfigKeys are auth.admin_config entries that hold credential
// material rather than operator-facing runtime configuration. admin_token_hash
// is the Argon2id hash of the CLI admin token, written to this table by
// InitAdminToken and rotate-admin-token. GET /admin/config is a ConfigRead
// (viewer-tier) route, so returning the whole table would hand a read-only
// admin an offline-crackable hash of a privileged credential — the same class
// of secret clientView and adminView are careful never to project. The row is
// left in place (the CLI reads it directly); it is stripped from the response.
var redactedConfigKeys = map[string]bool{
	"admin_token_hash": true,
}

// GetConfig handles GET /admin/config. entries is a key/value object, not a
// list, so it carries no list envelope; an empty store is an empty object
// rather than null. Credential-bearing keys (see redactedConfigKeys) are
// stripped so a viewer-tier reader never receives them.
func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	entries, err := h.adminConfig.List(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if entries == nil {
		entries = map[string]string{}
	}
	for k := range redactedConfigKeys {
		delete(entries, k)
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// UpdateConfig handles PUT /admin/config/{key}.
func (h *Handler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_key")
		return
	}

	// Validate config key name — alphanumeric, underscores, dots only
	if !configKeyPattern.MatchString(key) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_key_format")
		return
	}

	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if err := h.adminConfig.Set(r.Context(), key, req.Value); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminConfigChange, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"config_key": key,
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "updated", "key": key})
}

// DeleteConfig handles DELETE /admin/config/{key}.
func (h *Handler) DeleteConfig(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_key")
		return
	}

	if err := h.adminConfig.Delete(r.Context(), key); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	admin := GetAdmin(r.Context())
	_ = h.auditLog.Log(r.Context(), audit.AdminConfigChange, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"config_key": key,
		"action":     "delete",
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted", "key": key})
}

// ========== Metrics ==========

// GetMetrics handles GET /admin/metrics.
func (h *Handler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	// Proxy to the main vault's metrics if available, or expose admin-specific metrics
	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"note":   "Admin-specific metrics not yet implemented",
	})
}

// ========== Admin User Management ==========

// ListAdmins handles GET /admin/admins.
// Results are paginated via enforced limit/offset query params (default 50,
// max 100) to bound the response size of an unbounded admin-user set.
func (h *Handler) ListAdmins(w http.ResponseWriter, r *http.Request) {
	admins, err := h.admins.List(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	limit, offset := parsePagination(r)
	total := len(admins)
	admins = paginate(admins, limit, offset)

	type adminView struct {
		ID          string     `json:"id"`
		Username    string     `json:"username"`
		Role        string     `json:"role"`
		TOTP        bool       `json:"totp_configured"`
		LockedUntil *time.Time `json:"locked_until,omitempty"`
		LastLoginAt *time.Time `json:"last_login_at,omitempty"`
		CreatedAt   time.Time  `json:"created_at"`
		CreatedBy   string     `json:"created_by,omitempty"`
	}

	views := make([]adminView, 0, len(admins))
	for _, a := range admins {
		views = append(views, adminView{
			ID:          a.ID,
			Username:    a.Username,
			Role:        a.Role,
			TOTP:        a.TOTPVerified,
			LockedUntil: a.LockedUntil,
			LastLoginAt: a.LastLoginAt,
			CreatedAt:   a.CreatedAt,
			CreatedBy:   a.CreatedBy,
		})
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"admins": views,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// CreateAdmin handles POST /admin/admins.
func (h *Handler) CreateAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if req.Username == "" || req.Password == "" || req.Role == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_fields")
		return
	}

	if !rbac.IsValidRole(req.Role) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_role")
		return
	}

	// Password minimum length for admin accounts
	if len(req.Password) < 20 {
		httputil.WriteError(w, http.StatusBadRequest, "password_too_short")
		return
	}

	// Check for existing username
	existing, err := h.admins.GetByUsername(r.Context(), req.Username)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if existing != nil {
		httputil.WriteError(w, http.StatusConflict, "username_exists")
		return
	}

	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	hash, err := vaultcrypto.HashPassword(req.Password, h.pepper)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	creator := GetAdmin(r.Context())
	now := time.Now()
	admin := &model.AdminUser{
		ID:           id,
		Username:     req.Username,
		PasswordHash: hash,
		Role:         req.Role,
		CreatedAt:    now,
		UpdatedAt:    now,
		CreatedBy:    creator.ID,
	}

	if err := h.admins.Create(r.Context(), admin); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	_ = h.auditLog.Log(r.Context(), audit.AdminAccountCreate, creator.ID, id, r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"new_admin_id":       id,
		"new_admin_username": req.Username,
		"new_admin_role":     req.Role,
	}, 0)

	httputil.WriteJSON(w, http.StatusCreated, map[string]string{
		"id":       id,
		"username": req.Username,
		"role":     req.Role,
	})
}

// RevokeAdmin handles POST /admin/admins/{id}/revoke.
func (h *Handler) RevokeAdmin(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing_id")
		return
	}

	actor := GetAdmin(r.Context())

	// Prevent self-revocation
	if actor.ID == id {
		httputil.WriteError(w, http.StatusBadRequest, "cannot_revoke_self")
		return
	}

	// Revoke admin first — sessions CASCADE delete via FK.
	// This eliminates the race window where an in-flight request could
	// pass SessionAuth between session revoke and admin revoke.
	if err := h.admins.Revoke(r.Context(), id); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	_ = h.auditLog.Log(r.Context(), audit.AdminAccountRevoke, actor.ID, id, r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
		"revoked_admin_id": id,
	}, 0)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
