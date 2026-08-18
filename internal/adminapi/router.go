package adminapi

import (
	"net/http"
	"time"

	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/internal/repository"
)

// RouterOpts configures the admin gateway router.
type RouterOpts struct {
	// DevMode disables LocalOnly and RejectProxyHeaders middleware
	// for development behind ingress controllers.
	DevMode bool

	// Killswitch enables the killswitch panic on non-loopback requests (default: true).
	// When enabled, the pod crashes on breach attempts. When disabled, returns 403.
	Killswitch bool

	// AuditRepo is used by the killswitch to log breach attempts before crashing.
	AuditRepo repository.AuditRepository
}

// NewRouter creates the admin gateway HTTP mux with all routes and middleware.
func NewRouter(auth *AuthHandler, api *Handler, opts ...RouterOpts) http.Handler {
	mux := http.NewServeMux()

	sessionAuth := SessionAuth(auth.sessions, auth.admins, api.auditLog)

	// withPerm chains SessionAuth then RBACCheck for one route. It is a closure
	// so every guarded route shares the one audit logger without threading it
	// through a fourth positional argument at each call site; RBACCheck writes
	// an admin_authz_denied record on a permission denial (ASVS V16.3.2).
	withPerm := func(sessionAuth func(http.Handler) http.Handler, perm rbac.Permission, h http.HandlerFunc) http.Handler {
		return sessionAuth(RBACCheck(perm, api.auditLog)(h))
	}

	// Public: login (rate-limited — 10 attempts per minute per IP)
	loginRL := NewLoginRateLimit(10, time.Minute)
	mux.HandleFunc("POST /admin/auth/login", loginRL.Wrap(auth.Login))

	// Authenticated (session only, no RBAC)
	mux.Handle("POST /admin/auth/logout", sessionAuth(http.HandlerFunc(auth.Logout)))
	mux.Handle("GET /admin/status", sessionAuth(http.HandlerFunc(auth.Status)))

	// TOTP setup (allowed without 2FA being verified — that's the point)
	mux.Handle("POST /admin/admins/me/totp/setup", sessionAuth(http.HandlerFunc(auth.TOTPSetup)))
	mux.Handle("POST /admin/admins/me/totp/verify", sessionAuth(http.HandlerFunc(auth.TOTPVerify)))

	// Key management
	mux.Handle("GET /admin/keys", withPerm(sessionAuth, rbac.KeysList, api.ListKeys))
	mux.Handle("POST /admin/keys/rotate", withPerm(sessionAuth, rbac.KeysRotate, api.RotateKey))
	mux.Handle("DELETE /admin/keys/{kid}", withPerm(sessionAuth, rbac.KeysRevoke, api.RevokeKey))

	// User management
	mux.Handle("GET /admin/users", withPerm(sessionAuth, rbac.UsersList, api.ListUsers))
	mux.Handle("GET /admin/users/{id}", withPerm(sessionAuth, rbac.UsersRead, api.GetUser))
	mux.Handle("POST /admin/users/import", withPerm(sessionAuth, rbac.UsersImport, api.ImportUsers))
	mux.Handle("POST /admin/users/{id}/lock", withPerm(sessionAuth, rbac.UsersLock, api.LockUser))
	mux.Handle("POST /admin/users/{id}/unlock", withPerm(sessionAuth, rbac.UsersUnlock, api.UnlockUser))
	mux.Handle("DELETE /admin/users/{id}", withPerm(sessionAuth, rbac.UsersDelete, api.DeleteUser))

	// Session management.
	//
	// The two routes read and write different things, so they are gated
	// differently. GET /admin/sessions lists ADMIN sessions: the live roster of
	// who can administer the deployment, with each one's source IP and user
	// agent. rbac.go keeps admins:manage at super_admin because that roster is
	// reconnaissance for an attacker holding a lower-tier admin session, and
	// this route hands over the same thing, so it takes the same permission.
	// sessions:list stays viewer-tier and describes visibility into user
	// sessions, which this route does not provide.
	//
	// POST /admin/sessions/revoke-all is the global USER refresh-token nuke and
	// keeps sessions:revoke, the permission written for exactly that.
	mux.Handle("GET /admin/sessions", withPerm(sessionAuth, rbac.AdminsManage, api.ListSessions))
	mux.Handle("POST /admin/sessions/revoke-all", withPerm(sessionAuth, rbac.SessionsRevoke, api.RevokeAllSessions))

	// Audit log
	mux.Handle("GET /admin/audit", withPerm(sessionAuth, rbac.AuditRead, api.QueryAudit))

	// Client management
	mux.Handle("GET /admin/clients", withPerm(sessionAuth, rbac.ClientsList, api.ListClients))
	mux.Handle("GET /admin/clients/{id}", withPerm(sessionAuth, rbac.ClientsRead, api.GetClient))
	mux.Handle("POST /admin/clients", withPerm(sessionAuth, rbac.ClientsCreate, api.CreateClient))
	mux.Handle("POST /admin/clients/{id}/revoke", withPerm(sessionAuth, rbac.ClientsRevoke, api.RevokeClient))
	mux.Handle("POST /admin/clients/{id}/rotate", withPerm(sessionAuth, rbac.ClientsRotate, api.RotateClientSecret))

	// Custom roles catalog
	mux.Handle("GET /admin/roles", withPerm(sessionAuth, rbac.RolesList, api.ListRoles))
	mux.Handle("POST /admin/roles", withPerm(sessionAuth, rbac.RolesCreate, api.CreateRole))
	mux.Handle("DELETE /admin/roles/{name}", withPerm(sessionAuth, rbac.RolesDelete, api.DeleteRole))

	// Per-app email branding + template overrides (white-label auth emails)
	mux.Handle("GET /admin/email-branding", withPerm(sessionAuth, rbac.EmailRead, api.ListEmailBranding))
	mux.Handle("GET /admin/email-branding/{app}", withPerm(sessionAuth, rbac.EmailRead, api.GetEmailBranding))
	mux.Handle("PUT /admin/email-branding/{app}", withPerm(sessionAuth, rbac.EmailWrite, api.PutEmailBranding))
	mux.Handle("DELETE /admin/email-branding/{app}", withPerm(sessionAuth, rbac.EmailDelete, api.DeleteEmailBranding))
	mux.Handle("GET /admin/email-templates", withPerm(sessionAuth, rbac.EmailRead, api.ListEmailTemplates))
	mux.Handle("POST /admin/email-templates/preview", withPerm(sessionAuth, rbac.EmailWrite, api.PreviewEmailTemplate))
	mux.Handle("GET /admin/email-templates/{app}/{name}", withPerm(sessionAuth, rbac.EmailRead, api.GetEmailTemplate))
	mux.Handle("PUT /admin/email-templates/{app}/{name}", withPerm(sessionAuth, rbac.EmailWrite, api.PutEmailTemplate))
	mux.Handle("DELETE /admin/email-templates/{app}/{name}", withPerm(sessionAuth, rbac.EmailDelete, api.DeleteEmailTemplate))

	// Config management
	mux.Handle("GET /admin/config", withPerm(sessionAuth, rbac.ConfigRead, api.GetConfig))
	mux.Handle("PUT /admin/config/{key}", withPerm(sessionAuth, rbac.ConfigWrite, api.UpdateConfig))
	mux.Handle("DELETE /admin/config/{key}", withPerm(sessionAuth, rbac.ConfigWrite, api.DeleteConfig))

	// Metrics: the route and its permission gate exist, the implementation does
	// not. It answers 501 rather than a placeholder 200 so a caller cannot
	// mistake an empty stub for a working metrics feed.
	mux.Handle("GET /admin/metrics", withPerm(sessionAuth, rbac.MetricsRead, notImplemented))

	// Admin user management
	mux.Handle("GET /admin/admins", withPerm(sessionAuth, rbac.AdminsManage, api.ListAdmins))
	mux.Handle("POST /admin/admins", withPerm(sessionAuth, rbac.AdminsCreate, api.CreateAdmin))
	mux.Handle("POST /admin/admins/{id}/revoke", withPerm(sessionAuth, rbac.AdminsRevoke, api.RevokeAdmin))

	// HTML frontend routes — no server-side auth on page routes.
	// Browsers send GET without Authorization header, so sessionAuth would block
	// page loads with a JSON 401. Client-side JS handles auth redirection.
	// Security: admin gateway runs behind mTLS + loopback-only; pages are static
	// shells with no secrets. All data comes from auth-protected API endpoints.
	frontend := NewFrontendHandler()
	mux.HandleFunc("GET /admin/", frontend.Dashboard)
	mux.HandleFunc("GET /admin/login", frontend.LoginPage)
	mux.HandleFunc("GET /admin/ui/users", frontend.UsersPage)
	mux.HandleFunc("GET /admin/ui/keys", frontend.KeysPage)
	mux.HandleFunc("GET /admin/ui/sessions", frontend.SessionsPage)
	mux.HandleFunc("GET /admin/ui/audit", frontend.AuditPage)
	mux.HandleFunc("GET /admin/ui/clients", frontend.ClientsPage)
	mux.HandleFunc("GET /admin/ui/admins", frontend.AdminsPage)
	mux.HandleFunc("GET /admin/ui/config", frontend.ConfigPage)
	mux.HandleFunc("GET /admin/ui/users/{id}", frontend.UserDetailPage)
	mux.HandleFunc("GET /admin/ui/totp-setup", frontend.TOTPSetupPage)

	// Static assets
	mux.Handle("GET /admin/static/", http.HandlerFunc(frontend.ServeStatic))

	// Apply global middleware chain.
	// Production: LocalOnly → RejectProxyHeaders → SecurityHeaders → RequestID → Recovery → MaxBody(64KB)
	// Dev mode:   SecurityHeaders → RequestID → Recovery → MaxBody(64KB) (loopback checks skipped)
	var o RouterOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	var handler http.Handler = mux
	handler = MaxBody(64 * 1024)(handler)
	handler = Recovery(handler)
	handler = RequestID(handler)
	handler = SecurityHeaders(handler)
	if !o.DevMode {
		handler = RejectProxyHeaders(handler)
		handler = LocalOnly(o.Killswitch, o.AuditRepo)(handler)
	}

	return handler
}

// notImplemented answers a route that is mounted and permission-gated but has
// no implementation behind it, using the standard error envelope.
func notImplemented(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteError(w, http.StatusNotImplemented, "not_implemented")
}
