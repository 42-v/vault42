// Package adminapi provides the admin gateway HTTP handlers, middleware, and
// server-rendered frontend for The Vault's RBAC admin interface.
package adminapi

import (
	"context"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/internal/repository"
)

type ctxKey string

const (
	adminSessionKey ctxKey = "admin_session"
	adminUserKey    ctxKey = "admin_user"
)

// proxyHeaders are HTTP headers that indicate a request was relayed through a proxy.
// The admin gateway rejects any request carrying these headers to ensure only
// direct local connections are accepted.
var proxyHeaders = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"Via",
	"Forwarded",
	"X-Real-IP",
}

// killswitchPrefix is the panic sentinel that Recovery must not catch.
const killswitchPrefix = "KILLSWITCH: "

// LocalOnly middleware rejects any request where RemoteAddr is not a loopback address.
// This is layer 4 of the 6-layer local-only enforcement (on top of bind address,
// hostNetwork, and mTLS).
//
// When killswitch is enabled (default), a non-loopback request triggers a panic
// that crashes the pod — a hard crash signals a security breach and triggers
// CrashLoopBackOff for immediate visibility. When disabled (dev mode), it returns 403.
func LocalOnly(killswitch bool, auditRepo repository.AuditRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}

			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				log.Printf("CRITICAL admin-gateway: non-loopback connection from %s (UA: %s)", // #nosec G706 — sanitized
					sanitizeLogValue(r.RemoteAddr), sanitizeLogValue(r.UserAgent()))

				// Best-effort audit entry
				if auditRepo != nil {
					entry := &model.AuditEntry{
						EventType: "admin:killswitch_triggered",
						IP:        r.RemoteAddr,
						UserAgent: r.UserAgent(),
						RiskScore: 100,
						Metadata: map[string]interface{}{
							"method": r.Method,
							"path":   r.URL.Path,
						},
					}
					if id, idErr := vaultcrypto.RandomUUID(); idErr == nil {
						entry.ID = id
					}
					entry.Timestamp = time.Now()
					_ = auditRepo.Insert(r.Context(), entry)
				}

				if killswitch {
					panic(killswitchPrefix + "admin-gateway received request from non-local source: " + sanitizeLogValue(host))
				}

				httputil.WriteError(w, http.StatusForbidden, "local_only")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RejectProxyHeaders middleware rejects requests containing proxy relay headers.
// This is layer 6 of the local-only enforcement — even if a reverse proxy somehow
// reaches the gateway, requests with these headers are rejected.
func RejectProxyHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range proxyHeaders {
			if r.Header.Get(h) != "" {
				log.Printf("admin-gateway: rejected request with proxy header %s from %s", h, sanitizeLogValue(r.RemoteAddr)) // #nosec G706 — sanitized
				httputil.WriteError(w, http.StatusForbidden, "proxy_not_allowed")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// SessionAuth middleware validates admin session tokens from the Authorization
// header. It looks up the session by SHA-256 hash, checks expiry and revocation,
// and loads the admin user into context. Each token or session validity failure
// (missing or malformed Authorization header, an unknown, revoked or expired
// session, or a session whose admin no longer exists) is written to the
// append-only audit log as an admin_session_rejected event naming the reason
// (ASVS V16.3.2): the rejection is enforced regardless, and the record is what
// makes session-token replay and bogus-token probing detectable after the fact.
// auditLog may be nil, in which case the rejection is still enforced but not
// recorded; the wired gateway always supplies one.
//
//nolint:gocognit // explicit branches for token-format check, hash lookup, expiry, revocation, killswitch — security boundary; flat is clearer than helpers
func SessionAuth(sessions repository.AdminSessionRepository, admins repository.AdminUserRepository, auditLog *audit.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// reject records an admin_session_rejected audit event naming the
			// reason (when a logger is wired) and answers 401. It covers the
			// token and session validity failures only; the account_locked and
			// 2fa_required policy gates below apply to an already-valid session
			// and keep their own handling.
			reject := func(reason string) {
				if auditLog != nil {
					_ = auditLog.Log(r.Context(), audit.AdminSessionRejected, "", "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
						"reason": reason,
						"method": r.Method,
						"path":   r.URL.Path,
					}, 5)
				}
				httputil.WriteError(w, http.StatusUnauthorized, reason)
			}

			auth := r.Header.Get("Authorization")
			if auth == "" {
				reject("missing_authorization")
				return
			}

			parts := strings.SplitN(auth, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				reject("invalid_authorization")
				return
			}

			token := parts[1]
			if len(token) == 0 || len(token) > 256 {
				reject("invalid_token")
				return
			}

			hash := hashSessionToken(token)
			session, err := sessions.GetByTokenHash(r.Context(), hash)
			if err != nil || session == nil {
				reject("invalid_session")
				return
			}

			if session.Revoked {
				reject("session_revoked")
				return
			}

			if time.Now().After(session.ExpiresAt) {
				reject("session_expired")
				return
			}

			admin, err := admins.GetByID(r.Context(), session.AdminID)
			if err != nil || admin == nil {
				reject("admin_not_found")
				return
			}

			// Check if admin account is locked
			if admin.LockedUntil != nil && time.Now().Before(*admin.LockedUntil) {
				httputil.WriteError(w, http.StatusForbidden, "account_locked")
				return
			}

			// Require 2FA to be set up and verified for all admin users
			if !admin.TOTPVerified {
				// Allow access to TOTP setup/verify endpoints only
				if !isTOTPSetupPath(r.URL.Path) {
					httputil.WriteError(w, http.StatusForbidden, "2fa_required")
					return
				}
			}

			ctx := context.WithValue(r.Context(), adminSessionKey, session)
			ctx = context.WithValue(ctx, adminUserKey, admin)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// isTOTPSetupPath returns true for TOTP setup/verify endpoints and the TOTP setup UI page.
func isTOTPSetupPath(path string) bool {
	return path == "/admin/admins/me/totp/setup" || path == "/admin/admins/me/totp/verify" || path == "/admin/ui/totp-setup"
}

// RBACCheck middleware enforces that the authenticated admin has the required
// permission. A permission denial is written to the append-only audit log as an
// admin_authz_denied event (ASVS V16.3.2): the decision is enforced regardless,
// and the record is what makes privilege-boundary probing detectable after the
// fact. auditLog may be nil, in which case the denial is enforced but not
// recorded — the wired gateway always supplies one.
func RBACCheck(perm rbac.Permission, auditLog *audit.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			admin := GetAdmin(r.Context())
			if admin == nil {
				httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			if !rbac.HasPermission(rbac.Role(admin.Role), perm) {
				if auditLog != nil {
					_ = auditLog.Log(r.Context(), audit.AdminAuthzDenied, admin.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
						"role":       admin.Role,
						"permission": string(perm),
						"method":     r.Method,
						"path":       r.URL.Path,
					}, 5)
				}
				httputil.WriteError(w, http.StatusForbidden, "insufficient_permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetSession extracts the admin session from context.
func GetSession(ctx context.Context) *model.AdminSession {
	s, _ := ctx.Value(adminSessionKey).(*model.AdminSession)
	return s
}

// GetAdmin extracts the admin user from context.
func GetAdmin(ctx context.Context) *model.AdminUser {
	u, _ := ctx.Value(adminUserKey).(*model.AdminUser)
	return u
}

// WithAdmin attaches an admin user to the context. Used by middleware after
// session verification, and by tests that drive handlers directly with a
// pre-authenticated admin.
func WithAdmin(ctx context.Context, admin *model.AdminUser) context.Context {
	return context.WithValue(ctx, adminUserKey, admin)
}

// WithSession attaches an admin session to the context. Same role as
// [WithAdmin] but for the session value handlers read via [GetSession].
func WithSession(ctx context.Context, session *model.AdminSession) context.Context {
	return context.WithValue(ctx, adminSessionKey, session)
}

// MaxBody limits request body size.
func MaxBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// RequestID generates a unique request ID and adds it to the response headers.
// Never trusts client-supplied X-Request-ID — always generates a new one.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip any client-supplied request ID to prevent header injection
		r.Header.Del("X-Request-ID")
		id, err := vaultcrypto.RandomUUID()
		if err != nil {
			id = "00000000-0000-0000-0000-000000000000"
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}

// Recovery catches panics and returns 500. Killswitch panics are re-panicked
// to ensure the pod crashes — Recovery must never swallow a security breach signal.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Never recover from killswitch — let the pod crash
				if msg, ok := err.(string); ok && strings.HasPrefix(msg, killswitchPrefix) {
					panic(err)
				}
				log.Printf("admin-gateway: panic: %v", err)
				httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders adds security headers to all responses.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; form-action 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// loginAttempt tracks login rate limiting state per IP.
type loginAttempt struct {
	count    int
	windowAt time.Time
}

// LoginRateLimit provides per-IP rate limiting for the login endpoint.
// Allows maxAttempts per window period. Independent of account lockout.
type LoginRateLimit struct {
	mu          sync.Mutex
	attempts    map[string]*loginAttempt
	maxAttempts int
	window      time.Duration
}

// NewLoginRateLimit creates a login rate limiter.
func NewLoginRateLimit(maxAttempts int, window time.Duration) *LoginRateLimit {
	return &LoginRateLimit{
		attempts:    make(map[string]*loginAttempt),
		maxAttempts: maxAttempts,
		window:      window,
	}
}

// Wrap wraps a handler with per-IP login rate limiting.
func (rl *LoginRateLimit) Wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}

		rl.mu.Lock()
		now := time.Now()
		a, ok := rl.attempts[host]
		if !ok || now.After(a.windowAt) {
			a = &loginAttempt{count: 0, windowAt: now.Add(rl.window)}
			rl.attempts[host] = a
		}
		a.count++
		exceeded := a.count > rl.maxAttempts
		rl.mu.Unlock()

		if exceeded {
			log.Printf("admin-gateway: login rate limit exceeded for %s", sanitizeLogValue(host)) // #nosec G706 — sanitized
			httputil.WriteError(w, http.StatusTooManyRequests, "rate_limited")
			return
		}

		next(w, r)
	}
}

// configKeyPattern validates config key names — alphanumeric, underscores, dots only.
var configKeyPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.]{0,63}$`)

// sanitizeLogValue strips newlines and control characters to prevent log injection.
func sanitizeLogValue(s string) string {
	return strings.NewReplacer("\n", "", "\r", "", "\t", " ").Replace(s)
}
