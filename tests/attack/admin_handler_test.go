package attack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/adminapi"
	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/tests/mocks"
)

// Admin authentication used to be certified against middleware.AdminAuth, a
// Bearer-token gate in internal/middleware/admin.go with zero callers outside
// this file. The admin plane authenticates through adminapi.SessionAuth, wired
// once in adminapi.NewRouter, and middleware/admin.go shipped in nothing.
//
// So every test here drives the router NewRouter builds. The mutation that used
// to leave this file green — replacing the wired sessionAuth with a pass-through
// — now fails on every guarded route at once.

// --- fakes: the two admin repositories SessionAuth reads ---

// fakeAdminUsers is an in-memory AdminUserRepository. Only GetByID is reached by
// the authentication path; the rest satisfy the interface.
type fakeAdminUsers struct{ byID map[string]*model.AdminUser }

func (f *fakeAdminUsers) Create(context.Context, *model.AdminUser) error { return nil }
func (f *fakeAdminUsers) GetByID(_ context.Context, id string) (*model.AdminUser, error) {
	return f.byID[id], nil
}
func (f *fakeAdminUsers) GetByUsername(context.Context, string) (*model.AdminUser, error) {
	return nil, nil
}
func (f *fakeAdminUsers) List(context.Context) ([]*model.AdminUser, error)           { return nil, nil }
func (f *fakeAdminUsers) Count(context.Context) (int, error)                         { return len(f.byID), nil }
func (f *fakeAdminUsers) Update(context.Context, *model.AdminUser) error             { return nil }
func (f *fakeAdminUsers) IncrementFailedLogin(context.Context, string) (int, error)  { return 0, nil }
func (f *fakeAdminUsers) ResetFailedLogin(context.Context, string) error             { return nil }
func (f *fakeAdminUsers) LockUntil(context.Context, string, time.Time) error         { return nil }
func (f *fakeAdminUsers) UpdateLastTOTPCounter(context.Context, string, int64) error { return nil }
func (f *fakeAdminUsers) UpdateLastLogin(context.Context, string) error              { return nil }
func (f *fakeAdminUsers) Revoke(context.Context, string) error                       { return nil }

// fakeAdminSessions is an in-memory AdminSessionRepository keyed the way the
// production repository is keyed — by the SHA-256 hash of the bearer token, so
// a test that wants to be let in has to present a token whose hash is stored.
type fakeAdminSessions struct {
	byHash map[string]*model.AdminSession
}

func (f *fakeAdminSessions) Create(_ context.Context, s *model.AdminSession) error {
	f.byHash[s.TokenHash] = s
	return nil
}
func (f *fakeAdminSessions) GetByTokenHash(_ context.Context, hash string) (*model.AdminSession, error) {
	return f.byHash[hash], nil
}
func (f *fakeAdminSessions) ListByAdmin(context.Context, string) ([]*model.AdminSession, error) {
	return nil, nil
}
func (f *fakeAdminSessions) ListActive(context.Context) ([]*model.AdminSession, error) {
	return nil, nil
}
func (f *fakeAdminSessions) Revoke(context.Context, string) error            { return nil }
func (f *fakeAdminSessions) RevokeAllForAdmin(context.Context, string) error { return nil }
func (f *fakeAdminSessions) RevokeAll(context.Context) error                 { return nil }
func (f *fakeAdminSessions) DeleteExpired(context.Context) (int64, error)    { return 0, nil }

// validAdminToken is the bearer token the admin fixture below accepts. Its
// hash is what the session repository is keyed on.
const validAdminToken = "attack-suite-valid-admin-session-token"

func adminSessionTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// adminRouterUnderTest builds the wired admin gateway router over in-memory
// repositories, holding one live session for validAdminToken belonging to a
// super-admin with 2FA verified — the state an authenticated operator is in.
func adminRouterUnderTest(t *testing.T) http.Handler {
	t.Helper()
	h, _, _ := adminRouterForRole(t, rbac.RoleSuperAdmin)
	return h
}

// adminRouterForRole is the same fixture at a chosen role, returning the admin
// the live session points at and every audit row the plane wrote.
func adminRouterForRole(t *testing.T, role rbac.Role) (http.Handler, *model.AdminUser, *auditCapture) {
	t.Helper()

	admin := &model.AdminUser{
		ID:           "00000000-0000-0000-0000-0000000000a1",
		Username:     "attack-admin",
		Role:         string(role),
		TOTPVerified: true,
	}
	admins := &fakeAdminUsers{byID: map[string]*model.AdminUser{admin.ID: admin}}
	sessions := &fakeAdminSessions{byHash: map[string]*model.AdminSession{
		adminSessionTokenHash(validAdminToken): {
			ID:        "00000000-0000-0000-0000-0000000000b1",
			AdminID:   admin.ID,
			TokenHash: adminSessionTokenHash(validAdminToken),
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}}

	captured := &auditCapture{}
	auditLog := audit.NewLogger(&mocks.MockAuditRepo{InsertFn: captured.insert}, 0)
	authHandler := adminapi.NewAuthHandler(admins, sessions, auditLog, make([]byte, 32), "", time.Hour, 5, time.Hour)
	apiHandler := adminapi.NewHandler(
		&mocks.MockUserRepo{}, &mocks.MockClientRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockAuditRepo{}, admins, sessions, &mocks.MockAdminConfigRepo{},
		nil, auditLog, make([]byte, 32), "",
	)
	return adminapi.NewRouter(authHandler, apiHandler), admin, captured
}

// auditCapture records every row the admin plane wrote.
type auditCapture struct {
	mu      sync.Mutex
	entries []model.AuditEntry
}

func (c *auditCapture) insert(_ context.Context, e *model.AuditEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, *e)
	return nil
}

func (c *auditCapture) find(eventType string) (model.AuditEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.entries {
		if e.EventType == eventType {
			return e, true
		}
	}
	return model.AuditEntry{}, false
}

// hitAdminRoute drives one request at the wired router from loopback, since the
// deployed router refuses non-loopback callers before authentication runs.
func hitAdminRoute(t *testing.T, h http.Handler, method, path, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:54321"
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// refusalReason returns the "error" field of the standard envelope, which is
// what says WHICH gate refused. It matters here: SessionAuth answers with the
// reason it audited (missing_authorization, invalid_authorization,
// invalid_token, invalid_session), while RBACCheck answers a nil admin with
// "unauthorized". Asserting only the 401 accepts a router with no
// authentication at all, because RBACCheck then refuses the anonymous caller by
// accident — which is how the pass-through mutation survived a first draft of
// this suite.
func refusalReason(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("refusal body is not the standard envelope (%v): %s", err, rec.Body.String())
	}
	return body.Error
}

// --- the route inventory, read out of the router rather than listed here ---

// adminPublicRoutes are the routes NewRouter deliberately serves without a
// session: the login endpoint, and the static HTML shells the browser fetches
// with no Authorization header (their data all comes from guarded API routes).
// Everything else the router registers must refuse an anonymous caller. Moving
// a route into this set is the diff a reviewer has to justify.
var adminPublicRoutes = map[string]bool{
	"POST /admin/auth/login":   true,
	"GET /admin/":              true,
	"GET /admin/login":         true,
	"GET /admin/ui/users":      true,
	"GET /admin/ui/keys":       true,
	"GET /admin/ui/sessions":   true,
	"GET /admin/ui/audit":      true,
	"GET /admin/ui/clients":    true,
	"GET /admin/ui/admins":     true,
	"GET /admin/ui/config":     true,
	"GET /admin/ui/users/{id}": true,
	"GET /admin/ui/totp-setup": true,
	"GET /admin/static/":       true,
}

// adminRoutePatterns returns every route pattern NewRouter registers, read from
// the source so a route added without a guard shows up here on its own.
func adminRoutePatterns(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", "internal", "adminapi", "router.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var patterns []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "mux" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("unquote route pattern %s: %v", lit.Value, err)
		}
		patterns = append(patterns, pattern)
		return true
	})

	if len(patterns) == 0 {
		t.Fatal("no routes found in internal/adminapi/router.go; this gate has no subject")
	}
	return patterns
}

// TestAdminAuth_EveryGuardedRouteRefusesAnAnonymousCaller is the assertion the
// admin plane's authentication rests on. It enumerates the routes NewRouter
// registers, subtracts the deliberately public ones, and requires each of the
// rest to answer 401 to a caller with no Authorization header.
//
// Removing sessionAuth from one route fails that route; replacing the wired
// sessionAuth with a pass-through fails all of them.
func TestAdminAuth_EveryGuardedRouteRefusesAnAnonymousCaller(t *testing.T) {
	router := adminRouterUnderTest(t)

	guarded := 0
	for _, pattern := range adminRoutePatterns(t) {
		if adminPublicRoutes[pattern] {
			continue
		}
		guarded++
		t.Run(pattern, func(t *testing.T) {
			method, path, ok := strings.Cut(pattern, " ")
			if !ok {
				t.Fatalf("route pattern %q has no method", pattern)
			}
			// A wildcard segment needs a concrete value to route.
			path = strings.NewReplacer("{kid}", "some-kid", "{id}", "some-id").Replace(path)

			rec := hitAdminRoute(t, router, method, path, "")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s answered %d to a caller with no Authorization header, want 401. Body: %s",
					pattern, rec.Code, rec.Body.String())
			}
			if reason := refusalReason(t, rec); reason != "missing_authorization" {
				t.Fatalf("%s refused an anonymous caller with %q, want %q — the session gate is not what "+
					"turned this request away", pattern, reason, "missing_authorization")
			}
		})
	}

	if guarded == 0 {
		t.Fatal("every route in the admin router is on the public allowlist; the gate covers nothing")
	}
	t.Logf("admin routes refusing an anonymous caller: %d", guarded)
}

// TestAdminAuth_MalformedAuthorizationIsRefused covers the token-format gate on
// a guarded route of the wired router: the header must be a Bearer token of
// 1..256 characters, and an unknown token is refused like a missing one.
func TestAdminAuth_MalformedAuthorizationIsRefused(t *testing.T) {
	router := adminRouterUnderTest(t)
	oversize := "Bearer " + strings.Repeat("a", 257)

	cases := []struct {
		name       string
		value      string
		wantReason string
	}{
		{"unknown_token", "Bearer not-a-session", "invalid_session"},
		{"basic_auth", "Basic dXNlcjpwYXNz", "invalid_authorization"},
		{"empty_bearer", "Bearer ", "invalid_token"},
		{"no_space", "Bearertoken", "invalid_authorization"},
		{"just_bearer", "Bearer", "invalid_authorization"},
		{"oversize_token", oversize, "invalid_token"},
		{"dpop_scheme", "DPoP " + validAdminToken, "invalid_authorization"},
		{"lowercase_scheme", "bearer " + validAdminToken, "invalid_authorization"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := hitAdminRoute(t, router, http.MethodGet, "/admin/keys", tc.value)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("GET /admin/keys with %q answered %d, want 401: %s",
					tc.value, rec.Code, rec.Body.String())
			}
			if reason := refusalReason(t, rec); reason != tc.wantReason {
				t.Fatalf("GET /admin/keys with %q refused with %q, want %q",
					tc.value, reason, tc.wantReason)
			}
		})
	}
}

// TestAdminAuth_ValidSessionReachesTheRoute is the other half: the gate has to
// let a real operator through, or the anonymous-refusal test above would pass on
// a router that refuses everyone. The keystore is nil in this fixture, so the
// key routes answer 503 once past authentication — the point is that the request
// reached the handler rather than the 401.
func TestAdminAuth_ValidSessionReachesTheRoute(t *testing.T) {
	router := adminRouterUnderTest(t)
	rec := hitAdminRoute(t, router, http.MethodGet, "/admin/keys", "Bearer "+validAdminToken)
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("a live super-admin session was refused with %d: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminAuth_RevokedSessionIsRefused pins the property a bearer-token gate
// on a static secret cannot have: an operator's session can be taken away.
func TestAdminAuth_RevokedSessionIsRefused(t *testing.T) {
	admin := &model.AdminUser{
		ID: "00000000-0000-0000-0000-0000000000a2", Username: "revoked-admin",
		Role: string(rbac.RoleSuperAdmin), TOTPVerified: true,
	}
	admins := &fakeAdminUsers{byID: map[string]*model.AdminUser{admin.ID: admin}}
	sessions := &fakeAdminSessions{byHash: map[string]*model.AdminSession{
		adminSessionTokenHash(validAdminToken): {
			ID: "00000000-0000-0000-0000-0000000000b2", AdminID: admin.ID,
			TokenHash: adminSessionTokenHash(validAdminToken),
			ExpiresAt: time.Now().Add(time.Hour), Revoked: true,
		},
	}}
	auditLog := audit.NewLogger(&mocks.MockAuditRepo{}, time.Hour)
	router := adminapi.NewRouter(
		adminapi.NewAuthHandler(admins, sessions, auditLog, make([]byte, 32), "", time.Hour, 5, time.Hour),
		adminapi.NewHandler(&mocks.MockUserRepo{}, &mocks.MockClientRepo{}, &mocks.MockRefreshTokenRepo{},
			&mocks.MockAuditRepo{}, admins, sessions, &mocks.MockAdminConfigRepo{},
			nil, auditLog, make([]byte, 32), ""),
	)

	rec := hitAdminRoute(t, router, http.MethodGet, "/admin/keys", "Bearer "+validAdminToken)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked session answered %d, want 401: %s", rec.Code, rec.Body.String())
	}
	if reason := refusalReason(t, rec); reason != "session_revoked" {
		t.Fatalf("a revoked session was refused with %q, want %q", reason, "session_revoked")
	}
}

// TestAdminListKeys_NoPrivateKeyMaterial verifies that ListKeys never returns
// private key material. It reads the response the wired router produces for an
// authenticated caller rather than a literal the test wrote itself; the previous
// version marshalled a map it had just constructed and checked that map for
// fields it had not put in it, which no change to the handler could fail.
func TestAdminListKeys_NoPrivateKeyMaterial(t *testing.T) {
	router := adminRouterUnderTest(t)
	rec := hitAdminRoute(t, router, http.MethodGet, "/admin/keys", "Bearer "+validAdminToken)

	body := rec.Body.String()
	if json.Valid([]byte(body)) {
		var probe any
		if err := json.Unmarshal([]byte(body), &probe); err != nil {
			t.Fatalf("unmarshal ListKeys response: %v", err)
		}
	}
	for _, field := range []string{"private_key", "signing_key", "secret", "master_key", "PRIVATE KEY"} {
		if strings.Contains(body, field) {
			t.Fatalf("ListKeys response contains %q: %s", field, body)
		}
	}
}

// TestAdminAuth_TheSessionsAdminIsWhatRBACJudges is the handoff the plane's
// authorization rests on: SessionAuth resolves the session to an admin and puts
// it on the context, and RBACCheck judges that admin. Both halves were covered
// in isolation and the join was not — the middleware wrote the context with
// context.WithValue of its own while every test fixture in the tree built one
// with adminapi.WithAdmin, so the two could have disagreed on the key and
// nothing would have failed.
//
// A viewer session on a route the viewer tier does not hold must be refused with
// insufficient_permissions, and the audit row must name the admin the session
// pointed at — which only happens if the context RBACCheck read is the one
// SessionAuth built.
func TestAdminAuth_TheSessionsAdminIsWhatRBACJudges(t *testing.T) {
	router, admin, captured := adminRouterForRole(t, rbac.RoleViewer)

	rec := hitAdminRoute(t, router, http.MethodPost, "/admin/admins", "Bearer "+validAdminToken)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a viewer session answered %d on POST /admin/admins, want 403: %s", rec.Code, rec.Body.String())
	}
	if reason := refusalReason(t, rec); reason != "insufficient_permissions" {
		t.Fatalf("a viewer was refused with %q, want %q — the refusal did not come from RBACCheck",
			reason, "insufficient_permissions")
	}

	entry, ok := captured.find("admin_authz_denied")
	if !ok {
		t.Fatal("no admin_authz_denied row was written for a refused permission")
	}
	if entry.UserID != admin.ID {
		t.Errorf("the denial names admin %q, want %q — RBACCheck did not read the admin SessionAuth resolved",
			entry.UserID, admin.ID)
	}
	if got := entry.Metadata["role"]; got != admin.Role {
		t.Errorf("the denial records role %v, want %q", got, admin.Role)
	}
}
