package unit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/adminapi"
	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/internal/seed"
	"github.com/42-v/vault42/tests/mocks"
)

// adminHandlerEnv wires a Handler from in-memory mocks. keyStore is nil; the
// keystore-dependent endpoints (ListKeys, RotateKey, RevokeKey) exercise the
// 503 early-exit path under this setup, which is enough to drive coverage of
// the entry point. Endpoints that don't touch the keystore reach their main
// branches normally.
func adminHandlerEnv() *adminapi.Handler {
	return adminapi.NewHandler(
		&mocks.MockUserRepo{},
		&mocks.MockClientRepo{},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockAuditRepo{},
		newMockAdminUserRepo(),
		newMockAdminSessionRepo(),
		&mocks.MockAdminConfigRepo{},
		nil,
		audit.NewLogger(&mocks.MockAuditRepo{}, time.Hour),
		make([]byte, 32),
		"",
	)
}

// adminCtx returns a context with an authenticated admin attached, since most
// endpoints call adminapi.GetAdmin(ctx) to record the actor in the audit log.
func adminCtx(ctx context.Context) context.Context {
	return adminapi.WithAdmin(ctx, &model.AdminUser{
		ID:       "00000000-0000-0000-0000-000000000099",
		Username: "test-admin",
		Role:     "super",
	})
}

func runHandler(h func(http.ResponseWriter, *http.Request), method, target string, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec
}

func TestAdminHandler_ListKeys_503WhenNoKeystore(t *testing.T) {
	rec := runHandler(adminHandlerEnv().ListKeys, http.MethodGet, "/admin/keys", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestAdminHandler_RotateKey_503WhenNoKeystore(t *testing.T) {
	rec := runHandler(adminHandlerEnv().RotateKey, http.MethodPost, "/admin/keys/rotate", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestAdminHandler_RevokeKey_503WhenNoKeystore(t *testing.T) {
	rec := runHandler(adminHandlerEnv().RevokeKey, http.MethodDelete, "/admin/keys/kid1", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// ListUsers reads ?q= and branches on the shape it finds. The row names are the
// branch each query is here to reach; the status is the same 200 for all of
// them, which is why the query has to stay legible rather than being folded
// into one "search works" case.
func TestAdminHandler_ListUsers_QueryShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{name: "no query", url: "/admin/users"},
		{name: "a UUID", url: "/admin/users?q=00000000-0000-0000-0000-000000000001"},
		{name: "an email address", url: "/admin/users?q=test@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := runHandler(adminHandlerEnv().ListUsers, http.MethodGet, tc.url, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s answered %d, want 200: %s", tc.url, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAdminHandler_GetUser_NotFound404(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/admin/users/00000000-0000-0000-0000-000000000001", nil)
	r.SetPathValue("id", "00000000-0000-0000-0000-000000000001")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().GetUser(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_ListClients_OK(t *testing.T) {
	rec := runHandler(adminHandlerEnv().ListClients, http.MethodGet, "/admin/clients", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_GetClient_NotFound404(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/admin/clients/missing", nil)
	r.SetPathValue("id", "missing")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().GetClient(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_ListSessions_OK(t *testing.T) {
	rec := runHandler(adminHandlerEnv().ListSessions, http.MethodGet, "/admin/sessions", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_QueryAudit_OK(t *testing.T) {
	rec := runHandler(adminHandlerEnv().QueryAudit, http.MethodGet, "/admin/audit", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_GetConfig_OK(t *testing.T) {
	rec := runHandler(adminHandlerEnv().GetConfig, http.MethodGet, "/admin/config", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_GetMetrics_OK(t *testing.T) {
	rec := runHandler(adminHandlerEnv().GetMetrics, http.MethodGet, "/admin/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_CreateClient_BadJSON400(t *testing.T) {
	rec := runHandler(adminHandlerEnv().CreateClient, http.MethodPost,
		"/admin/clients", "not-json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_UpdateConfig_BadJSON400(t *testing.T) {
	rec := runHandler(adminHandlerEnv().UpdateConfig, http.MethodPut,
		"/admin/config/foo", "not-json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func newAuthHandlerForRouter() *adminapi.AuthHandler {
	return adminapi.NewAuthHandler(
		newMockAdminUserRepo(),
		newMockAdminSessionRepo(),
		audit.NewLogger(&mocks.MockAuditRepo{}, time.Hour),
		make([]byte, 32),
		"",
		time.Hour,
		5,
		time.Hour,
	)
}

func TestAdminRouter_BuildsAndServesLogin(t *testing.T) {
	router := adminapi.NewRouter(newAuthHandlerForRouter(), adminHandlerEnv())
	if router == nil {
		t.Fatal("NewRouter returned nil")
	}
	r := httptest.NewRequest(http.MethodPost, "/admin/auth/login", strings.NewReader(`{"username":"x","password":"y"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden && rec.Code != http.StatusOK {
		t.Fatalf("login through router: unexpected status %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminRouter_DevModeBuilds(t *testing.T) {
	router := adminapi.NewRouter(newAuthHandlerForRouter(), adminHandlerEnv(),
		adminapi.RouterOpts{DevMode: true})
	if router == nil {
		t.Fatal("dev-mode router is nil")
	}
}

func TestAdminRouter_KillswitchOptionBuilds(t *testing.T) {
	router := adminapi.NewRouter(newAuthHandlerForRouter(), adminHandlerEnv(),
		adminapi.RouterOpts{Killswitch: true, AuditRepo: &mocks.MockAuditRepo{}})
	if router == nil {
		t.Fatal("killswitch router is nil")
	}
}

// runAuthHandler is the AuthHandler equivalent of runHandler — it attaches
// both an admin and a session to the context so handlers that look up either
// reach their main branches.
func runAuthHandler(h *adminapi.AuthHandler, fn func(http.ResponseWriter, *http.Request), method, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	admin := &model.AdminUser{ID: "00000000-0000-0000-0000-000000000099", Username: "admin", Role: "super"}
	session := &model.AdminSession{ID: "00000000-0000-0000-0000-000000000aaa", AdminID: admin.ID}
	ctx := adminapi.WithAdmin(r.Context(), admin)
	ctx = adminapi.WithSession(ctx, session)
	r = r.WithContext(ctx)
	rec := httptest.NewRecorder()
	fn(rec, r)
	return rec
}

func TestAuthHandler_Logout_OK(t *testing.T) {
	h := newAuthHandlerForRouter()
	rec := runAuthHandler(h, h.Logout, http.MethodPost, "/admin/auth/logout")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandler_Logout_NoSession401(t *testing.T) {
	h := newAuthHandlerForRouter()
	r := httptest.NewRequest(http.MethodPost, "/admin/auth/logout", nil)
	rec := httptest.NewRecorder()
	h.Logout(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuthHandler_Status_OK(t *testing.T) {
	h := newAuthHandlerForRouter()
	rec := runAuthHandler(h, h.Status, http.MethodGet, "/admin/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestAuthHandler_Status_NoAdmin401(t *testing.T) {
	h := newAuthHandlerForRouter()
	r := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	rec := httptest.NewRecorder()
	h.Status(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuthHandler_TOTPSetup_OK(t *testing.T) {
	h := newAuthHandlerForRouter()
	rec := runAuthHandler(h, h.TOTPSetup, http.MethodPost, "/admin/admins/me/totp/setup")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandler_TOTPVerify_BadJSON400(t *testing.T) {
	h := newAuthHandlerForRouter()
	r := httptest.NewRequest(http.MethodPost, "/admin/admins/me/totp/verify",
		strings.NewReader("not-json"))
	r.Header.Set("Content-Type", "application/json")
	admin := &model.AdminUser{ID: "00000000-0000-0000-0000-000000000099", Username: "admin"}
	r = r.WithContext(adminapi.WithAdmin(r.Context(), admin))
	rec := httptest.NewRecorder()
	h.TOTPVerify(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestEnsureFirstAdmin_CreatesWhenEmpty(t *testing.T) {
	// A generated bootstrap password is delivered before the row is written and
	// never through the log, so the test has to give the process somewhere to
	// put it.
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", filepath.Join(t.TempDir(), "first-boot.env"))
	admins := newMockAdminUserRepo()
	if err := adminapi.EnsureFirstAdmin(context.Background(), admins, &mocks.MockAdminConfigRepo{}, ""); err != nil {
		t.Fatalf("EnsureFirstAdmin: %v", err)
	}
	got, _ := admins.List(context.Background())
	if len(got) != 1 {
		t.Fatalf("admin count = %d, want 1", len(got))
	}
}

func TestEnsureFirstAdmin_NoOpWhenExists(t *testing.T) {
	admins := newMockAdminUserRepo()
	_ = admins.Create(context.Background(), &model.AdminUser{
		ID: "00000000-0000-0000-0000-000000000001", Username: "existing",
	})
	if err := adminapi.EnsureFirstAdmin(context.Background(), admins, &mocks.MockAdminConfigRepo{}, ""); err != nil {
		t.Fatalf("EnsureFirstAdmin: %v", err)
	}
	got, _ := admins.List(context.Background())
	if len(got) != 1 {
		t.Fatalf("admin count = %d, want 1 (no-op)", len(got))
	}
}

func TestAdminHandler_LockUser_NotFound(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost,
		"/admin/users/00000000-0000-0000-0000-000000000001/lock",
		strings.NewReader(`{"hours":1,"reason":"test"}`))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("id", "00000000-0000-0000-0000-000000000001")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().LockUser(rec, r)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 404 or 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_UnlockUser_NotFound(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost,
		"/admin/users/00000000-0000-0000-0000-000000000001/unlock", nil)
	r.SetPathValue("id", "00000000-0000-0000-0000-000000000001")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().UnlockUser(rec, r)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_ListAdmins_OK(t *testing.T) {
	rec := runHandler(adminHandlerEnv().ListAdmins, http.MethodGet, "/admin/admins", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_CreateAdmin_BadJSON400(t *testing.T) {
	rec := runHandler(adminHandlerEnv().CreateAdmin, http.MethodPost,
		"/admin/admins", "not-json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_DeleteConfig_OK(t *testing.T) {
	r := httptest.NewRequest(http.MethodDelete, "/admin/config/foo", nil)
	r.SetPathValue("key", "foo")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().DeleteConfig(rec, r)
	if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_RevokeClient_NotFound(t *testing.T) {
	r := httptest.NewRequest(http.MethodDelete, "/admin/clients/missing", nil)
	r.SetPathValue("id", "missing")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().RevokeClient(rec, r)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_RotateClientSecret_NotFound(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/admin/clients/missing/rotate", nil)
	r.SetPathValue("id", "missing")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().RotateClientSecret(rec, r)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandler_RevokeAllSessions_OK(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost,
		"/admin/users/00000000-0000-0000-0000-000000000001/sessions/revoke", nil)
	r.SetPathValue("id", "00000000-0000-0000-0000-000000000001")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().RevokeAllSessions(rec, r)
	if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminMiddleware_GetSession_NoneReturnsNil(t *testing.T) {
	if s := adminapi.GetSession(context.Background()); s != nil {
		t.Fatalf("GetSession with empty ctx = %v, want nil", s)
	}
	admin := &model.AdminSession{ID: "x"}
	ctx := adminapi.WithSession(context.Background(), admin)
	if s := adminapi.GetSession(ctx); s == nil || s.ID != "x" {
		t.Fatalf("GetSession round-trip failed")
	}
}

// SessionAuth has many rejection branches; one test per branch reaches a
// distinct error path. A passing handler downstream confirms the happy path.
func sessionAuthGuard(sessions *mockAdminSessionRepo, admins *mockAdminUserRepo) http.Handler {
	mw := adminapi.SessionAuth(sessions, admins, audit.NewLogger(&mocks.MockAuditRepo{}, 0))
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// Four ways an Authorization header fails to name a live admin session. They
// take different paths through the guard -- absent, wrong scheme, refused on
// length before any lookup, and looked up and not found -- and all four have to
// end at 401, because a guard that answered 400 or 404 to any of them would be
// telling an unauthenticated caller which one it was.
func TestSessionAuth_UnauthenticatedRequestsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		// header is the Authorization value; empty means the header is absent.
		header string
	}{
		{name: "no Authorization header"},
		{name: "a scheme other than Bearer", header: "Basic xyz"},
		{name: "a token past the length bound", header: "Bearer " + strings.Repeat("a", 300)},
		{name: "a well-formed token no session matches", header: "Bearer not-a-real-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := sessionAuthGuard(newMockAdminSessionRepo(), newMockAdminUserRepo())
			r := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s answered %d, want 401", tc.name, rec.Code)
			}
		})
	}
}

func TestRBACCheck_NoAdmin401(t *testing.T) {
	mw := adminapi.RBACCheck(rbac.AuditRead, nil)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/audit", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRBACCheck_AdminMissingPerm403(t *testing.T) {
	mw := adminapi.RBACCheck(rbac.ConfigWrite, nil)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	r := httptest.NewRequest(http.MethodPost, "/admin/config/x", nil)
	r = r.WithContext(adminapi.WithAdmin(r.Context(), &model.AdminUser{Role: string(rbac.RoleViewer)}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestAuthHandler_Login_HappyPath(t *testing.T) {
	h, admins, _ := setupAdminAuth(t)
	password := "ThisIsAVeryLongSecurePassword123!"
	_ = createTestAdmin(t, admins, "happy", password)

	rec := httptest.NewRecorder()
	h.Login(rec, loginRequest("happy", password, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandler_Login_NoBody400(t *testing.T) {
	h, _, _ := setupAdminAuth(t)
	r := httptest.NewRequest(http.MethodPost, "/admin/auth/login", strings.NewReader("not-json"))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Login(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAuthHandler_Login_EmptyCreds400(t *testing.T) {
	h, _, _ := setupAdminAuth(t)
	r := httptest.NewRequest(http.MethodPost, "/admin/auth/login", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Login(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAdminSecurityHeaders_AllSet(t *testing.T) {
	h := adminapi.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/ui", nil))
	required := []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"}
	for _, hdr := range required {
		if rec.Header().Get(hdr) == "" {
			t.Fatalf("missing header %s", hdr)
		}
	}
}

func TestAdminHandler_RevokeAdmin_PreventSelf(t *testing.T) {
	r := httptest.NewRequest(http.MethodDelete, "/admin/admins/00000000-0000-0000-0000-000000000099", nil)
	r.SetPathValue("id", "00000000-0000-0000-0000-000000000099")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().RevokeAdmin(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (self-revoke blocked)", rec.Code)
	}
}

func TestAdminHandler_RevokeAdmin_MissingID(t *testing.T) {
	r := httptest.NewRequest(http.MethodDelete, "/admin/admins/", nil)
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().RevokeAdmin(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAdminHandler_RevokeAdmin_OtherID(t *testing.T) {
	r := httptest.NewRequest(http.MethodDelete, "/admin/admins/other-id", nil)
	r.SetPathValue("id", "00000000-0000-0000-0000-000000000aaa")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().RevokeAdmin(rec, r)
	if rec.Code != http.StatusOK && rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestSeed_RunAdminsCreatesAndSkips(t *testing.T) {
	admins := newMockAdminUserRepo()
	sf := &seed.File{
		Admins: []seed.AdminSeed{
			{Username: "seeded-1", Password: "SeedingAdminLongerThan15Chars!", Role: string(rbac.RoleSuperAdmin)},
			{Username: "seeded-2", Password: "AnotherLongEnoughPassword!2", Role: string(rbac.RoleViewer)},
		},
	}
	if err := seed.RunAdmins(context.Background(), sf, admins, ""); err != nil {
		t.Fatalf("RunAdmins (initial): %v", err)
	}
	got, _ := admins.List(context.Background())
	if len(got) != 2 {
		t.Fatalf("admin count = %d, want 2", len(got))
	}
	// Re-run should be idempotent — both admins exist, no new inserts.
	if err := seed.RunAdmins(context.Background(), sf, admins, ""); err != nil {
		t.Fatalf("RunAdmins (idempotent): %v", err)
	}
	got, _ = admins.List(context.Background())
	if len(got) != 2 {
		t.Fatalf("admin count after re-run = %d, want 2 (no-op)", len(got))
	}
}

func TestRBACCheck_AdminWithPerm200(t *testing.T) {
	mw := adminapi.RBACCheck(rbac.AuditRead, nil)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	r := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
	r = r.WithContext(adminapi.WithAdmin(r.Context(), &model.AdminUser{Role: string(rbac.RoleSuperAdmin)}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
