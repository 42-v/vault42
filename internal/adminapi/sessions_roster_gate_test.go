package adminapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
)

// routerWithSession builds the real admin router and a bearer token that
// authenticates as an admin holding the given role, so a test exercises the
// route's actual permission gate rather than a copy of it.
func routerWithSession(t *testing.T, role rbac.Role) (http.Handler, string) {
	t.Helper()

	admins := newFakeAdminRepo()
	admin := &model.AdminUser{
		ID:           "00000000-0000-0000-0000-0000000000aa",
		Username:     "someone",
		Role:         string(role),
		TOTPVerified: true,
	}
	admins.users[admin.ID] = admin

	const token = "session-token-for-the-permission-gate"
	sessions := newFakeSessionRepo()
	sessions.sessions["s1"] = &model.AdminSession{
		ID:        "s1",
		AdminID:   admin.ID,
		TokenHash: hashSessionToken(token),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	api := newTestHandler(admins, nil, nil, nil)
	api.sessions = sessions

	return NewRouter(newTestAuth(admins, sessions), api, RouterOpts{DevMode: true}), token
}

// TestListSessionsIsNotAViewerCapability closes a reconnaissance leak the
// codebase already refuses to allow anywhere else.
//
// GET /admin/sessions projects admin_id, source IP, user agent and both
// timestamps for every currently logged-in admin. Its gate was sessions:list,
// which sits in viewerPerms because that permission is documented as
// "visibility into active refresh-token sessions" — user sessions, not the
// admin roster. internal/rbac/rbac.go keeps admins:manage at super_admin for the
// stated reason that "the roster of who can administer the deployment is
// reconnaissance for an attacker who has taken a lower-tier admin session, so it
// does not follow the usual 'list is viewer' rule". A stolen viewer session
// handed over exactly that roster, plus each admin's source IP and user agent.
//
// The endpoint reads the admin plane, so it is gated on the permission that
// governs the admin plane.
func TestListSessionsIsNotAViewerCapability(t *testing.T) {
	router, token := routerWithSession(t, rbac.RoleViewer)

	req := httptest.NewRequest(http.MethodGet, "/admin/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403. A viewer-tier session was handed the live roster of "+
			"every logged-in admin with their source IPs — the reconnaissance the admins:manage "+
			"tier exists to deny. Body: %s", rec.Code, rec.Body.String())
	}
}

// TestListSessionsStaysAvailableToTheAdminTier is the other direction, so the
// gate above cannot pass by refusing everyone.
func TestListSessionsStaysAvailableToTheAdminTier(t *testing.T) {
	router, token := routerWithSession(t, rbac.RoleSuperAdmin)

	req := httptest.NewRequest(http.MethodGet, "/admin/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body %s", rec.Code, rec.Body.String())
	}
}
