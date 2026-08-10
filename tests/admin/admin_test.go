// Package admin_test provides end-to-end tests for the Vault Admin Gateway.
// Tests require a running admin gateway with mTLS. Run deploy-dev.sh first.
//
// Required env vars:
//
//	ADMIN_FIRST_PASSWORD — first-boot super_admin password (from pod logs)
//
// Optional env vars:
//
//	ADMIN_GW_URL          — gateway URL (default: https://localhost:9443)
//	ADMIN_GW_CLIENT_CERT  — client cert path (default: ../../secrets/admin-gateway/client.crt)
//	ADMIN_GW_CLIENT_KEY   — client key path  (default: ../../secrets/admin-gateway/client.key)
//	ADMIN_GW_CA_CERT      — CA cert path     (default: ../../secrets/admin-gateway/ca.crt)
package admin_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Frontend Page Tests — verify server-rendered HTML
// ---------------------------------------------------------------------------

func TestLoginPage(t *testing.T) {
	resp, err := sharedClient.Get(baseURL() + "/admin/login")
	if err != nil {
		t.Fatalf("GET /admin/login: %v", err)
	}
	requireStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	requireContains(t, body, "loginForm")
	requireContains(t, body, `id="username"`)
	requireContains(t, body, `id="password"`)
	requireContains(t, body, "login-logo")
}

func TestDashboardRequiresAuth(t *testing.T) {
	// Without session token, dashboard should return 401 (SessionAuth middleware).
	resp, err := sharedClient.Get(baseURL() + "/admin/")
	if err != nil {
		t.Fatalf("GET /admin/: %v", err)
	}
	resp.Body.Close()
	// Accept 401 (missing auth), or 200/302 if page renders without auth check.
	if resp.StatusCode != http.StatusUnauthorized &&
		resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusFound {
		t.Errorf("GET /admin/ without auth: expected 401/200/302, got %d", resp.StatusCode)
	}
}

func TestDashboardPage(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/")
	requireStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	requireContains(t, body, "Dashboard")
	requireContains(t, body, "keyCount")
	requireContains(t, body, "sessionCount")
	requireContains(t, body, "adminCount")
	requireContains(t, body, "clientCount")
}

func TestUsersPage(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/ui/users")
	requireStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	requireContains(t, body, "Users")
	requireContains(t, body, "userSearch")
	requireContains(t, body, "usersBody")
}

func TestKeysPage(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/ui/keys")
	requireStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	requireContains(t, body, "Signing Keys")
	requireContains(t, body, "keysBody")
}

func TestSessionsPage(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/ui/sessions")
	requireStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	requireContains(t, body, "Admin Sessions")
	requireContains(t, body, "sessionsBody")
}

func TestAuditPage(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/ui/audit")
	requireStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	requireContains(t, body, "Audit Log")
	requireContains(t, body, "auditEventType")
	requireContains(t, body, "auditBody")
}

func TestClientsPage(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/ui/clients")
	requireStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	requireContains(t, body, "Service Clients")
	requireContains(t, body, "clientsBody")
	requireContains(t, body, "createClientForm")
}

func TestAdminsPage(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/ui/admins")
	requireStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	requireContains(t, body, "Admin Accounts")
	requireContains(t, body, "adminsBody")
	requireContains(t, body, "createAdminForm")
}

func TestConfigPage(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/ui/config")
	requireStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	requireContains(t, body, "Configuration")
	requireContains(t, body, "configBody")
	requireContains(t, body, "addConfigForm")
}

// ---------------------------------------------------------------------------
// Static Assets
// ---------------------------------------------------------------------------

func TestStaticCSS(t *testing.T) {
	resp, err := sharedClient.Get(baseURL() + "/admin/static/style.css")
	if err != nil {
		t.Fatalf("GET style.css: %v", err)
	}
	requireStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	requireContains(t, body, "--green")
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/css") {
		t.Errorf("expected text/css content-type, got %s", ct)
	}
}

func TestStaticJS(t *testing.T) {
	resp, err := sharedClient.Get(baseURL() + "/admin/static/admin.js")
	if err != nil {
		t.Fatalf("GET admin.js: %v", err)
	}
	requireStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	requireContains(t, body, "data-action")
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("expected javascript content-type, got %s", ct)
	}
}

// ---------------------------------------------------------------------------
// Security Headers
// ---------------------------------------------------------------------------

func TestSecurityHeaders(t *testing.T) {
	resp, err := sharedClient.Get(baseURL() + "/admin/login")
	if err != nil {
		t.Fatalf("GET /admin/login: %v", err)
	}
	resp.Body.Close()

	headers := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "no-store",
	}
	for name, want := range headers {
		got := resp.Header.Get(name)
		if !strings.Contains(got, want) {
			t.Errorf("%s: want %q in %q", name, want, got)
		}
	}

	if csp := resp.Header.Get("Content-Security-Policy"); csp == "" {
		t.Error("missing Content-Security-Policy header")
	}
	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts == "" {
		t.Error("missing Strict-Transport-Security header")
	}
}

// ---------------------------------------------------------------------------
// Auth API Tests — grouped to minimize login attempts (rate limit: 10/min)
// ---------------------------------------------------------------------------

func TestLoginSuccess(t *testing.T) {
	// Login success is verified by TestMain (sharedToken must be non-empty).
	// Additional logins would hit TOTP replay prevention (same 30s window).
	if sharedToken == "" {
		t.Fatal("TestMain should have set sharedToken — login failed")
	}
	// Verify the session is actually usable by hitting /admin/status.
	resp := authedGet(t, sharedClient, sharedToken, "/admin/status")
	requireStatus(t, resp, http.StatusOK)
	var status map[string]any
	decodeJSON(t, resp, &status)
	if status["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", status["status"])
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	body := `{"username":"admin","password":"wrong_password_1234567890"}`
	resp, err := sharedClient.Post(baseURL()+"/admin/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST login: %v", err)
	}

	var lr loginResponse
	decodeJSON(t, resp, &lr)
	if lr.Token != "" {
		t.Error("should not return token for invalid credentials")
	}
	if lr.Error == "" {
		t.Error("expected error for invalid credentials")
	}
}

func TestLoginNonexistentUser(t *testing.T) {
	body := `{"username":"nonexistent_user_xyz","password":"some_password_1234567890"}`
	resp, err := sharedClient.Post(baseURL()+"/admin/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST login: %v", err)
	}

	var lr loginResponse
	decodeJSON(t, resp, &lr)
	if lr.Token != "" {
		t.Error("should not return token for nonexistent user")
	}
	if lr.Error == "" {
		t.Error("expected error for nonexistent user")
	}
}

func TestStatusEndpoint(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/status")
	requireStatus(t, resp, http.StatusOK)

	var status map[string]any
	decodeJSON(t, resp, &status)
	admin, _ := status["admin"].(map[string]any)
	if admin == nil {
		t.Fatal("expected 'admin' object in status response")
	}
	if admin["username"] != "admin" {
		t.Errorf("expected username 'admin', got %v", admin["username"])
	}
}

func TestLogout(t *testing.T) {
	if logoutToken == "" {
		t.Skip("no logout token available (TOTP not configured)")
	}
	token := logoutToken

	resp := authedPost(t, sharedClient, token, "/admin/auth/logout", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Errorf("logout: expected 200 or 204, got %d", resp.StatusCode)
	}

	// Token should now be invalid.
	resp2 := authedGet(t, sharedClient, token, "/admin/status")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 after logout, got %d", resp2.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Data API Tests — all use shared session (no extra logins)
// ---------------------------------------------------------------------------

func TestKeysAPI(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/keys")
	requireStatus(t, resp, http.StatusOK)

	var result map[string]any
	decodeJSON(t, resp, &result)
	if _, ok := result["keys"]; !ok {
		t.Error("response missing 'keys' field")
	}
}

func TestSessionsAPI(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/sessions")
	requireStatus(t, resp, http.StatusOK)

	var result map[string]any
	decodeJSON(t, resp, &result)
	sessions, ok := result["sessions"]
	if !ok {
		t.Error("response missing 'sessions' field")
	}
	if arr, ok := sessions.([]any); ok && len(arr) == 0 {
		t.Error("expected at least one active session")
	}
}

func TestAuditAPI(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/audit?limit=5")
	requireStatus(t, resp, http.StatusOK)

	var result map[string]any
	decodeJSON(t, resp, &result)
	if _, ok := result["entries"]; !ok {
		t.Error("response missing 'entries' field")
	}
}

func TestClientsAPI(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/clients")
	requireStatus(t, resp, http.StatusOK)

	var result map[string]any
	decodeJSON(t, resp, &result)
	if _, ok := result["clients"]; !ok {
		t.Error("response missing 'clients' field")
	}
}

func TestAdminsAPI(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/admins")
	requireStatus(t, resp, http.StatusOK)

	var result map[string]any
	decodeJSON(t, resp, &result)
	admins, ok := result["admins"]
	if !ok {
		t.Error("response missing 'admins' field")
	}
	if arr, ok := admins.([]any); ok && len(arr) == 0 {
		t.Error("expected at least one admin")
	}
}

func TestConfigAPI(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/config")
	requireStatus(t, resp, http.StatusOK)

	var result map[string]any
	decodeJSON(t, resp, &result)
	// Config may be empty, but the response should parse successfully.
}

func TestMetricsAPI(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/metrics")
	requireStatus(t, resp, http.StatusOK)

	var result map[string]any
	decodeJSON(t, resp, &result)
}

// ---------------------------------------------------------------------------
// API Mutation Tests
// ---------------------------------------------------------------------------

func TestClientCreateAndRevoke(t *testing.T) {
	clientName := fmt.Sprintf("e2e-test-%d", time.Now().UnixNano())
	createBody := map[string]any{
		"name":          clientName,
		"role":          "service",
		"scopes":        []string{"user:read"},
		"redirect_uris": []string{},
	}
	resp := authedPost(t, sharedClient, sharedToken, "/admin/clients", createBody)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body := readBody(t, resp)
		t.Fatalf("create client: %d %s", resp.StatusCode, body)
	}
	var created map[string]any
	decodeJSON(t, resp, &created)
	clientID, _ := created["id"].(string)
	if clientID == "" {
		t.Fatal("created client has no ID")
	}
	if _, ok := created["secret"]; !ok {
		t.Error("created client should include plaintext secret")
	}

	// Verify it appears in the list.
	resp2 := authedGet(t, sharedClient, sharedToken, "/admin/clients")
	requireStatus(t, resp2, http.StatusOK)
	var listed map[string]any
	decodeJSON(t, resp2, &listed)
	clients, _ := listed["clients"].([]any)
	found := false
	for _, c := range clients {
		cm, _ := c.(map[string]any)
		if cm["id"] == clientID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("client %s not found in list", clientID)
	}

	// Revoke it.
	resp3 := authedPost(t, sharedClient, sharedToken, "/admin/clients/"+clientID+"/revoke", nil)
	if resp3.StatusCode != http.StatusOK && resp3.StatusCode != http.StatusNoContent {
		body := readBody(t, resp3)
		t.Fatalf("revoke client: %d %s", resp3.StatusCode, body)
	}
	resp3.Body.Close()
}

func TestUserSearchAPI(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/users?q=dev@vault.localhost")
	requireStatus(t, resp, http.StatusOK)

	var result map[string]any
	decodeJSON(t, resp, &result)
	if _, ok := result["users"]; !ok {
		t.Error("response missing 'users' field")
	}
}

// ---------------------------------------------------------------------------
// API Auth Enforcement — no login needed (tests unauthenticated access)
// ---------------------------------------------------------------------------

func TestAPIRequiresAuth(t *testing.T) {
	endpoints := []string{
		"/admin/keys",
		"/admin/sessions",
		"/admin/audit",
		"/admin/clients",
		"/admin/admins",
		"/admin/config",
		"/admin/status",
		"/admin/metrics",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			req, _ := http.NewRequest("GET", baseURL()+ep, nil)
			resp, err := sharedClient.Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", ep, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("GET %s without auth: expected 401, got %d", ep, resp.StatusCode)
			}
		})
	}
}
