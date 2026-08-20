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
	"sort"
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

// TestUIPages walks every server-rendered page behind the session token. The
// markers are the ids the page's own JavaScript binds to, so a template that
// still answers 200 while having lost the table it exists to fill is caught
// here instead of by a human loading the page.
func TestUIPages(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		wants []string
	}{
		{"dashboard", "/admin/", []string{"Dashboard", "keyCount", "sessionCount", "adminCount", "clientCount"}},
		{"users", "/admin/ui/users", []string{"Users", "userSearch", "usersBody"}},
		{"keys", "/admin/ui/keys", []string{"Signing Keys", "keysBody"}},
		{"sessions", "/admin/ui/sessions", []string{"Admin Sessions", "sessionsBody"}},
		{"audit", "/admin/ui/audit", []string{"Audit Log", "auditEventType", "auditBody"}},
		{"clients", "/admin/ui/clients", []string{"Service Clients", "clientsBody", "createClientForm"}},
		{"admins", "/admin/ui/admins", []string{"Admin Accounts", "adminsBody", "createAdminForm"}},
		{"config", "/admin/ui/config", []string{"Configuration", "configBody", "addConfigForm"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := authedGet(t, sharedClient, sharedToken, tc.path)
			defer resp.Body.Close()
			requireStatus(t, resp, http.StatusOK)
			body := readBody(t, resp)
			for _, want := range tc.wants {
				requireContains(t, body, want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Static Assets
// ---------------------------------------------------------------------------

// TestStaticAssets checks that the embedded assets are served with a
// content type a browser will execute or apply. A stylesheet served as
// text/plain renders an unstyled page, and a script served as text/plain does
// not run at all, in both cases behind a 200.
func TestStaticAssets(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		wantBody  string
		wantCtype string
	}{
		{"stylesheet", "/admin/static/style.css", "--green", "text/css"},
		{"script", "/admin/static/admin.js", "data-action", "javascript"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := sharedClient.Get(baseURL() + tc.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			requireStatus(t, resp, http.StatusOK)
			if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, tc.wantCtype) {
				t.Errorf("%s: Content-Type %q, want one containing %q", tc.path, ct, tc.wantCtype)
			}
			requireContains(t, readBody(t, resp), tc.wantBody)
		})
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
	defer resp.Body.Close()
	requireStatus(t, resp, http.StatusOK)
	var status map[string]any
	decodeJSON(t, resp, &status)
	if status["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", status["status"])
	}
}

// TestLoginRefusesBadCredentials pins the two ways a login fails and the fact
// that they look identical from outside. A wrong password and an unknown
// username have to answer with the same status and the same error, otherwise
// the endpoint tells an attacker which usernames exist.
func TestLoginRefusesBadCredentials(t *testing.T) {
	cases := []struct {
		name     string
		username string
		password string
	}{
		{"wrong password", "admin", "wrong_password_1234567890"},
		{"unknown user", "nonexistent_user_xyz", "some_password_1234567890"},
	}

	answers := make(map[string]string, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"username":%q,"password":%q}`, tc.username, tc.password)
			resp, err := sharedClient.Post(baseURL()+"/admin/auth/login", "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatalf("POST login: %v", err)
			}
			status := resp.StatusCode

			var lr loginResponse
			decodeJSON(t, resp, &lr)
			if status != http.StatusUnauthorized {
				t.Errorf("got %d, want 401", status)
			}
			if lr.Token != "" {
				t.Error("a refused login handed back a token")
			}
			if lr.Error == "" {
				t.Error("a refused login gave no error to show the operator")
			}
			answers[tc.name] = fmt.Sprintf("%d %s", status, lr.Error)
		})
	}

	if len(answers) == len(cases) {
		wrongPassword, unknownUser := answers[cases[0].name], answers[cases[1].name]
		if wrongPassword != unknownUser {
			t.Errorf("wrong password answered %q, unknown user answered %q; the two must be indistinguishable or the endpoint enumerates admins",
				wrongPassword, unknownUser)
		}
	}
}

func TestStatusEndpoint(t *testing.T) {
	resp := authedGet(t, sharedClient, sharedToken, "/admin/status")
	defer resp.Body.Close()
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
		// Not a resource this suite can be missing. TestMain enrolls TOTP
		// whenever the gateway answers requires_2fa, which a first-boot admin
		// always does, and a gateway that already has TOTP fails the very first
		// login instead of reaching here. An empty token means the gateway
		// reported TOTP as configured and then accepted a login with no code,
		// which is the bug this suite would exist to catch. Skipping it would
		// report that as green.
		t.Fatal("logoutToken is empty: the gateway accepted a login without a TOTP code while reporting TOTP as configured")
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

// TestDataAPIs reads every collection the admin UI fetches. Each row names the
// field the page's JavaScript indexes into, so a handler that renamed or
// dropped it fails here rather than in a browser; wantNonEmpty is set only
// where the suite itself guarantees a row exists, since the session doing the
// asking is one of them.
func TestDataAPIs(t *testing.T) {
	cases := []struct {
		name         string
		path         string
		field        string // "" means only that the body parses as a JSON object
		wantNonEmpty bool
	}{
		{"keys", "/admin/keys", "keys", false},
		{"sessions", "/admin/sessions", "sessions", true},
		{"audit", "/admin/audit?limit=5", "entries", false},
		{"clients", "/admin/clients", "clients", false},
		{"admins", "/admin/admins", "admins", true},
		{"user search", "/admin/users?q=dev@vault.localhost", "users", false},
		{"config", "/admin/config", "", false},
		{"metrics", "/admin/metrics", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := authedGet(t, sharedClient, sharedToken, tc.path)
			defer resp.Body.Close()
			requireStatus(t, resp, http.StatusOK)

			var result map[string]any
			decodeJSON(t, resp, &result)
			if tc.field == "" {
				return
			}

			value, ok := result[tc.field]
			if !ok {
				t.Fatalf("GET %s: response has no %q field, only %v", tc.path, tc.field, mapKeys(result))
			}
			if tc.wantNonEmpty {
				arr, ok := value.([]any)
				if !ok {
					t.Fatalf("GET %s: %q is %T, want a list", tc.path, tc.field, value)
				}
				if len(arr) == 0 {
					t.Errorf("GET %s: %q is empty, and this suite's own session or admin should be in it", tc.path, tc.field)
				}
			}
		})
	}
}

// mapKeys names what a response did carry, so a renamed field is one line of
// output away from being obvious.
func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
	defer resp.Body.Close()
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
	defer resp2.Body.Close()
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
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK && resp3.StatusCode != http.StatusNoContent {
		body := readBody(t, resp3)
		t.Fatalf("revoke client: %d %s", resp3.StatusCode, body)
	}
	resp3.Body.Close()
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
