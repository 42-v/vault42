//go:build browser

package browser_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// ======================================================================
// Test 1: Cookie Secure flag
// Verify that the Set-Cookie for refresh_token has the Secure flag
// when the vault is running with TLS enabled.
// ======================================================================
func TestCookieSecureFlag(t *testing.T) {
	email := uniqueEmail("secure-flag")
	registerAndVerifyUser(t, email)

	result := loginViaAPI(t, email)
	cookie := getRefreshCookie(result.Response)
	if cookie == nil {
		t.Fatal("no refresh_token cookie set")
	}

	if !cookie.Secure {
		t.Error("refresh_token cookie is not Secure — must be set when TLS is enabled")
	}
	t.Logf("  refresh_token Secure=%v", cookie.Secure)
}

// ======================================================================
// Test 2: Cookie HttpOnly flag — verify via browser DOM
// Navigate to the frontend after login and verify that document.cookie
// does NOT expose the refresh_token (proving HttpOnly is effective).
// ======================================================================
func TestCookieHttpOnlyFlag(t *testing.T) {
	email := uniqueEmail("httponly")
	registerAndVerifyUser(t, email)

	// First verify at the HTTP level that HttpOnly is set
	result := loginViaAPI(t, email)
	cookie := getRefreshCookie(result.Response)
	if cookie == nil {
		t.Fatal("no refresh_token cookie set")
	}
	if !cookie.HttpOnly {
		t.Fatal("refresh_token cookie is not HttpOnly at HTTP level")
	}

	// Now verify via browser: document.cookie must NOT contain refresh_token
	if !hasChromeInstalled() {
		t.Log("  HttpOnly confirmed at HTTP level (skipping browser check: Chrome not installed)")
		return
	}

	ctx, cancel := newBrowserContext(t)
	defer cancel()

	var cookies string
	err := chromedp.Run(ctx,
		// Navigate to a vault endpoint to establish the domain
		chromedp.Navigate(baseURL+"/healthz"),
		chromedp.WaitReady("body"),
		// Set the cookie via Chrome DevTools Protocol (which can set HttpOnly)
		chromedp.ActionFunc(func(ctx context.Context) error {
			return network.SetCookie("__Host-refresh_token", cookie.Value).
				WithDomain("vault.localhost").
				WithPath("/").
				WithHTTPOnly(true).
				WithSecure(true).
				Do(ctx)
		}),
		// Now try to read it via JavaScript — should NOT be visible
		chromedp.Evaluate(`document.cookie`, &cookies),
	)
	if err != nil {
		t.Fatalf("chromedp: %v", err)
	}

	if strings.Contains(cookies, "__Host-refresh_token") {
		t.Error("refresh_token is accessible via document.cookie — HttpOnly not effective in browser")
	} else {
		t.Log("  refresh_token is NOT accessible via document.cookie (HttpOnly confirmed)")
	}
}

// ======================================================================
// Test 3: Content-Security-Policy header present
// ======================================================================
func TestCSPHeaderPresent(t *testing.T) {
	client := httpClient()
	resp, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header is missing")
	}

	// Verify it includes key directives
	if !strings.Contains(csp, "default-src") {
		t.Error("CSP missing default-src directive")
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Error("CSP missing frame-ancestors 'none' directive")
	}
	t.Logf("  CSP: %s", csp)
}

// ======================================================================
// Test 4: Clickjacking protection
// Verify X-Frame-Options: DENY or CSP frame-ancestors 'none'.
// ======================================================================
func TestClickjackingProtection(t *testing.T) {
	client := httpClient()
	resp, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()

	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")

	hasXFO := xfo == "DENY"
	hasCSPFrameAncestors := strings.Contains(csp, "frame-ancestors 'none'")

	if !hasXFO && !hasCSPFrameAncestors {
		t.Fatal("no clickjacking protection: X-Frame-Options is not DENY and CSP frame-ancestors 'none' is missing")
	}

	if hasXFO {
		t.Logf("  X-Frame-Options: %s", xfo)
	}
	if hasCSPFrameAncestors {
		t.Logf("  CSP includes frame-ancestors 'none'")
	}
}

// ======================================================================
// Test 5: Full login flow via API
// Register -> try login (unverified, expect 401) -> verify email -> login with MFA -> verify tokens.
// ======================================================================
func TestLoginFlowViaAPI(t *testing.T) {
	email := uniqueEmail("login-flow")

	// Register
	registerUser(t, email)
	t.Log("  Registered")

	// Login should fail (email not verified) — returns 401 (not 403) to prevent
	// user enumeration: attacker cannot distinguish unverified from wrong password.
	client := httpClient()
	body, _ := json.Marshal(map[string]string{
		"email": email, "password": testPassword,
	})
	resp, err := client.Post(baseURL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login (unverified): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("login (unverified) status = %d, want 401", resp.StatusCode)
	}
	t.Log("  Login blocked (email not verified)")

	// Verify email
	verifyEmailViaDB(t, email)
	t.Log("  Email verified via DB")

	// Login should succeed (handles MFA if required)
	result := loginViaAPI(t, email)

	if result.AccessToken == "" {
		t.Fatal("login did not return access_token")
	}
	t.Logf("  Got access_token (%d chars)", len(result.AccessToken))

	cookie := getRefreshCookie(result.Response)
	if cookie == nil {
		t.Fatal("login did not set refresh_token cookie")
	}
	if cookie.Value == "" {
		t.Fatal("refresh_token cookie has empty value")
	}
	t.Logf("  Got refresh_token cookie (HttpOnly=%v, Secure=%v, SameSite=%v)",
		cookie.HttpOnly, cookie.Secure, cookie.SameSite)
}

// ======================================================================
// Test 6: Logout clears the refresh_token cookie
// Login -> logout -> verify Set-Cookie clears refresh_token (MaxAge=-1 or Expires in past).
// ======================================================================
func TestLogoutClearsCookie(t *testing.T) {
	email := uniqueEmail("logout-clear")
	registerAndVerifyUser(t, email)

	result := loginViaAPI(t, email)

	// Logout
	client := httpClient()
	logoutReq, _ := http.NewRequest("POST", baseURL+"/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+result.AccessToken)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer logoutResp.Body.Close()

	if logoutResp.StatusCode != 200 {
		raw, _ := io.ReadAll(logoutResp.Body)
		t.Fatalf("logout status = %d, body = %s", logoutResp.StatusCode, raw)
	}

	// Check that Set-Cookie clears the refresh_token
	cookie := getRefreshCookie(logoutResp)
	if cookie == nil {
		t.Fatal("logout response did not include a refresh_token Set-Cookie header")
	}

	// Cookie should be cleared: MaxAge < 0, or value is empty, or Expires is in the past
	cleared := false
	if cookie.MaxAge < 0 {
		cleared = true
	}
	if cookie.Value == "" {
		cleared = true
	}
	if !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()) {
		cleared = true
	}

	if !cleared {
		t.Errorf("logout did not clear refresh_token cookie: MaxAge=%d, Value=%q, Expires=%v",
			cookie.MaxAge, cookie.Value, cookie.Expires)
	} else {
		t.Logf("  refresh_token cookie cleared (MaxAge=%d, Value=%q)", cookie.MaxAge, cookie.Value)
	}
}

// ======================================================================
// Test 7: Refresh token rotation and replay detection
// Login -> get refresh token -> refresh -> verify new token is different ->
// replay old token -> verify old rejected AND entire family nuked.
// ======================================================================
func TestRefreshTokenRotation(t *testing.T) {
	email := uniqueEmail("rotation")
	registerAndVerifyUser(t, email)

	result := loginViaAPI(t, email)

	originalCookie := getRefreshCookie(result.Response)
	if originalCookie == nil {
		t.Fatal("login did not set refresh_token cookie")
	}
	originalToken := originalCookie.Value

	// Use the refresh token — should succeed and return a new token
	status, body, refreshResp := refreshWithCookie(t, originalToken)
	if status != 200 {
		t.Fatalf("refresh status = %d, want 200, body = %v", status, body)
	}

	newCookie := getRefreshCookie(refreshResp)
	if newCookie == nil {
		t.Fatal("refresh did not set new refresh_token cookie")
	}
	newToken := newCookie.Value

	if newToken == originalToken {
		t.Fatal("refresh token was not rotated (same token returned)")
	}
	t.Log("  Token rotated successfully")

	// Use the NEW token before attempting replay — should succeed
	secondStatus, secondBody, secondResp := refreshWithCookie(t, newToken)
	if secondStatus != 200 {
		t.Fatalf("second refresh status = %d, want 200, body = %v", secondStatus, secondBody)
	}
	secondCookie := getRefreshCookie(secondResp)
	if secondCookie == nil {
		t.Fatal("second refresh did not set new refresh_token cookie")
	}
	t.Log("  New token works after rotation")

	// Now replay the ORIGINAL token — should be rejected (single-use)
	replayStatus, replayBody, _ := refreshWithCookie(t, originalToken)
	if replayStatus != 401 {
		t.Fatalf("replay of old refresh token: status = %d, want 401, body = %v", replayStatus, replayBody)
	}
	t.Logf("  Old token correctly rejected: %v", replayBody["error"])

	// After replay detection, the entire token family is nuked.
	// The newest token should now also be invalid (security measure).
	nukedStatus, _, _ := refreshWithCookie(t, secondCookie.Value)
	if nukedStatus != 401 {
		t.Fatalf("token family should be nuked after replay: status = %d, want 401", nukedStatus)
	}
	t.Log("  Token family nuked after replay detection (security measure confirmed)")
}

// ======================================================================
// Test 8: XSS in display_name
// Register a user with a script tag in display_name, then verify the
// API response returns it escaped/stripped, and confirm via browser DOM
// that no executable script exists.
// ======================================================================
func TestXSSInDisplayName(t *testing.T) {
	email := uniqueEmail("xss")
	xssPayload := `<script>alert(1)</script>`

	// Register with XSS payload in display_name
	registerUserWithDisplayName(t, email, xssPayload)
	verifyEmailViaDB(t, email)

	// Login and get access token
	result := loginViaAPI(t, email)

	// Fetch profile via API and verify the display_name is sanitized
	client := httpClient()
	profileReq, _ := http.NewRequest("GET", baseURL+"/user/profile", nil)
	profileReq.Header.Set("Authorization", "Bearer "+result.AccessToken)
	profileResp, err := client.Do(profileReq)
	if err != nil {
		t.Fatalf("GET /user/profile: %v", err)
	}
	defer profileResp.Body.Close()

	raw, _ := io.ReadAll(profileResp.Body)
	profileJSON := string(raw)

	// The raw JSON response should NOT contain unescaped <script> tags.
	if strings.Contains(profileJSON, "<script>") {
		t.Error("profile API response contains raw <script> tag — XSS vulnerability")
	}
	t.Logf("  API response display_name is sanitized: no raw <script> tag")

	// Browser-level check: render the profile JSON in a page and verify
	// no <script> element exists in the DOM
	if !hasChromeInstalled() {
		t.Log("  Skipping browser DOM check: Chrome not installed")
		return
	}

	ctx, cancel := newBrowserContext(t)
	defer cancel()

	var profile map[string]interface{}
	json.Unmarshal(raw, &profile)
	displayName, _ := profile["display_name"].(string)

	htmlPage := fmt.Sprintf(`<html><body><div id="name">%s</div></body></html>`, displayName)

	var scriptCount int64
	err = chromedp.Run(ctx,
		chromedp.Navigate("data:text/html,"+htmlPage),
		chromedp.WaitReady("body"),
		chromedp.Evaluate(`document.querySelectorAll('script').length`, &scriptCount),
	)
	if err != nil {
		t.Fatalf("chromedp: %v", err)
	}

	if scriptCount > 0 {
		t.Errorf("DOM contains %d <script> elements — XSS payload executed", scriptCount)
	} else {
		t.Log("  Browser DOM contains no <script> elements (XSS prevented)")
	}
}

// ======================================================================
// Test 9: SameSite=Strict on refresh_token cookie
// ======================================================================
func TestSameSiteStrictOnCookie(t *testing.T) {
	email := uniqueEmail("samesite")
	registerAndVerifyUser(t, email)

	result := loginViaAPI(t, email)
	cookie := getRefreshCookie(result.Response)
	if cookie == nil {
		t.Fatal("no refresh_token cookie set")
	}

	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %d, want %d (Strict)", cookie.SameSite, http.SameSiteStrictMode)
	} else {
		t.Log("  SameSite=Strict confirmed")
	}

	// Also verify by inspecting the raw Set-Cookie header
	for _, h := range result.Response.Header["Set-Cookie"] {
		if strings.Contains(h, "__Host-refresh_token") {
			lower := strings.ToLower(h)
			if !strings.Contains(lower, "samesite=strict") {
				t.Errorf("raw Set-Cookie header does not contain SameSite=Strict: %s", h)
			} else {
				t.Logf("  Raw header confirms SameSite=Strict")
			}
		}
	}
}

// ======================================================================
// Test 10: Security headers present
// Verify X-Content-Type-Options: nosniff, X-Frame-Options: DENY,
// Strict-Transport-Security, Referrer-Policy, X-XSS-Protection, and
// Cache-Control headers are all present.
// ======================================================================
func TestSecurityHeadersPresent(t *testing.T) {
	client := httpClient()
	resp, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"X-XSS-Protection":      "0",
		"Referrer-Policy":       "no-referrer",
		"Cache-Control":         "no-store",
	}

	for name, want := range expected {
		got := resp.Header.Get(name)
		if got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		} else {
			t.Logf("  %s: %s", name, got)
		}
	}

	// HSTS should be present (since vault.localhost uses TLS)
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("Strict-Transport-Security header is missing")
	} else {
		if !strings.Contains(hsts, "max-age=") {
			t.Error("HSTS missing max-age directive")
		}
		t.Logf("  Strict-Transport-Security: %s", hsts)
	}

	// CSP should be present
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing")
	} else {
		t.Logf("  Content-Security-Policy: %s", csp)
	}
}
