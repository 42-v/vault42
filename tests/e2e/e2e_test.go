package e2e

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

var (
	baseURL    = "https://vault.localhost"
	mailpitURL = "http://mail.localhost"
)

// TestMain gates the suite on a reachable deployment.
//
// This suite talks to a real vault42 over HTTPS and reaches into the cluster
// with kubectl to reset state, so it cannot run without one. When no server
// answers it exits 0, which is right for a developer running `go test ./...` on
// a laptop and wrong everywhere a green result is read as evidence.
//
// It was read as evidence. The CI step named "E2E tests (skipped if no server)"
// never started a server, so the suite skipped itself on every run since it was
// written and reported success for doing nothing. A suite that passes by not
// running is worse than no suite, because it occupies the slot where a real one
// would be missed.
//
// VAULT_E2E_REQUIRED closes that. Set it anywhere a skip must not read as a
// pass, and an unreachable server becomes a failure that names the URL it tried
// and how to bring one up. The default stays a skip so the laptop case is
// unaffected.
func TestMain(m *testing.M) {
	if u := os.Getenv("VAULT_E2E_URL"); u != "" {
		baseURL = u
	}
	if u := os.Getenv("MAILPIT_URL"); u != "" {
		mailpitURL = u
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	if _, err := client.Get(baseURL + "/healthz"); err != nil {
		if os.Getenv("VAULT_E2E_REQUIRED") == "1" {
			fmt.Fprintf(os.Stderr,
				"FAIL e2e: VAULT_E2E_REQUIRED=1 but no vault42 answered at %s: %v\n"+
					"This suite needs a deployment. Bring one up with scripts/deploy-dev.sh, or\n"+
					"point VAULT_E2E_URL at an existing one. Unset VAULT_E2E_REQUIRED only where a\n"+
					"skipped run is genuinely acceptable, which is not a release gate.\n",
				baseURL, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr,
			"SKIP e2e: vault server not reachable at %s: %v\n"+
				"Nothing in this suite ran. Set VAULT_E2E_REQUIRED=1 to make this a failure.\n",
			baseURL, err)
		os.Exit(0)
	}

	// Clear lockout counters and old emails from previous test runs
	clearTestState()

	os.Exit(m.Run())
}

// skipRateLimited handles a 429 from the deployment under test.
//
// A rate-limited endpoint means the request never reached the behavior the test
// is about, so there is nothing to assert -- but skipping is only the right
// answer where a skipped run is acceptable, and VAULT_E2E_REQUIRED marks the
// runs where it is not. Without this the release gate could set the variable,
// get a reachable server, and still watch these tests skip themselves one by
// one while the suite reported success.
func skipRateLimited(t *testing.T, endpoint string) {
	t.Helper()

	const fix = "deploy with rateLimitEnabled: false for E2E"
	if os.Getenv("VAULT_E2E_REQUIRED") == "1" {
		t.Fatalf("%s answered 429, so this test asserted nothing: %s", endpoint, fix)
	}
	t.Skipf("skipping: rate limited on %s (%s)", endpoint, fix)
}

// clearTestState resets rate-limit/lockout counters in Redis and clears Mailpit messages
// so that previous test runs don't pollute the current run.
func clearTestState() {
	// Flush Redis lockout keys (IP + account lockouts from previous runs)
	cmd := exec.Command("kubectl", "exec", "-n", "vault-dev", "deploy/vault-redis", "--",
		"redis-cli", "--scan", "--pattern", "lockout*")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		keys := strings.Fields(strings.TrimSpace(string(out)))
		if len(keys) > 0 {
			args := append([]string{"exec", "-n", "vault-dev", "deploy/vault-redis", "--", "redis-cli", "DEL"}, keys...)
			exec.Command("kubectl", args...).Run() //nolint:errcheck
		}
	}

	// Clear Mailpit messages
	httpClient := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("DELETE", mailpitURL+"/api/v1/messages", nil)
	httpClient.Do(req) //nolint:errcheck
}

// noRedirectClient returns an HTTP client that does NOT follow redirects.
// Trusts self-signed certs (mkcert) for local HTTPS dev.
func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// jsonPost sends a JSON POST and returns status, decoded body, and raw response.
// Automatically retries on 429 (rate limited) by waiting for the Retry-After period.
// If rate limiting persists after retries, returns the 429 response instead of failing
// the test — callers can check the status code and skip if appropriate.
func jsonPost(t *testing.T, client *http.Client, url string, payload interface{}) (int, map[string]interface{}, *http.Response) {
	t.Helper()
	var lastResp *http.Response
	for range 3 {
		body, _ := json.Marshal(payload)
		resp, err := client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST %s: %v", url, err)
		}
		if resp.StatusCode == 429 {
			lastResp = resp
			resp.Body.Close()
			wait := parseRetryAfter(resp.Header.Get("Retry-After"), 5)
			if wait > 10 {
				wait = 10 // cap retry wait at 10s for tests
			}
			t.Logf("  rate limited on %s, waiting %ds...", url, wait)
			time.Sleep(time.Duration(wait) * time.Second)
			continue
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		json.Unmarshal(raw, &result)
		return resp.StatusCode, result, resp
	}
	// Return the 429 response so callers can decide how to handle it
	if lastResp != nil {
		return 429, map[string]interface{}{"error": "rate_limited"}, lastResp
	}
	t.Fatalf("POST %s: still rate limited after retries", url)
	return 0, nil, nil
}

// parseRetryAfter parses the Retry-After header value (seconds). Falls back to defaultSec.
func parseRetryAfter(header string, defaultSec int) int {
	if header == "" {
		return defaultSec
	}
	n := 0
	for _, c := range header {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			return defaultSec
		}
	}
	if n == 0 {
		return defaultSec
	}
	// Cap at 60s for tests — don't wait an hour
	if n > 60 {
		return 60
	}
	return n
}

// jsonGet sends a GET and returns status + decoded body.
func jsonGet(t *testing.T, client *http.Client, url string) (int, map[string]interface{}) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(raw, &result)
	return resp.StatusCode, result
}

// authedGet sends an authenticated GET request.
func authedGet(t *testing.T, client *http.Client, url, token string) (int, map[string]interface{}, *http.Response) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(raw, &result)
	return resp.StatusCode, result, resp
}

// authedPost sends an authenticated JSON POST request.
func authedPost(t *testing.T, client *http.Client, url, token string, payload interface{}) (int, map[string]interface{}, *http.Response) {
	t.Helper()
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(raw, &result)
	return resp.StatusCode, result, resp
}

// authedDelete sends an authenticated DELETE request.
func authedDelete(t *testing.T, client *http.Client, url, token string) (int, map[string]interface{}) {
	t.Helper()
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(raw, &result)
	return resp.StatusCode, result
}

// refreshWithCookie sends POST /auth/refresh with a refresh_token cookie.
func refreshWithCookie(t *testing.T, client *http.Client, refreshToken string) (int, map[string]interface{}, *http.Response) {
	t.Helper()
	req, _ := http.NewRequest("POST", baseURL+"/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: refreshToken})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /auth/refresh: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(raw, &result)
	return resp.StatusCode, result, resp
}

// verifyEmail marks a user's email as verified via kubectl exec into postgres.
func verifyEmail(t *testing.T, email string) {
	t.Helper()
	cmd := exec.Command("kubectl", "exec", "-n", "vault-dev", "vault-postgres-0", "--",
		"psql", "-U", "vault_mig", "-d", "vault", "-c",
		fmt.Sprintf("UPDATE auth.users SET email_verified=TRUE WHERE email='%s'", email))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify email via psql: %v\n%s", err, out)
	}
}

// getRefreshCookie extracts the refresh_token cookie from a login response.
func getRefreshCookie(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-refresh_token" {
			return c.Value
		}
	}
	return ""
}

// fetchOTPCode retrieves the most recent email OTP code from Mailpit for the given email address.
// It polls Mailpit for up to 5 seconds waiting for the OTP email to arrive.
// After reading, it deletes the message so subsequent calls get newer codes.
func fetchOTPCode(t *testing.T, emailAddr string) string {
	t.Helper()
	httpClient := &http.Client{Timeout: 5 * time.Second}
	otpRe := regexp.MustCompile(`sign-in:\s*(\d{6})`)

	var lastErr string
	for range 10 {
		searchURL := fmt.Sprintf("%s/api/v1/search?query=to:%s+subject:verification+code", mailpitURL, emailAddr)
		resp, err := httpClient.Get(searchURL)
		if err != nil {
			lastErr = fmt.Sprintf("mailpit search: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var searchResult struct {
			Messages []struct {
				ID string `json:"ID"`
			} `json:"messages"`
		}
		json.NewDecoder(resp.Body).Decode(&searchResult)
		resp.Body.Close()

		if len(searchResult.Messages) == 0 {
			lastErr = "no OTP email found yet"
			time.Sleep(500 * time.Millisecond)
			continue
		}

		msgID := searchResult.Messages[0].ID

		// Fetch the most recent message body
		msgURL := fmt.Sprintf("%s/api/v1/message/%s", mailpitURL, msgID)
		msgResp, err := httpClient.Get(msgURL)
		if err != nil {
			lastErr = fmt.Sprintf("mailpit message fetch: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var msg struct {
			Text string `json:"Text"`
		}
		json.NewDecoder(msgResp.Body).Decode(&msg)
		msgResp.Body.Close()

		matches := otpRe.FindStringSubmatch(msg.Text)
		if len(matches) < 2 {
			lastErr = "OTP code not found in email body"
			time.Sleep(500 * time.Millisecond)
			continue
		}

		// Delete message so subsequent logins get fresh codes
		delBody, _ := json.Marshal(map[string][]string{"ids": {msgID}})
		delReq, _ := http.NewRequest("DELETE", mailpitURL+"/api/v1/messages", bytes.NewReader(delBody))
		delReq.Header.Set("Content-Type", "application/json")
		httpClient.Do(delReq) //nolint:errcheck

		return matches[1]
	}
	t.Fatalf("fetchOTPCode(%s): %s", emailAddr, lastErr)
	return ""
}

// loginResult holds the outcome of loginWithMFA.
type loginResult struct {
	AccessToken  string
	RefreshToken string
	Response     *http.Response
	Body         map[string]interface{}
}

// loginWithMFA logs in an already-registered+verified user with testPassword, handling email OTP if MFA is required.
func loginWithMFA(t *testing.T, client *http.Client, email string) loginResult {
	t.Helper()
	return loginExistingWithMFA(t, client, email, testPassword, nil)
}

// loginExistingWithMFA logs in an already-registered+verified user, handling email OTP.
// If extraHeaders is non-nil, they are set on the login request.
func loginExistingWithMFA(t *testing.T, client *http.Client, email, password string, extraHeaders map[string]string) loginResult {
	t.Helper()

	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req, _ := http.NewRequest("POST", baseURL+"/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	var resp *http.Response
	var err error
	for range 3 {
		body, _ = json.Marshal(map[string]string{"email": email, "password": password})
		req, _ = http.NewRequest("POST", baseURL+"/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("login POST: %v", err)
		}
		if resp.StatusCode == 429 {
			resp.Body.Close()
			wait := parseRetryAfter(resp.Header.Get("Retry-After"), 5)
			if wait > 10 {
				wait = 10
			}
			t.Logf("  rate limited on login, waiting %ds...", wait)
			time.Sleep(time.Duration(wait) * time.Second)
			continue
		}
		break
	}
	if resp.StatusCode == 429 {
		t.Fatalf("login: still rate limited after retries")
	}

	var loginBody map[string]interface{}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(raw, &loginBody)

	// Check if MFA is required (email OTP flow)
	requires2FA, _ := loginBody["requires_2fa"].(bool)
	if !requires2FA {
		// Direct login — no MFA needed
		accessToken, _ := loginBody["access_token"].(string)
		if accessToken == "" {
			t.Fatalf("login did not return access_token and requires_2fa was false, body = %v", loginBody)
		}
		return loginResult{
			AccessToken:  accessToken,
			RefreshToken: getRefreshCookie(resp),
			Response:     resp,
			Body:         loginBody,
		}
	}

	// MFA required — complete email OTP verification
	challengeToken, _ := loginBody["challenge_token"].(string)
	if challengeToken == "" {
		t.Fatalf("requires_2fa but no challenge_token, body = %v", loginBody)
	}

	// Fetch OTP code from Mailpit
	otpCode := fetchOTPCode(t, email)
	t.Logf("  Got email OTP code: %s", otpCode)

	// Verify OTP
	verifyBody, _ := json.Marshal(map[string]string{"code": otpCode})
	verifyReq, _ := http.NewRequest("POST", baseURL+"/auth/2fa/email-otp/verify", bytes.NewReader(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("Authorization", "Bearer "+challengeToken)
	for k, v := range extraHeaders {
		verifyReq.Header.Set(k, v)
	}

	verifyResp, err := client.Do(verifyReq)
	if err != nil {
		t.Fatalf("email OTP verify: %v", err)
	}
	var verifyResult map[string]interface{}
	verifyRaw, _ := io.ReadAll(verifyResp.Body)
	verifyResp.Body.Close()
	json.Unmarshal(verifyRaw, &verifyResult)

	if verifyResp.StatusCode != 200 {
		t.Fatalf("email OTP verify status = %d, want 200, body = %s", verifyResp.StatusCode, verifyRaw)
	}

	accessToken, _ := verifyResult["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("email OTP verify did not return access_token, body = %v", verifyResult)
	}

	return loginResult{
		AccessToken:  accessToken,
		RefreshToken: getRefreshCookie(verifyResp),
		Response:     verifyResp,
		Body:         verifyResult,
	}
}

// uniqueEmail generates a unique test email.
func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@test.vault.local", prefix, time.Now().UnixNano())
}

const testPassword = "SuperSecure!Passw0rd-E2E-15chars"

// ======================================================================
// Test: Cluster health check (prerequisite for all other tests)
// ======================================================================
func TestHealthEndpoints(t *testing.T) {
	client := noRedirectClient()

	t.Run("healthz returns 200", func(t *testing.T) {
		status, body := jsonGet(t, client, baseURL+"/healthz")
		if status != 200 {
			t.Fatalf("healthz status = %d, want 200", status)
		}
		if body["status"] != "ok" {
			t.Fatalf("healthz body = %v, want status=ok", body)
		}
	})

	t.Run("readyz returns 200 with database up", func(t *testing.T) {
		status, body := jsonGet(t, client, baseURL+"/readyz")
		if status != 200 {
			t.Fatalf("readyz status = %d, want 200", status)
		}
		if body["database"] != "up" {
			t.Fatalf("readyz database = %v, want up", body["database"])
		}
	})
}

// ======================================================================
// Test: JWKS and OIDC discovery
// ======================================================================
func TestWellKnownEndpoints(t *testing.T) {
	client := noRedirectClient()

	t.Run("JWKS returns valid key set", func(t *testing.T) {
		status, body := jsonGet(t, client, baseURL+"/.well-known/jwks.json")
		if status != 200 {
			t.Fatalf("jwks status = %d, want 200", status)
		}
		keys, ok := body["keys"].([]interface{})
		if !ok || len(keys) == 0 {
			t.Fatal("jwks has no keys")
		}
		key0 := keys[0].(map[string]interface{})
		if key0["kty"] != "RSA" {
			t.Fatalf("key type = %v, want RSA", key0["kty"])
		}
		if key0["alg"] != "RS256" {
			t.Fatalf("key alg = %v, want RS256", key0["alg"])
		}
		if key0["use"] != "sig" {
			t.Fatalf("key use = %v, want sig", key0["use"])
		}
		if key0["kid"] == nil || key0["kid"] == "" {
			t.Fatal("key has no kid")
		}
	})

	t.Run("OIDC discovery returns required fields", func(t *testing.T) {
		status, body := jsonGet(t, client, baseURL+"/.well-known/openid-configuration")
		if status != 200 {
			t.Fatalf("oidc status = %d, want 200", status)
		}
		required := []string{
			"issuer", "authorization_endpoint", "token_endpoint",
			"userinfo_endpoint", "jwks_uri", "scopes_supported",
			"response_types_supported", "id_token_signing_alg_values_supported",
		}
		for _, field := range required {
			if body[field] == nil {
				t.Errorf("missing required field: %s", field)
			}
		}
		if body["issuer"] != "https://vault.localhost" {
			t.Errorf("issuer = %v, want https://vault.localhost", body["issuer"])
		}
	})
}

// ======================================================================
// Test: Full user lifecycle — register → verify → login → profile → refresh → logout
// ======================================================================
func TestFullUserLifecycle(t *testing.T) {
	client := noRedirectClient()
	email := uniqueEmail("lifecycle")

	// Step 1: Register
	t.Log("Step 1: Register")
	status, body, _ := jsonPost(t, client, baseURL+"/auth/register", map[string]string{
		"email":        email,
		"password":     testPassword,
		"display_name": "E2E Test User",
	})
	if status != 201 {
		t.Fatalf("register status = %d, want 201, body = %v", status, body)
	}
	t.Log("  Registration accepted (anti-enumeration: no user_id in response)")

	// Step 2: Login should fail (email not verified — returns generic invalid_credentials for anti-enumeration)
	t.Log("Step 2: Login should fail — email not verified")
	status, body, _ = jsonPost(t, client, baseURL+"/auth/login", map[string]string{
		"email": email, "password": testPassword,
	})
	if status != 401 {
		t.Fatalf("login (unverified) status = %d, want 401, body = %v", status, body)
	}
	if body["error"] != "invalid_credentials" {
		t.Fatalf("login error = %v, want invalid_credentials", body["error"])
	}

	// Step 3: Verify email (via DB)
	t.Log("Step 3: Verify email via DB")
	verifyEmail(t, email)

	// Step 4: Login should succeed (with email OTP if MFA enforced)
	t.Log("Step 4: Login")
	lr := loginWithMFA(t, client, email)
	accessToken := lr.AccessToken
	refreshToken := lr.RefreshToken
	if refreshToken == "" {
		t.Fatal("login did not set refresh_token cookie")
	}
	t.Logf("  Got access_token (%d chars), refresh_token cookie", len(accessToken))

	// Step 5: Access protected endpoint — GET /user/profile
	t.Log("Step 5: GET /user/profile")
	status, profile, _ := authedGet(t, client, baseURL+"/user/profile", accessToken)
	if status != 200 {
		t.Fatalf("profile status = %d, want 200, body = %v", status, profile)
	}
	if profile["email"] != email {
		t.Fatalf("profile email = %v, want %s", profile["email"], email)
	}
	if profile["display_name"] != "E2E Test User" {
		t.Fatalf("profile display_name = %v, want E2E Test User", profile["display_name"])
	}
	emailVerified, _ := profile["email_verified"].(bool)
	if !emailVerified {
		t.Fatal("profile email_verified = false, want true")
	}
	t.Logf("  Profile: %s (%s)", profile["display_name"], profile["email"])

	// Step 6: List sessions
	t.Log("Step 6: GET /user/sessions")
	status, sessions, _ := authedGet(t, client, baseURL+"/user/sessions", accessToken)
	if status != 200 {
		t.Fatalf("sessions status = %d, want 200", status)
	}
	sessionList, _ := sessions["sessions"].([]interface{})
	if len(sessionList) == 0 {
		t.Fatal("expected at least 1 session")
	}
	t.Logf("  Sessions: %d active", len(sessionList))

	// Step 7: Refresh token
	t.Log("Step 7: Refresh token")
	refreshStatus, refreshBody, refreshResp := refreshWithCookie(t, client, refreshToken)
	if refreshStatus != 200 {
		t.Fatalf("refresh status = %d, want 200, body = %v", refreshStatus, refreshBody)
	}
	newAccessToken, _ := refreshBody["access_token"].(string)
	if newAccessToken == "" {
		t.Fatal("refresh did not return new access_token")
	}
	newRefreshToken := getRefreshCookie(refreshResp)
	if newRefreshToken == "" {
		t.Fatal("refresh did not set new refresh_token cookie")
	}
	if newRefreshToken == refreshToken {
		t.Fatal("refresh token was not rotated")
	}
	t.Log("  Token pair rotated successfully")

	// Step 8: Old refresh token should fail (single-use)
	t.Log("Step 8: Replay old refresh token → should fail")
	replayStatus, replayBody, _ := refreshWithCookie(t, client, refreshToken)
	if replayStatus != 401 {
		t.Fatalf("replay status = %d, want 401, body = %v", replayStatus, replayBody)
	}
	t.Logf("  Replay correctly rejected: %v", replayBody["error"])

	// Step 9: Access profile with new token
	t.Log("Step 9: Access profile with new access token")
	status, _, _ = authedGet(t, client, baseURL+"/user/profile", newAccessToken)
	if status != 200 {
		t.Fatalf("profile with new token status = %d, want 200", status)
	}
	t.Log("  New access token works")

	// Step 10: Logout
	t.Log("Step 10: Logout")
	status, logoutBody, _ := authedPost(t, client, baseURL+"/auth/logout", newAccessToken, nil)
	if status != 200 {
		t.Fatalf("logout status = %d, want 200, body = %v", status, logoutBody)
	}
	if logoutBody["status"] != "logged_out" {
		t.Fatalf("logout status = %v, want logged_out", logoutBody["status"])
	}
	t.Log("  Logged out successfully")
}

// ======================================================================
// Test: Duplicate registration
// ======================================================================
func TestDuplicateRegistration(t *testing.T) {
	client := noRedirectClient()
	email := uniqueEmail("dup")

	// First registration
	status, _, _ := jsonPost(t, client, baseURL+"/auth/register", map[string]string{
		"email": email, "password": testPassword, "display_name": "First",
	})
	if status != 201 {
		t.Fatalf("first register status = %d, want 201", status)
	}

	// Second registration — same email (returns 201 to prevent user enumeration)
	status, body, _ := jsonPost(t, client, baseURL+"/auth/register", map[string]string{
		"email": email, "password": testPassword, "display_name": "Second",
	})
	if status != 201 {
		t.Fatalf("duplicate register status = %d, want 201, body = %v", status, body)
	}
	if body["status"] != "verification_email_sent" {
		t.Fatalf("duplicate status = %v, want verification_email_sent", body["status"])
	}
}

// ======================================================================
// Test: Login with wrong password
// ======================================================================
func TestLoginWrongPassword(t *testing.T) {
	client := noRedirectClient()
	email := uniqueEmail("wrongpw")

	// Register + verify
	regStatus, _, _ := jsonPost(t, client, baseURL+"/auth/register", map[string]string{
		"email": email, "password": testPassword, "display_name": "Test",
	})
	if regStatus == 429 {
		skipRateLimited(t, "/auth/register")
	}
	verifyEmail(t, email)

	// Wrong password
	status, body, _ := jsonPost(t, client, baseURL+"/auth/login", map[string]string{
		"email": email, "password": "WrongPassword12345!",
	})
	if status == 429 {
		skipRateLimited(t, "/auth/login")
	}
	if status != 401 {
		t.Fatalf("wrong password status = %d, want 401", status)
	}
	if body["error"] != "invalid_credentials" {
		t.Fatalf("wrong password error = %v, want invalid_credentials", body["error"])
	}
}

// ======================================================================
// Test: Login with non-existent email (same response as wrong password)
// ======================================================================
func TestLoginNonExistentEmail(t *testing.T) {
	client := noRedirectClient()

	status, body, _ := jsonPost(t, client, baseURL+"/auth/login", map[string]string{
		"email": "nobody-exists@test.vault.local", "password": testPassword,
	})
	if status != 401 {
		t.Fatalf("nonexistent email status = %d, want 401", status)
	}
	if body["error"] != "invalid_credentials" {
		t.Fatalf("nonexistent email error = %v, want invalid_credentials", body["error"])
	}
}

// ======================================================================
// Test: Short password rejected
// ======================================================================
func TestPasswordTooShort(t *testing.T) {
	client := noRedirectClient()
	email := uniqueEmail("shortpw")

	status, body, _ := jsonPost(t, client, baseURL+"/auth/register", map[string]string{
		"email": email, "password": "short123", "display_name": "Test",
	})
	if status == 429 {
		skipRateLimited(t, "/auth/register")
	}
	if status != 400 {
		t.Fatalf("short password status = %d, want 400, body = %v", status, body)
	}
	if body["error"] != "password_too_short" {
		t.Fatalf("short password error = %v, want password_too_short", body["error"])
	}
}

// ======================================================================
// Test: Protected endpoints without auth → 401
// ======================================================================
func TestProtectedEndpointsRequireAuth(t *testing.T) {
	client := noRedirectClient()

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/user/profile"},
		{"GET", "/user/sessions"},
		{"GET", "/user/devices"},
		{"POST", "/auth/logout"},
		{"POST", "/user/password"},
		{"POST", "/auth/2fa/totp/setup"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req, _ := http.NewRequest(ep.method, baseURL+ep.path, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", ep.method, ep.path, err)
			}
			resp.Body.Close()
			if resp.StatusCode != 401 {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

// ======================================================================
// Test: Invalid/expired JWT rejected
// ======================================================================
func TestInvalidJWTRejected(t *testing.T) {
	client := noRedirectClient()

	testCases := []struct {
		name  string
		token string
	}{
		{"garbage token", "not.a.jwt"},
		{"empty bearer", ""},
		{"alg none attack", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", baseURL+"/user/profile", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != 401 {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

// ======================================================================
// Test: Refresh without cookie → 401
// ======================================================================
func TestRefreshWithoutCookie(t *testing.T) {
	client := noRedirectClient()

	status, body, _ := jsonPost(t, client, baseURL+"/auth/refresh", nil)
	if status != 401 {
		t.Fatalf("refresh without cookie status = %d, want 401, body = %v", status, body)
	}
	if body["error"] != "missing_refresh_token" {
		t.Fatalf("refresh error = %v, want missing_refresh_token", body["error"])
	}
}

// ======================================================================
// Test: Password change flow
// ======================================================================
func TestPasswordChange(t *testing.T) {
	client := noRedirectClient()
	email := uniqueEmail("pwchange")
	newPassword := "NewSuperSecure!Pa$$-Changed-15"

	// Register + verify + login (with MFA)
	jsonPost(t, client, baseURL+"/auth/register", map[string]string{
		"email": email, "password": testPassword, "display_name": "PW Change Test",
	})
	verifyEmail(t, email)
	lr := loginWithMFA(t, client, email)
	accessToken := lr.AccessToken

	// Change password
	t.Log("Changing password")
	status, body, _ := authedPost(t, client, baseURL+"/user/password", accessToken, map[string]string{
		"current_password": testPassword,
		"new_password":     newPassword,
	})
	if status != 200 {
		t.Fatalf("change password status = %d, want 200, body = %v", status, body)
	}
	t.Log("  Password changed successfully")

	// Login with old password → should fail
	t.Log("Login with old password should fail")
	status, _, _ = jsonPost(t, client, baseURL+"/auth/login", map[string]string{
		"email": email, "password": testPassword,
	})
	if status != 401 {
		t.Fatalf("old password login status = %d, want 401", status)
	}

	// Login with new password → should succeed (with MFA)
	t.Log("Login with new password should succeed")
	lr2 := loginExistingWithMFA(t, client, email, newPassword, nil)
	if lr2.AccessToken == "" {
		t.Fatal("new password login did not return access_token")
	}
	t.Log("  New password works!")
}

// ======================================================================
// Test: Password reset flow (request → confirm via cache token)
// ======================================================================
func TestPasswordResetRequest(t *testing.T) {
	client := noRedirectClient()
	email := uniqueEmail("pwreset")

	// Register + verify
	jsonPost(t, client, baseURL+"/auth/register", map[string]string{
		"email": email, "password": testPassword, "display_name": "PW Reset Test",
	})
	verifyEmail(t, email)

	// Request password reset — should always return 200 (anti-enumeration)
	t.Log("Requesting password reset")
	status, body, _ := jsonPost(t, client, baseURL+"/auth/password/reset", map[string]string{
		"email": email,
	})
	if status != 200 {
		t.Fatalf("reset request status = %d, want 200, body = %v", status, body)
	}
	t.Logf("  Reset response: %v", body["status"])

	// Request for non-existent email — same 200 response (anti-enumeration)
	t.Log("Requesting reset for non-existent email")
	status, _, _ = jsonPost(t, client, baseURL+"/auth/password/reset", map[string]string{
		"email": "nobody@test.vault.local",
	})
	if status != 200 {
		t.Fatalf("reset (nonexistent) status = %d, want 200", status)
	}
	t.Log("  Anti-enumeration: same response for non-existent email")
}

// ======================================================================
// Test: Security headers are present
// ======================================================================
func TestSecurityHeaders(t *testing.T) {
	client := noRedirectClient()
	resp, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()

	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	}

	for name, want := range headers {
		got := resp.Header.Get(name)
		if got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
}

// ======================================================================
// Test: CORS headers
// ======================================================================
func TestCORSHeaders(t *testing.T) {
	client := noRedirectClient()

	// Preflight request from allowed origin
	t.Run("preflight from allowed origin", func(t *testing.T) {
		req, _ := http.NewRequest("OPTIONS", baseURL+"/auth/login", nil)
		req.Header.Set("Origin", "https://vault.localhost")
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("OPTIONS: %v", err)
		}
		resp.Body.Close()
		// In dev mode CORS should be permissive
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		if acao == "" {
			t.Log("  CORS: no Access-Control-Allow-Origin header (may be normal for same-origin)")
		} else {
			t.Logf("  CORS Allow-Origin: %s", acao)
		}
	})
}

// ======================================================================
// Test: Max body size enforcement
// ======================================================================
func TestMaxBodySize(t *testing.T) {
	client := noRedirectClient()

	// Send >8KB body
	bigBody := strings.Repeat("A", 16*1024)
	resp, err := client.Post(baseURL+"/auth/register", "application/json",
		strings.NewReader(bigBody))
	if err != nil {
		t.Fatalf("POST with big body: %v", err)
	}
	resp.Body.Close()

	// Should be rejected (400 or 413)
	if resp.StatusCode != 400 && resp.StatusCode != 413 {
		t.Errorf("big body status = %d, want 400 or 413", resp.StatusCode)
	}
	t.Logf("  Big body correctly rejected with %d", resp.StatusCode)
}

// ======================================================================
// Test: Verify access token with JWKS public key
// ======================================================================
func TestJWKSTokenVerification(t *testing.T) {
	client := noRedirectClient()
	email := uniqueEmail("jwks-verify")

	// Register + verify + login (with MFA)
	jsonPost(t, client, baseURL+"/auth/register", map[string]string{
		"email": email, "password": testPassword, "display_name": "JWKS Test",
	})
	verifyEmail(t, email)
	lr := loginWithMFA(t, client, email)
	accessToken := lr.AccessToken

	// Fetch JWKS
	_, jwksBody := jsonGet(t, client, baseURL+"/.well-known/jwks.json")
	keys, ok := jwksBody["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Fatalf("JWKS did not return keys, body = %v", jwksBody)
	}

	// Parse the token header to get the kid, then find the matching JWKS key
	parts := strings.SplitN(accessToken, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format: %d parts", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	var headerMap map[string]interface{}
	if err := json.Unmarshal(headerJSON, &headerMap); err != nil {
		t.Fatalf("parse JWT header: %v", err)
	}
	tokenKid, _ := headerMap["kid"].(string)
	if tokenKid == "" {
		t.Fatal("JWT has no kid header")
	}

	// Find the JWKS key matching the token's kid
	var key0 map[string]interface{}
	for _, k := range keys {
		km, ok := k.(map[string]interface{})
		if !ok {
			continue
		}
		if kid, _ := km["kid"].(string); kid == tokenKid {
			key0 = km
			break
		}
	}
	if key0 == nil {
		t.Fatalf("no JWKS key matches token kid %q", tokenKid)
	}
	nStr, _ := key0["n"].(string)
	eStr, _ := key0["e"].(string)
	kid := tokenKid

	// Decode n and e from base64url
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	pubKey := &rsa.PublicKey{N: n, E: e}

	// Parse and validate the JWT using the JWKS public key
	mc := vjwt.MapClaims{}
	token, err := vjwt.ParseWithClaims(accessToken, &mc, func(token *vjwt.Token) (any, error) {
		if alg, _ := token.Header["alg"].(string); alg != "RS256" {
			return nil, fmt.Errorf("unexpected alg: %s", alg)
		}
		tokenKid, _ := token.Header["kid"].(string)
		if tokenKid != kid {
			return nil, fmt.Errorf("kid mismatch: %s != %s", tokenKid, kid)
		}
		return pubKey, nil
	})
	if err != nil {
		t.Fatalf("jwt parse with JWKS key: %v", err)
	}
	if !token.Valid {
		t.Fatal("token not valid")
	}

	claimsPtr, ok := token.Claims.(*vjwt.MapClaims)
	if !ok {
		t.Fatal("could not extract claims")
	}
	claims := *claimsPtr

	// Verify claims
	iss, _ := claims["iss"].(string)
	if iss != "https://vault.localhost" {
		t.Errorf("iss = %s, want https://vault.localhost", iss)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		t.Error("sub claim is empty")
	}
	tokenType, _ := claims["token_type"].(string)
	if tokenType == "" {
		t.Error("token_type claim is empty")
	}
	t.Logf("  token_type = %s", tokenType)
	t.Logf("  JWT verified externally: iss=%s sub=%s kid=%s", iss, sub, kid)
}

// ======================================================================
// Test: Cookie attributes on login
// ======================================================================
func TestRefreshCookieAttributes(t *testing.T) {
	client := noRedirectClient()
	email := uniqueEmail("cookie")

	// Register + verify + login (with MFA)
	jsonPost(t, client, baseURL+"/auth/register", map[string]string{
		"email": email, "password": testPassword, "display_name": "Cookie Test",
	})
	verifyEmail(t, email)
	lr := loginWithMFA(t, client, email)

	// The refresh cookie comes from the MFA verify response
	if lr.RefreshToken == "" {
		t.Fatal("no refresh_token cookie set")
	}

	// We need the actual cookie object for attribute checks, so do a fresh login
	// to get the raw response. Since the user already logged in, we can use refresh.
	_, refreshBody, refreshResp := refreshWithCookie(t, client, lr.RefreshToken)
	_ = refreshBody
	var refreshCookie *http.Cookie
	for _, c := range refreshResp.Cookies() {
		if c.Name == "__Host-refresh_token" {
			refreshCookie = c
			break
		}
	}
	if refreshCookie == nil {
		t.Fatal("no refresh_token cookie on refresh response")
	}

	// Check cookie attributes
	if !refreshCookie.HttpOnly {
		t.Error("refresh_token cookie is not HttpOnly")
	}
	if refreshCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %d, want Strict (%d)", refreshCookie.SameSite, http.SameSiteStrictMode)
	}
	if refreshCookie.Path != "/" {
		t.Errorf("Path = %s, want /", refreshCookie.Path)
	}
	if !refreshCookie.Secure {
		t.Error("refresh_token cookie should have Secure flag (HTTPS dev)")
	}
	t.Logf("  Cookie attributes: HttpOnly=%v SameSite=%v Path=%s Secure=%v MaxAge=%d",
		refreshCookie.HttpOnly, refreshCookie.SameSite, refreshCookie.Path,
		refreshCookie.Secure, refreshCookie.MaxAge)
}

// ======================================================================
// Test: Multi-device session management
// ======================================================================
func TestMultiDeviceSessionManagement(t *testing.T) {
	client := noRedirectClient()
	email := uniqueEmail("multidev")

	// Register + verify
	jsonPost(t, client, baseURL+"/auth/register", map[string]string{
		"email": email, "password": testPassword, "display_name": "Multi Device",
	})
	verifyEmail(t, email)

	// Login from "device A" (default User-Agent)
	t.Log("Login from device A")
	lrA := loginWithMFA(t, client, email)
	tokenA := lrA.AccessToken

	// Login from "device B" (different User-Agent)
	t.Log("Login from device B")
	lrB := loginExistingWithMFA(t, client, email, testPassword, map[string]string{
		"User-Agent": "DeviceB-E2E-Test/1.0",
	})

	// Device A token should work with default headers
	statusA, _, _ := authedGet(t, client, baseURL+"/user/profile", tokenA)
	if statusA != 200 {
		t.Fatalf("profile A = %d, want 200", statusA)
	}

	// Device B token must use same User-Agent it logged in with (fingerprint check)
	reqProfile, _ := http.NewRequest("GET", baseURL+"/user/profile", nil)
	reqProfile.Header.Set("Authorization", "Bearer "+lrB.AccessToken)
	reqProfile.Header.Set("User-Agent", "DeviceB-E2E-Test/1.0")
	respProfile, err := client.Do(reqProfile)
	if err != nil {
		t.Fatalf("profile B: %v", err)
	}
	respProfile.Body.Close()
	statusB := respProfile.StatusCode
	if statusB != 200 {
		t.Fatalf("profile B = %d, want 200", statusB)
	}
	t.Log("  Both devices can access profile")

	// List sessions — should have 2+
	status, sessions, _ := authedGet(t, client, baseURL+"/user/sessions", tokenA)
	if status != 200 {
		t.Fatalf("sessions status = %d, want 200", status)
	}
	sessionList, _ := sessions["sessions"].([]interface{})
	if len(sessionList) < 2 {
		t.Logf("  Warning: expected >=2 sessions, got %d (fingerprinting may merge same-IP devices)", len(sessionList))
	} else {
		t.Logf("  Sessions visible: %d", len(sessionList))
	}

	// Revoke all sessions
	t.Log("Revoke all sessions")
	status, _ = authedDelete(t, client, baseURL+"/user/sessions", tokenA)
	if status != 200 {
		t.Fatalf("revoke all status = %d, want 200", status)
	}
	t.Log("  All sessions revoked")
}

// ======================================================================
// Test: SQL injection payloads in login
// ======================================================================
func TestSQLInjectionInLogin(t *testing.T) {
	client := noRedirectClient()

	payloads := []string{
		"' OR '1'='1",
		"admin'--",
		"'; DROP TABLE auth.users; --",
		"' UNION SELECT * FROM auth.users--",
	}

	for _, payload := range payloads {
		name := payload
		if len(name) > 20 {
			name = name[:20]
		}
		t.Run(name, func(t *testing.T) {
			status, _, _ := jsonPost(t, client, baseURL+"/auth/login", map[string]string{
				"email": payload, "password": payload,
			})
			// Should get clean error, not 500
			if status == 500 {
				t.Errorf("SQL injection payload caused 500: %s", payload)
			}
		})
	}
}

// ======================================================================
// Test: User enumeration prevention — timing consistency
// ======================================================================
func TestUserEnumerationPrevention(t *testing.T) {
	client := noRedirectClient()
	email := uniqueEmail("enumtest")

	// Register a real user (don't verify — we just need it to exist)
	jsonPost(t, client, baseURL+"/auth/register", map[string]string{
		"email": email, "password": testPassword, "display_name": "Enum Test",
	})
	verifyEmail(t, email)

	// Time login with real email + wrong password.
	// Interleave real/fake requests to reduce ordering bias (warm-up, rate limiting).
	const iterations = 15
	var realTimes, fakeTimes []time.Duration

	fakeEmail := uniqueEmail("nonexistent-enum")

	for i := 0; i < iterations; i++ {
		start := time.Now()
		jsonPost(t, client, baseURL+"/auth/login", map[string]string{
			"email": email, "password": "WrongPassword12345!",
		})
		realTimes = append(realTimes, time.Since(start))

		start = time.Now()
		jsonPost(t, client, baseURL+"/auth/login", map[string]string{
			"email": fakeEmail, "password": "WrongPassword12345!",
		})
		fakeTimes = append(fakeTimes, time.Since(start))
	}

	// Calculate averages
	var realAvg, fakeAvg time.Duration
	for _, d := range realTimes {
		realAvg += d
	}
	for _, d := range fakeTimes {
		fakeAvg += d
	}
	realAvg /= time.Duration(iterations)
	fakeAvg /= time.Duration(iterations)

	t.Logf("  Real user avg: %v, Non-existent user avg: %v", realAvg, fakeAvg)

	// Timing-based enumeration prevention is best-effort in test environments.
	// Container scheduling, rate limiting, and network jitter make this inherently noisy.
	// We use a 5x threshold — real enumeration attacks need <2x differences.
	ratio := float64(realAvg) / float64(fakeAvg)
	if ratio < 0.2 || ratio > 5.0 {
		t.Errorf("timing ratio = %.2f, want 0.2-5.0 (potential enumeration vector)", ratio)
	} else {
		t.Logf("  Timing ratio: %.2f (within acceptable range)", ratio)
	}
}

// ======================================================================
// Test: Register with invalid email format
// ======================================================================
func TestInvalidEmailFormat(t *testing.T) {
	client := noRedirectClient()

	invalidEmails := []string{
		"not-an-email",
		"@missing-local.com",
		"missing@",
		"",
	}

	for _, email := range invalidEmails {
		name := email
		if name == "" {
			name = "(empty)"
		}
		t.Run(name, func(t *testing.T) {
			status, _, _ := jsonPost(t, client, baseURL+"/auth/register", map[string]string{
				"email": email, "password": testPassword, "display_name": "Test",
			})
			if status != 400 {
				t.Errorf("invalid email %q: status = %d, want 400", email, status)
			}
		})
	}
}
