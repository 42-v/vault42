//go:build browser

package browser_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

var (
	baseURL    = "https://vault.localhost"
	mailpitURL = "http://mail.localhost"
)

const browserRequiredEnv = "VAULT_BROWSER_REQUIRED"

func TestMain(m *testing.M) {
	if u := os.Getenv("VAULT_BROWSER_URL"); u != "" {
		baseURL = u
	}
	if u := os.Getenv("MAILPIT_URL"); u != "" {
		mailpitURL = u
	}

	// Skip suite if vault is unreachable. A quiet Exit(0) here used to look
	// like a passing gate; name the env var that makes the skip fatal.
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	if _, err := client.Get(baseURL + "/healthz"); err != nil {
		if os.Getenv(browserRequiredEnv) == "1" {
			fmt.Fprintf(os.Stderr,
				"FAIL browser: %s=1 but no vault42 answered at %s: %v\n"+
					"This suite needs a deployment, chromedp and Chrome, plus kubectl and Mailpit.\n"+
					"Bring a vault up with scripts/deploy-dev.sh, or point VAULT_BROWSER_URL at an\n"+
					"existing one. Unset %s only where a skipped run is genuinely acceptable,\n"+
					"which is not a release gate.\n",
				browserRequiredEnv, baseURL, err, browserRequiredEnv)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr,
			"SKIP browser: vault server not reachable at %s: %v\n"+
				"Nothing in this suite ran. Set %s=1 to make this a failure.\n",
			baseURL, err, browserRequiredEnv)
		os.Exit(0)
	}

	// Clear Mailpit messages from previous runs
	clearMailpit()

	os.Exit(m.Run())
}

// clearMailpit deletes all messages in Mailpit so previous test runs don't pollute.
func clearMailpit() {
	c := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("DELETE", mailpitURL+"/api/v1/messages", nil)
	c.Do(req) //nolint:errcheck
}

// newBrowserContext creates a chromedp context with a headless browser.
// Caller must cancel the returned cancel function.
func newBrowserContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, ctxCancel := chromedp.NewContext(allocCtx)

	// Set a global timeout
	ctx, timeoutCancel := context.WithTimeout(ctx, 30*time.Second)

	cancel := func() {
		timeoutCancel()
		ctxCancel()
		allocCancel()
	}

	return ctx, cancel
}

// testPassword is the password used for browser test accounts (>=15 chars per NIST policy).
const testPassword = "BrowserTest!Secure-P@ss15"

// uniqueEmail generates a unique email for browser tests.
func uniqueEmail(prefix string) string {
	return fmt.Sprintf("browser-%s-%d@test.vault.local", prefix, time.Now().UnixNano())
}

// httpClient returns a test HTTP client that trusts self-signed certs.
func httpClient() *http.Client {
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

// registerUser creates a test user via the API.
func registerUser(t *testing.T, email string) {
	t.Helper()
	client := httpClient()

	body, _ := json.Marshal(map[string]string{
		"email": email, "password": testPassword, "display_name": "Browser Test",
	})
	resp, err := client.Post(baseURL+"/auth/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("register status = %d, want 201", resp.StatusCode)
	}
}

// registerUserWithDisplayName creates a test user with a custom display_name.
func registerUserWithDisplayName(t *testing.T, email, displayName string) {
	t.Helper()
	client := httpClient()

	body, _ := json.Marshal(map[string]string{
		"email": email, "password": testPassword, "display_name": displayName,
	})
	resp, err := client.Post(baseURL+"/auth/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("register status = %d, want 201", resp.StatusCode)
	}
}

// verifyEmailViaDB marks a user's email as verified via kubectl exec into postgres.
func verifyEmailViaDB(t *testing.T, email string) {
	t.Helper()
	cmd := exec.Command("kubectl", "exec", "-n", "vault-dev", "vault-postgres-0", "--",
		"psql", "-U", "vault_mig", "-d", "vault", "-c",
		fmt.Sprintf("UPDATE auth.users SET email_verified=TRUE WHERE email='%s'", email))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify email via psql: %v\n%s", err, out)
	}
}

// registerAndVerifyUser creates a test user via the API and verifies their email via DB.
func registerAndVerifyUser(t *testing.T, email string) {
	t.Helper()
	registerUser(t, email)
	verifyEmailViaDB(t, email)
}

// loginResult holds the outcome of a login (with or without MFA).
type loginResult struct {
	AccessToken string
	Response    *http.Response // the final response (login or OTP verify)
}

// loginViaAPI logs in a verified user, completing email OTP if MFA is required.
// Returns the loginResult with access token and the response containing cookies.
// The caller should NOT close the response body — it is already consumed.
func loginViaAPI(t *testing.T, email string) loginResult {
	t.Helper()
	client := httpClient()
	body, _ := json.Marshal(map[string]string{
		"email": email, "password": testPassword,
	})
	resp, err := client.Post(baseURL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("login status = %d, body = %s", resp.StatusCode, raw)
	}

	var loginBody map[string]interface{}
	json.Unmarshal(raw, &loginBody)

	// Check if MFA is required (email OTP flow)
	requires2FA, _ := loginBody["requires_2fa"].(bool)
	if !requires2FA {
		accessToken, _ := loginBody["access_token"].(string)
		if accessToken == "" {
			t.Fatalf("login did not return access_token and requires_2fa was false, body = %v", loginBody)
		}
		return loginResult{AccessToken: accessToken, Response: resp}
	}

	// MFA required — complete email OTP
	challengeToken, _ := loginBody["challenge_token"].(string)
	if challengeToken == "" {
		t.Fatalf("requires_2fa but no challenge_token, body = %v", loginBody)
	}

	otpCode := fetchOTPCode(t, email)
	t.Logf("  Got email OTP code: %s", otpCode)

	verifyBody, _ := json.Marshal(map[string]string{"code": otpCode})
	verifyReq, _ := http.NewRequest("POST", baseURL+"/auth/2fa/email-otp/verify", bytes.NewReader(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("Authorization", "Bearer "+challengeToken)

	verifyResp, err := client.Do(verifyReq)
	if err != nil {
		t.Fatalf("email OTP verify: %v", err)
	}
	verifyRaw, _ := io.ReadAll(verifyResp.Body)
	verifyResp.Body.Close()

	if verifyResp.StatusCode != 200 {
		t.Fatalf("email OTP verify status = %d, want 200, body = %s", verifyResp.StatusCode, verifyRaw)
	}

	var verifyResult map[string]interface{}
	json.Unmarshal(verifyRaw, &verifyResult)

	accessToken, _ := verifyResult["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("email OTP verify did not return access_token, body = %v", verifyResult)
	}

	return loginResult{AccessToken: accessToken, Response: verifyResp}
}

// getRefreshCookie extracts the refresh_token cookie from a response.
func getRefreshCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-refresh_token" {
			return c
		}
	}
	return nil
}

// refreshWithCookie sends POST /auth/refresh with a refresh_token cookie.
func refreshWithCookie(t *testing.T, refreshToken string) (int, map[string]interface{}, *http.Response) {
	t.Helper()
	client := httpClient()
	req, _ := http.NewRequest("POST", baseURL+"/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: refreshToken})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /auth/refresh: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var result map[string]interface{}
	json.Unmarshal(raw, &result)
	return resp.StatusCode, result, resp
}

// fetchOTPCode retrieves the most recent email OTP code from Mailpit for the given email address.
// It polls Mailpit for up to 5 seconds waiting for the OTP email to arrive.
// After reading, it deletes the message so subsequent calls get newer codes.
func fetchOTPCode(t *testing.T, emailAddr string) string {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second}
	otpRe := regexp.MustCompile(`sign-in:\s*(\d{6})`)

	var lastErr string
	for range 10 {
		searchURL := fmt.Sprintf("%s/api/v1/search?query=to:%s+subject:verification+code", mailpitURL, emailAddr)
		resp, err := c.Get(searchURL)
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

		msgURL := fmt.Sprintf("%s/api/v1/message/%s", mailpitURL, msgID)
		msgResp, err := c.Get(msgURL)
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
		c.Do(delReq) //nolint:errcheck

		return matches[1]
	}
	t.Fatalf("fetchOTPCode(%s): %s", emailAddr, lastErr)
	return ""
}

// hasChromeInstalled checks whether a Chrome/Chromium binary is available.
func hasChromeInstalled() bool {
	for _, name := range []string{"google-chrome", "chromium-browser", "chromium"} {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}
