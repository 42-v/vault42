//go:build stress

package stress

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	baseURL     = envOr("VAULT_STRESS_URL", "https://vault.localhost")
	mailpitURL  = envOr("MAILPIT_URL", "http://mail.localhost")
	concurrency = envInt("STRESS_CONCURRENCY", 50)
	duration    = envDuration("STRESS_DURATION", 30*time.Second)
	testPass    = "StressTest!Secure-15chars"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil && d > 0 {
			return d
		}
	}
	return fallback
}

// stressClient returns an HTTP client tuned for stress testing.
func stressClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- local dev with mkcert
			MaxIdleConnsPerHost: concurrency,
			MaxIdleConns:        concurrency * 2,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// freshConnClient returns a client that doesn't reuse connections.
func freshConnClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- local dev with mkcert
			DisableKeepAlives: true,
		},
	}
}

var emailCounter int64
var emailMu sync.Mutex

// spoofIP returns a unique fake IP via X-Forwarded-For to bypass per-IP rate limits.
// The dev deployment trusts 10.0.0.0/8 as proxy network, so XFF is respected.
func spoofIP() string {
	emailMu.Lock()
	emailCounter++
	n := emailCounter
	emailMu.Unlock()
	// Generate IPs in 172.16.x.x range (private, not in trusted proxy range)
	return fmt.Sprintf("172.16.%d.%d", (n/256)%256, n%256)
}

// spoofHeaders returns headers with a spoofed X-Forwarded-For IP.
func spoofHeaders(extra map[string]string) map[string]string {
	h := map[string]string{
		"X-Forwarded-For": spoofIP(),
	}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

// uniqueEmail generates a unique email for stress test user provisioning.
func uniqueEmail(prefix string) string {
	emailMu.Lock()
	emailCounter++
	n := emailCounter
	emailMu.Unlock()
	return fmt.Sprintf("stress-%s-%d-%d@test.vault.local", prefix, time.Now().UnixNano(), n)
}

// userCreds holds provisioned user credentials.
type userCreds struct {
	Email        string
	AccessToken  string
	RefreshToken string
}

// provisionUser registers a user, verifies email via kubectl psql, and logs in.
// Retries on 429/502/503 (rate limit / backpressure) with exponential backoff.
func provisionUser(t *testing.T, client *http.Client) userCreds {
	t.Helper()
	email := uniqueEmail("user")

	// Register with retries (argon2 semaphore may return 503 under load)
	regBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": testPass,
	})
	var regStatus int
	for attempt := range 10 {
		resp, err := client.Post(baseURL+"/auth/register", "application/json", bytes.NewReader(regBody)) // #nosec G107 -- test code
		if err != nil {
			t.Fatalf("register %s: %v", email, err)
		}
		resp.Body.Close()
		regStatus = resp.StatusCode
		if regStatus == 201 {
			break
		}
		if regStatus == 429 || regStatus == 502 || regStatus == 503 {
			wait := time.Duration(1<<attempt) * 200 * time.Millisecond
			if wait > 5*time.Second {
				wait = 5 * time.Second
			}
			time.Sleep(wait)
			// Re-create body reader (consumed by previous attempt)
			regBody, _ = json.Marshal(map[string]string{
				"email":    email,
				"password": testPass,
			})
			continue
		}
		t.Fatalf("register %s: status %d", email, regStatus)
	}
	if regStatus != 201 {
		t.Fatalf("register %s: status %d after retries", email, regStatus)
	}

	// Verify email via kubectl exec + psql (same pattern as e2e tests)
	verifyEmail(t, email)

	// Login with retries
	var lresp *http.Response
	var raw []byte
	for attempt := range 10 {
		loginBody, _ := json.Marshal(map[string]string{
			"email":    email,
			"password": testPass,
		})
		var err error
		lresp, err = client.Post(baseURL+"/auth/login", "application/json", bytes.NewReader(loginBody)) // #nosec G107 -- test code
		if err != nil {
			t.Fatalf("login %s: %v", email, err)
		}
		raw, _ = io.ReadAll(lresp.Body)
		lresp.Body.Close()
		if lresp.StatusCode == 200 {
			break
		}
		if lresp.StatusCode == 429 || lresp.StatusCode == 502 || lresp.StatusCode == 503 {
			wait := time.Duration(1<<attempt) * 200 * time.Millisecond
			if wait > 5*time.Second {
				wait = 5 * time.Second
			}
			time.Sleep(wait)
			continue
		}
		t.Fatalf("login %s: status %d, body: %s", email, lresp.StatusCode, raw)
	}
	if lresp.StatusCode != 200 {
		t.Fatalf("login %s: status %d after retries, body: %s", email, lresp.StatusCode, raw)
	}

	var result map[string]interface{}
	json.Unmarshal(raw, &result) //nolint:errcheck

	// Handle MFA if required (email OTP via Mailpit)
	if requires2FA, _ := result["requires_2fa"].(bool); requires2FA {
		challengeToken, _ := result["challenge_token"].(string)
		if challengeToken == "" {
			t.Fatalf("login %s: requires_2fa but no challenge_token", email)
		}

		// Fetch OTP code from Mailpit
		otpCode := fetchOTPCode(t, email)

		// Verify OTP with retries
		for attempt := range 5 {
			verifyBody, _ := json.Marshal(map[string]string{"code": otpCode})
			verifyReq, _ := http.NewRequest("POST", baseURL+"/auth/2fa/email-otp/verify", bytes.NewReader(verifyBody))
			verifyReq.Header.Set("Content-Type", "application/json")
			verifyReq.Header.Set("Authorization", "Bearer "+challengeToken)

			verifyResp, vErr := client.Do(verifyReq) // #nosec G107 -- test code
			if vErr != nil {
				t.Fatalf("otp verify %s: %v", email, vErr)
			}
			vRaw, _ := io.ReadAll(verifyResp.Body)
			verifyResp.Body.Close()

			if verifyResp.StatusCode == 200 {
				json.Unmarshal(vRaw, &result) //nolint:errcheck
				lresp = verifyResp
				break
			}
			if verifyResp.StatusCode == 502 || verifyResp.StatusCode == 503 {
				wait := time.Duration(1<<attempt) * 200 * time.Millisecond
				time.Sleep(wait)
				continue
			}
			t.Fatalf("otp verify %s: status %d, body: %s", email, verifyResp.StatusCode, vRaw)
		}
	}

	accessToken, _ := result["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("login %s: no access_token in response: %v", email, result)
	}

	refreshToken := ""
	for _, c := range lresp.Cookies() {
		if c.Name == "__Host-refresh_token" {
			refreshToken = c.Value
			break
		}
	}

	return userCreds{
		Email:        email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
}

// verifyEmail marks a user's email as verified via kubectl exec into postgres.
func verifyEmail(t *testing.T, email string) {
	t.Helper()
	namespace := envOr("KUBE_NAMESPACE", "vault-dev")
	escaped := strings.ReplaceAll(email, "'", "''")
	cmd := exec.Command("kubectl", "exec", "-n", namespace, "vault-postgres-0", "--",
		"psql", "-U", "vault_mig", "-d", "vault", "-c",
		fmt.Sprintf("UPDATE auth.users SET email_verified=TRUE WHERE email='%s'", escaped))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify email via psql: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "UPDATE") {
		t.Fatalf("verify email: unexpected output: %s", out)
	}
}

// fetchOTPCode retrieves the email OTP code from Mailpit for the given email address.
// Polls for up to 10 seconds, deletes the message after reading.
func fetchOTPCode(t *testing.T, emailAddr string) string {
	t.Helper()
	httpClient := &http.Client{Timeout: 5 * time.Second}
	otpRe := regexp.MustCompile(`sign-in:\s*(\d{6})`)

	for range 20 {
		searchURL := fmt.Sprintf("%s/api/v1/search?query=to:%s+subject:verification+code", mailpitURL, emailAddr)
		resp, err := httpClient.Get(searchURL) // #nosec G107 -- test code
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var searchResult struct {
			Messages []struct {
				ID string `json:"ID"`
			} `json:"messages"`
		}
		json.NewDecoder(resp.Body).Decode(&searchResult) //nolint:errcheck
		resp.Body.Close()

		if len(searchResult.Messages) == 0 {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		msgID := searchResult.Messages[0].ID
		msgURL := fmt.Sprintf("%s/api/v1/message/%s", mailpitURL, msgID)
		msgResp, err := httpClient.Get(msgURL) // #nosec G107 -- test code
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var msg struct {
			Text string `json:"Text"`
		}
		json.NewDecoder(msgResp.Body).Decode(&msg) //nolint:errcheck
		msgResp.Body.Close()

		matches := otpRe.FindStringSubmatch(msg.Text)
		if len(matches) < 2 {
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
	t.Fatalf("fetchOTPCode(%s): no OTP email found after 10s", emailAddr)
	return ""
}

// provisionUsers provisions N users concurrently (capped at 3 parallel).
func provisionUsers(t *testing.T, n int) []userCreds {
	t.Helper()
	client := stressClient()
	users := make([]userCreds, n)
	sem := make(chan struct{}, 3) // cap at 3 to avoid overwhelming argon2 semaphore
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error

	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			mu.Lock()
			if firstErr != nil {
				mu.Unlock()
				return
			}
			mu.Unlock()

			u := provisionUser(t, client)
			mu.Lock()
			users[idx] = u
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Verify all users were provisioned
	for i, u := range users {
		if u.Email == "" {
			t.Fatalf("user %d was not provisioned", i)
		}
	}
	return users
}

// postJSON sends a POST with JSON body, returns response, latency, and error.
func postJSON(client *http.Client, url string, body interface{}, headers map[string]string) (*http.Response, time.Duration, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := client.Do(req) // #nosec G107 -- test code
	lat := time.Since(start)
	return resp, lat, err
}

// getJSON sends a GET request, returns response, latency, and error.
func getJSON(client *http.Client, url string, headers map[string]string) (*http.Response, time.Duration, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := client.Do(req) // #nosec G107 -- test code
	lat := time.Since(start)
	return resp, lat, err
}

// runWorkers launches worker goroutines that execute fn in a loop for the given duration.
// fn returns (statusCode, latency). statusCode 0 means a network error/timeout.
func runWorkers(t *testing.T, workers int, dur time.Duration, fn func() (int, time.Duration)) *StressResult {
	t.Helper()

	var allLatencies [][]time.Duration
	allResults := make([]*workerResult, workers)
	latSlices := make([][]time.Duration, workers)

	for i := range workers {
		allResults[i] = &workerResult{}
		latSlices[i] = make([]time.Duration, 0, 1024)
	}

	var wg sync.WaitGroup
	start := time.Now()
	deadline := start.Add(dur)

	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			wr := allResults[idx]
			lats := &latSlices[idx]
			for time.Now().Before(deadline) {
				status, lat := fn()
				wr.record(status, lat)
				*lats = append(*lats, lat)
			}
		}(i)
	}
	wg.Wait()
	wallClock := time.Since(start)

	// Merge results
	merged := &StressResult{Duration: wallClock}
	allLatencies = latSlices
	for i := range workers {
		r := allResults[i].toResult()
		merged.Total += r.Total
		merged.Success += r.Success
		merged.RateLimited += r.RateLimited
		merged.Backpressure += r.Backpressure
		merged.ClientErr += r.ClientErr
		merged.ServerErr += r.ServerErr
		merged.Timeouts += r.Timeouts
	}
	for _, lats := range allLatencies {
		merged.Latencies = append(merged.Latencies, lats...)
	}

	return merged
}

// skipIfUnreachable skips the test if the server is not reachable.
func skipIfUnreachable(t *testing.T) {
	t.Helper()
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- local dev
		},
	}
	_, err := client.Get(baseURL + "/healthz") // #nosec G107 -- test code
	if err != nil {
		t.Skipf("vault server not reachable at %s: %v", baseURL, err)
	}
}
