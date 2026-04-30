package admin_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Shared test state — initialized in TestMain
// ---------------------------------------------------------------------------

var (
	sharedClient     *http.Client
	sharedToken      string
	sharedURL        string
	sharedTOTPSecret string // set during TOTP setup, used by login tests
	logoutToken      string // separate session for TestLogout
)

func TestMain(m *testing.M) {
	sharedURL = envOr("ADMIN_GW_URL", "https://localhost:9443")

	pw := os.Getenv("ADMIN_FIRST_PASSWORD")
	if pw == "" {
		log.Println("ADMIN_FIRST_PASSWORD not set — skipping E2E tests")
		os.Exit(0)
	}

	client, err := makeClient()
	if err != nil {
		log.Fatalf("create mTLS client: %v", err)
	}
	sharedClient = client

	// Login (first boot — no TOTP yet)
	token, requires2FA, err := doLogin(client, "admin", pw, "")
	if err != nil {
		log.Fatalf("login: %v", err)
	}

	// Complete TOTP setup if required
	if requires2FA {
		var secret string
		token, secret, err = setupTOTP(client, token)
		if err != nil {
			log.Fatalf("TOTP setup: %v", err)
		}
		sharedTOTPSecret = secret

		// Create a second session for TestLogout (avoids TOTP replay with TestLoginSuccess).
		// Use +1 period offset to get a fresh counter value.
		logoutTok, _, err := doLoginAt(client, "admin", pw, secret, time.Now().Add(31*time.Second))
		if err != nil {
			log.Fatalf("create logout session: %v", err)
		}
		logoutToken = logoutTok
	}

	sharedToken = token
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// Env / URL helpers
// ---------------------------------------------------------------------------

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func baseURL() string { return sharedURL }

// ---------------------------------------------------------------------------
// mTLS HTTP client
// ---------------------------------------------------------------------------

func makeClient() (*http.Client, error) {
	certFile := envOr("ADMIN_GW_CLIENT_CERT", "../../k8s/dev/admin-certs/client.crt")
	keyFile := envOr("ADMIN_GW_CLIENT_KEY", "../../k8s/dev/admin-certs/client.key")
	caFile := envOr("ADMIN_GW_CA_CERT", "../../k8s/dev/admin-certs/ca.crt")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("parse CA certificate")
	}

	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// newClient creates a fresh mTLS client for tests that need one.
func newClient(t *testing.T) *http.Client {
	t.Helper()
	c, err := makeClient()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	return c
}

// ---------------------------------------------------------------------------
// Login + TOTP setup
// ---------------------------------------------------------------------------

type loginResponse struct {
	Token       string `json:"token"`
	Error       string `json:"error"`
	Requires2FA bool   `json:"requires_2fa"`
}

// doLogin performs a login and returns token + whether 2FA setup is needed.
// If totpSecret is non-empty, a TOTP code is generated for the current time.
func doLogin(client *http.Client, username, password, totpSecret string) (string, bool, error) {
	return doLoginAt(client, username, password, totpSecret, time.Now())
}

// doLoginAt performs a login with a TOTP code generated for the specified time.
// The time offset allows generating codes for future periods to avoid TOTP replay
// rejection (the server accepts ±1 period skew).
func doLoginAt(client *http.Client, username, password, totpSecret string, t time.Time) (string, bool, error) {
	var body string
	if totpSecret != "" {
		code, err := generateTOTPAt(totpSecret, t)
		if err != nil {
			return "", false, fmt.Errorf("generate TOTP code: %w", err)
		}
		body = fmt.Sprintf(`{"username":%q,"password":%q,"totp_code":%q}`, username, password, code)
	} else {
		body = fmt.Sprintf(`{"username":%q,"password":%q}`, username, password)
	}
	resp, err := client.Post(baseURL()+"/admin/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		return "", false, fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	var lr loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return "", false, fmt.Errorf("decode login response: %w", err)
	}
	if lr.Error != "" {
		return "", false, fmt.Errorf("login error: %s", lr.Error)
	}
	if lr.Token == "" {
		return "", false, fmt.Errorf("login response missing token")
	}
	return lr.Token, lr.Requires2FA, nil
}

// setupTOTP performs TOTP enrollment: setup → generate code → verify.
// Returns the same token (session is now 2FA-verified) and the TOTP secret.
func setupTOTP(client *http.Client, token string) (string, string, error) {
	// Step 1: POST /admin/admins/me/totp/setup
	req, _ := http.NewRequest("POST", baseURL()+"/admin/admins/me/totp/setup", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("TOTP setup request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("TOTP setup: status %d: %s", resp.StatusCode, b)
	}

	var setupResp struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&setupResp); err != nil {
		return "", "", fmt.Errorf("decode TOTP setup: %w", err)
	}
	if setupResp.Secret == "" {
		return "", "", fmt.Errorf("TOTP setup response missing secret")
	}

	// Step 2: Generate TOTP code
	code, err := generateTOTP(setupResp.Secret)
	if err != nil {
		return "", "", fmt.Errorf("generate TOTP code: %w", err)
	}

	// Step 3: POST /admin/admins/me/totp/verify
	verifyBody := fmt.Sprintf(`{"code":%q}`, code)
	req2, _ := http.NewRequest("POST", baseURL()+"/admin/admins/me/totp/verify", strings.NewReader(verifyBody))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		return "", "", fmt.Errorf("TOTP verify request: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		return "", "", fmt.Errorf("TOTP verify: status %d: %s", resp2.StatusCode, b)
	}

	return token, setupResp.Secret, nil
}

// generateTOTP generates a 6-digit TOTP code for the current time.
func generateTOTP(secret string) (string, error) {
	return generateTOTPAt(secret, time.Now())
}

// generateTOTPAt generates a 6-digit TOTP code for a specific time.
// Standard RFC 6238: HMAC-SHA1, 30-second period, 6 digits.
func generateTOTPAt(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}

	counter := uint64(t.Unix()) / 30
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key) // #nosec G401 — TOTP requires SHA1 per RFC 6238
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%06d", code%1000000), nil
}

// login authenticates and returns the session token (for tests needing a separate session).
// Uses the shared TOTP secret if set.
func login(t *testing.T, client *http.Client, username, password string) string {
	t.Helper()
	token, _, err := doLogin(client, username, password, sharedTOTPSecret)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return token
}

// getAdminPassword returns the first-boot admin password from env.
func getAdminPassword(t *testing.T) string {
	t.Helper()
	pw := os.Getenv("ADMIN_FIRST_PASSWORD")
	if pw == "" {
		t.Skip("ADMIN_FIRST_PASSWORD not set")
	}
	return pw
}

// ---------------------------------------------------------------------------
// Authenticated request helpers
// ---------------------------------------------------------------------------

func authedGet(t *testing.T, client *http.Client, token, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", baseURL()+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func authedPost(t *testing.T, client *http.Client, token, path string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req, err := http.NewRequest("POST", baseURL()+path, &buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func authedDelete(t *testing.T, client *http.Client, token, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("DELETE", baseURL()+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", path, err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func decodeJSON(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func requireStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		body := readBody(t, resp)
		t.Fatalf("want status %d, got %d; body: %s", want, resp.StatusCode, body)
	}
}

func requireContains(t *testing.T, body, substr string) {
	t.Helper()
	if !strings.Contains(body, substr) {
		t.Errorf("body should contain %q but doesn't; first 500 chars: %s", substr, truncate(body, 500))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
