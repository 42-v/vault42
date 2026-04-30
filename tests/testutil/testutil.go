// Package testutil holds shared test helpers — fixture builders, fake
// HTTP recorders, and time-freezing utilities — used across unit, attack,
// compliance, and integration test suites.
package testutil

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// RegisterUser registers a test user and returns the response.
func RegisterUser(t *testing.T, client *http.Client, baseURL, email, password string) map[string]interface{} {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password, "display_name": "Test"})
	resp, err := client.Post(baseURL+"/auth/register", "application/json", bytes.NewReader(body)) // #nosec G107 -- test utility, URL from test code
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result) // #nosec G104 -- test utility; decode errors surface as nil fields in test assertions
	return result
}

// LoginUser logs in and returns the response + cookies.
func LoginUser(t *testing.T, client *http.Client, baseURL, email, password string) (map[string]interface{}, []*http.Cookie) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := client.Post(baseURL+"/auth/login", "application/json", bytes.NewReader(body)) // #nosec G107 -- test utility, URL from test code
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result) // #nosec G104 -- test utility; decode errors surface as nil fields in test assertions
	return result, resp.Cookies()
}

// AuthRequest makes an authenticated request with a Bearer token.
func AuthRequest(t *testing.T, client *http.Client, method, url, accessToken string, body interface{}) *http.Response {
	t.Helper()
	var reqBody *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("auth request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req) // #nosec G107 G704 -- test utility, URL from test code
	if err != nil {
		t.Fatalf("auth request: %v", err)
	}
	return resp
}

// RefreshTokens refreshes using cookies, returns new response + cookies.
func RefreshTokens(t *testing.T, client *http.Client, baseURL string, cookies []*http.Cookie) (map[string]interface{}, []*http.Cookie) {
	t.Helper()
	req, _ := http.NewRequest("POST", baseURL+"/auth/refresh", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := client.Do(req) // #nosec G107 G704 -- test utility, URL from test code
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result) // #nosec G104 -- test utility; decode errors surface as nil fields in test assertions
	return result, resp.Cookies()
}

// DecodeJSON reads and decodes JSON from an http.Response body. Closes the body.
func DecodeJSON(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result) // #nosec G104 -- test utility; decode errors surface as nil fields in test assertions
	return result
}

// AssertStatus checks the HTTP status code.
func AssertStatus(t *testing.T, resp *http.Response, expected int) {
	t.Helper()
	if resp.StatusCode != expected {
		t.Errorf("status = %d, want %d", resp.StatusCode, expected)
	}
}

// ExtractCookies returns a map of cookie name -> cookie from the response.
func ExtractCookies(resp *http.Response) map[string]*http.Cookie {
	cookies := make(map[string]*http.Cookie)
	for _, c := range resp.Cookies() {
		cookies[c.Name] = c
	}
	return cookies
}

// NoRedirectClient returns an HTTP client that doesn't follow redirects.
func NoRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
