package multireplica_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// transientLimiter reports whether a response is a transient rate-limiter
// condition worth retrying in a test: a 429 (rate limited, drains soon) or a
// 503 rate_limiter_unavailable (the L4 fail-closed path tripped by a momentary
// cache blip — under podman load the shared test-Redis can hiccup). Neither is
// the behavior these cross-replica tests assert (the rate_limit_shared subtest
// detects 429 with its own direct calls), so retrying keeps the suite robust
// without masking real assertions or weakening the fail-closed design.
func transientLimiter(status int, m map[string]interface{}) bool {
	return status == 429 || (status == 503 && m["error"] == "rate_limiter_unavailable")
}

// jsonPost posts JSON, retrying a few times on a transient rate-limiter response.
func jsonPost(t *testing.T, client *http.Client, url string, payload interface{}) (int, map[string]interface{}) {
	t.Helper()
	b, _ := json.Marshal(payload)
	var status int
	var m map[string]interface{}
	for i := 0; i < 6; i++ {
		resp, err := client.Post(url, "application/json", strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("POST %s: %v", url, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		status = resp.StatusCode
		m = nil
		json.Unmarshal(raw, &m)
		if transientLimiter(status, m) {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		return status, m
	}
	return status, m
}

// jsonGet .
func jsonGet(t *testing.T, client *http.Client, url string) (int, map[string]interface{}) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]interface{}
	json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

// authedGet .
func authedGet(t *testing.T, client *http.Client, url, token string) (int, map[string]interface{}) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]interface{}
	json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

// getCookie .
func getCookie(resp *http.Response, name string) string {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// refreshWithCookie posts refresh using cookie to given base.
func refreshWithCookie(t *testing.T, client *http.Client, base, refreshToken string) (int, map[string]interface{}, *http.Response) {
	t.Helper()
	req, _ := http.NewRequest("POST", base+"/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: refreshToken})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var m map[string]interface{}
	json.Unmarshal(raw, &m)
	return resp.StatusCode, m, resp
}

// jsonPostWithResp returns resp for cookie extraction.
func jsonPostWithResp(t *testing.T, client *http.Client, url string, payload interface{}) (int, map[string]interface{}, *http.Response) {
	t.Helper()
	b, _ := json.Marshal(payload)
	resp, err := client.Post(url, "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]interface{}
	json.Unmarshal(raw, &m)
	return resp.StatusCode, m, resp
}

// challengePost posts JSON to a challenge-protected endpoint (e.g. /auth/2fa/*/verify)
// by setting Authorization: Bearer <challengeToken>. Retries on 429 like jsonPost.
func challengePost(t *testing.T, client *http.Client, url, challengeToken string, payload interface{}) (int, map[string]interface{}) {
	t.Helper()
	b, _ := json.Marshal(payload)
	for i := 0; i < 4; i++ {
		req, _ := http.NewRequest("POST", url, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		if challengeToken != "" {
			req.Header.Set("Authorization", "Bearer "+challengeToken)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", url, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var m map[string]interface{}
		json.Unmarshal(raw, &m)
		if transientLimiter(resp.StatusCode, m) {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		return resp.StatusCode, m
	}
	return 429, map[string]interface{}{"error": "rate_limited"}
}

// challengePostWithResp is like challengePost but returns the *Response (body already drained) so
// caller can extract cookies set by the MFA verify response. The helper closes the body.
func challengePostWithResp(t *testing.T, client *http.Client, url, challengeToken string, payload interface{}) (int, map[string]interface{}, *http.Response) {
	t.Helper()
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	if challengeToken != "" {
		req.Header.Set("Authorization", "Bearer "+challengeToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var m map[string]interface{}
	json.Unmarshal(raw, &m)
	return resp.StatusCode, m, resp
}

// loginUser performs login (and MFA email-otp completion if required) against the replica.
// Returns access and refresh (if set on final response).
func loginUser(t *testing.T, client *http.Client, r *testReplica, email, pw string) (access, refresh string) {
	t.Helper()
	var st int
	var lbody map[string]interface{}
	var resp *http.Response
	for i := 0; i < 6; i++ {
		st, lbody, resp = jsonPostWithResp(t, client, r.URL+"/auth/login", map[string]string{
			"email": email, "password": pw,
		})
		if transientLimiter(st, lbody) {
			resp.Body.Close()
			time.Sleep(150 * time.Millisecond)
			continue
		}
		break
	}
	if st != 200 {
		t.Fatalf("login %s: status=%d body=%v", email, st, lbody)
	}
	access, _ = lbody["access_token"].(string)
	refresh = getCookie(resp, "__Host-refresh_token")
	resp.Body.Close()
	if access != "" {
		return access, refresh
	}
	chTok, _ := lbody["challenge_token"].(string)
	if chTok == "" {
		t.Fatalf("no access_token and no challenge_token: %v", lbody)
	}
	code := r.email.getOTP(email)
	if code == "" {
		t.Fatalf("MFA required but no OTP captured for %s", email)
	}
	stV, vbody, vresp := challengePostWithResp(t, client, r.URL+"/auth/2fa/email-otp/verify", chTok, map[string]string{"code": code})
	refresh = getCookie(vresp, "__Host-refresh_token")
	// vresp already closed inside helper
	access, _ = vbody["access_token"].(string)
	if stV != 200 || access == "" {
		t.Fatalf("mfa verify after login: status=%d body=%v", stV, vbody)
	}
	return access, refresh
}

// itoa converts small non-neg int to decimal string (no strconv dep for this package).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	bp := len(b)
	for n > 0 {
		bp--
		b[bp] = byte('0' + n%10)
		n /= 10
	}
	return string(b[bp:])
}
