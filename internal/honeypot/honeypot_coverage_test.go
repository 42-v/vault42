package honeypot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ConfigureFakeJWT tests
// ---------------------------------------------------------------------------

func TestConfigureFakeJWT_NoOp(t *testing.T) {
	// ConfigureFakeJWT uses sync.Once, so the first call in the test binary
	// configures and all subsequent calls are no-ops. The default values are
	// "vault"/"vault". We verify that calling it multiple times does not panic
	// and that the output still produces valid JWTs with the original iss/aud.
	ConfigureFakeJWT("should-be-ignored", "should-be-ignored", 15*time.Minute)
	ConfigureFakeJWT("also-ignored", "also-ignored", 15*time.Minute)

	token, err := GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT after ConfigureFakeJWT: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	// Decode payload to check iss/aud.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	// Since sync.Once already fired (possibly with defaults "vault"/"vault"),
	// we just verify the claims are non-empty strings.
	iss, ok := claims["iss"].(string)
	if !ok || iss == "" {
		t.Error("iss claim should be a non-empty string")
	}
	// aud is an array on every token the vault signs, because jwt.ClaimStrings
	// marshals as one. A trap token that spelled it as a bare string could be
	// told apart from a real one by decoding a single segment.
	aud, ok := claims["aud"].([]interface{})
	if !ok || len(aud) == 0 {
		t.Errorf("aud claim should be a non-empty array like a real token's, got %#v", claims["aud"])
	}
}

// ---------------------------------------------------------------------------
// FakeLoginCookie tests
// ---------------------------------------------------------------------------

func TestFakeLoginCookie_ReturnsHexToken(t *testing.T) {
	cookie, err := FakeLoginCookie()
	if err != nil {
		t.Fatalf("FakeLoginCookie error: %v", err)
	}
	if len(cookie) != 64 {
		t.Errorf("cookie length = %d, want 64 hex chars", len(cookie))
	}
	// Verify it is valid hex.
	for _, c := range cookie {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex character %q in cookie", c)
			break
		}
	}
}

func TestFakeLoginCookie_Unique(t *testing.T) {
	c1, err := FakeLoginCookie()
	if err != nil {
		t.Fatalf("FakeLoginCookie: %v", err)
	}
	c2, err := FakeLoginCookie()
	if err != nil {
		t.Fatalf("FakeLoginCookie: %v", err)
	}
	if c1 == c2 {
		t.Error("consecutive FakeLoginCookie calls should produce unique values")
	}
}

// ---------------------------------------------------------------------------
// Err tests
// ---------------------------------------------------------------------------

func TestErr_Format(t *testing.T) {
	err := Err("something failed")
	if err == nil {
		t.Fatal("Err should return non-nil error")
	}
	want := "honeypot: something failed"
	if err.Error() != want {
		t.Errorf("Err message = %q, want %q", err.Error(), want)
	}
}

func TestErr_EmptyMessage(t *testing.T) {
	err := Err("")
	want := "honeypot: "
	if err.Error() != want {
		t.Errorf("Err empty message = %q, want %q", err.Error(), want)
	}
}

// ---------------------------------------------------------------------------
// Alert with webhook error status
// ---------------------------------------------------------------------------

func TestAlert_WebhookReturnsErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	a := NewAlerter(srv.URL, nil, nil)

	// Should not panic; the error status is logged but not propagated.
	a.Alert(context.Background(), Event{
		EventType: "trap_login",
		IP:        "10.0.0.1",
		UserAgent: "test-agent",
		RiskScore: 80,
	})
}

func TestAlert_WebhookReturns500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := NewAlerter(srv.URL, nil, nil)

	// Should not panic.
	a.Alert(context.Background(), Event{
		EventType: "scan_detected",
		IP:        "10.0.0.2",
		RiskScore: 50,
	})
}

// ---------------------------------------------------------------------------
// Alert with failed webhook connection
// ---------------------------------------------------------------------------

func TestAlert_WebhookConnectionFailed(t *testing.T) {
	// Use a URL that will fail to connect (closed server).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	url := srv.URL
	srv.Close() // Close immediately so the connection fails.

	a := NewAlerter(url, nil, nil)

	// Should not panic; connection errors are logged but not propagated.
	a.Alert(context.Background(), Event{
		EventType: "trap_login",
		IP:        "10.0.0.3",
		RiskScore: 90,
	})
}

func TestAlert_WebhookUnresolvableHost(t *testing.T) {
	a := NewAlerter("http://this-host-does-not-exist.invalid:9999/webhook", nil, nil)

	// Should not panic; DNS resolution failure is logged.
	a.Alert(context.Background(), Event{
		EventType: "probe",
		IP:        "10.0.0.4",
		RiskScore: 20,
	})
}

// ---------------------------------------------------------------------------
// NewAlerter with invalid URL scheme
// ---------------------------------------------------------------------------

func TestNewAlerter_InvalidScheme(t *testing.T) {
	a := NewAlerter("ftp://example.com/webhook", []string{"trap@test.com"}, nil)

	// webhookURL should be sanitized to empty.
	if a.webhookURL != "" {
		t.Errorf("webhookURL should be empty for invalid scheme, got %q", a.webhookURL)
	}

	// Trap users should still work.
	if !a.IsTrapUser("trap@test.com") {
		t.Error("trap user should still be configured")
	}
}

func TestNewAlerter_FileScheme(t *testing.T) {
	a := NewAlerter("file:///etc/passwd", nil, nil)
	if a.webhookURL != "" {
		t.Errorf("webhookURL should be empty for file:// scheme, got %q", a.webhookURL)
	}
}

func TestNewAlerter_JavascriptScheme(t *testing.T) {
	a := NewAlerter("javascript:alert(1)", nil, nil)
	if a.webhookURL != "" {
		t.Errorf("webhookURL should be empty for javascript: scheme, got %q", a.webhookURL)
	}
}

func TestNewAlerter_ValidHTTPS(t *testing.T) {
	a := NewAlerter("https://hooks.example.com/alert", nil, nil)
	if a.webhookURL != "https://hooks.example.com/alert" {
		t.Errorf("webhookURL = %q, want https://hooks.example.com/alert", a.webhookURL)
	}
}

func TestNewAlerter_ValidHTTP(t *testing.T) {
	a := NewAlerter("http://localhost:8080/webhook", nil, nil)
	if a.webhookURL != "http://localhost:8080/webhook" {
		t.Errorf("webhookURL = %q, want http://localhost:8080/webhook", a.webhookURL)
	}
}

func TestNewAlerter_EmptyURL(t *testing.T) {
	a := NewAlerter("", nil, nil)
	if a.webhookURL != "" {
		t.Errorf("webhookURL should be empty, got %q", a.webhookURL)
	}
}

// ---------------------------------------------------------------------------
// CollectHeaders with Cookie header
// ---------------------------------------------------------------------------

func TestCollectHeaders_CookieRedacted(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/me", nil)
	r.Header.Set("Cookie", "session=abc123; refresh=secret_token")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-Request-Id", "req-42")

	headers := CollectHeaders(r)

	if headers["Cookie"] != "[REDACTED]" {
		t.Errorf("Cookie header = %q, want [REDACTED]", headers["Cookie"])
	}
	if headers["Accept"] != "application/json" {
		t.Errorf("Accept header = %q, want application/json", headers["Accept"])
	}
	if headers["X-Request-Id"] != "req-42" {
		t.Errorf("X-Request-Id header = %q, want req-42", headers["X-Request-Id"])
	}
}

func TestCollectHeaders_BothAuthAndCookieRedacted(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/login", nil)
	r.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.xxx.yyy")
	r.Header.Set("Cookie", "refresh=token123")
	r.Header.Set("Content-Type", "application/json")

	headers := CollectHeaders(r)

	if headers["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization = %q, want [REDACTED]", headers["Authorization"])
	}
	if headers["Cookie"] != "[REDACTED]" {
		t.Errorf("Cookie = %q, want [REDACTED]", headers["Cookie"])
	}
	if headers["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", headers["Content-Type"])
	}
}

func TestCollectHeaders_NoSensitiveHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/health", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("User-Agent", "Mozilla/5.0")

	headers := CollectHeaders(r)

	for k, v := range headers {
		if v == "[REDACTED]" {
			t.Errorf("header %q should not be redacted", k)
		}
	}
}

func TestCollectHeaders_MultiValueHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Accept-Encoding", "gzip")
	r.Header.Add("Accept-Encoding", "deflate")

	headers := CollectHeaders(r)

	val := headers["Accept-Encoding"]
	if !strings.Contains(val, "gzip") || !strings.Contains(val, "deflate") {
		t.Errorf("Accept-Encoding = %q, want both gzip and deflate", val)
	}
}

// ---------------------------------------------------------------------------
// Alert without webhook (audit-only path, no webhook URL)
// ---------------------------------------------------------------------------

func TestAlert_NoWebhook_NoPanic(t *testing.T) {
	a := NewAlerter("", []string{"trap@test.com"}, nil)
	a.Alert(context.Background(), Event{
		EventType: "trap_login",
		IP:        "192.168.1.1",
		Email:     "trap@test.com",
		RiskScore: 100,
	})
}

// ---------------------------------------------------------------------------
// Alert with invalid-scheme alerter (webhook URL was sanitized away)
// ---------------------------------------------------------------------------

func TestAlert_SanitizedScheme_NoWebhookSent(t *testing.T) {
	a := NewAlerter("ftp://evil.com/exfil", nil, nil)

	// Should not panic and should not attempt to send to ftp://.
	a.Alert(context.Background(), Event{
		EventType: "probe",
		IP:        "10.0.0.5",
		RiskScore: 10,
	})
}
