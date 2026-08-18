package honeypot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsTrapUser(t *testing.T) {
	a := NewAlerter("", []string{"admin@example.com", "test@trap.com"}, nil)

	tests := []struct {
		input string
		want  bool
	}{
		{"admin@example.com", true},
		{"ADMIN@EXAMPLE.COM", true},
		{"test@trap.com", true},
		{"real@user.com", false},
		{"", false},
		{" admin@example.com ", true},
	}
	for _, tt := range tests {
		if got := a.IsTrapUser(tt.input); got != tt.want {
			t.Errorf("IsTrapUser(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsTrapUserEmpty(t *testing.T) {
	a := NewAlerter("", nil, nil)
	if a.IsTrapUser("anything") {
		t.Error("empty trap list should match nothing")
	}
}

func TestAlertSendsWebhook(t *testing.T) {
	var received Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("webhook method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("webhook content-type should be application/json")
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := NewAlerter(srv.URL, nil, nil)
	a.Alert(context.Background(), Event{
		Timestamp: time.Now(),
		EventType: "trap_login",
		IP:        "1.2.3.4",
		UserAgent: "curl/7.0",
		Email:     "admin@test.com",
		RiskScore: 100,
	})

	if received.EventType != "trap_login" {
		t.Errorf("webhook event_type = %q, want trap_login", received.EventType)
	}
	if received.IP != "1.2.3.4" {
		t.Errorf("webhook IP = %q, want 1.2.3.4", received.IP)
	}
	if received.RiskScore != 100 {
		t.Errorf("webhook risk_score = %d, want 100", received.RiskScore)
	}
}

func TestAlertNoWebhookURL(t *testing.T) {
	// Should not panic with empty webhook URL
	a := NewAlerter("", nil, nil)
	a.Alert(context.Background(), Event{
		EventType: "test",
		IP:        "1.2.3.4",
	})
}

func TestRedactBody(t *testing.T) {
	body := `{"email":"test@test.com","password":"secret123","remember_me":true}`
	redacted := RedactBody(body)
	if strings.Contains(redacted, "secret123") {
		t.Error("password should be redacted")
	}
	if !strings.Contains(redacted, "[REDACTED]") {
		t.Error("should contain [REDACTED] placeholder")
	}
	if !strings.Contains(redacted, "test@test.com") {
		t.Error("email should be preserved")
	}
}

func TestRedactBodyNonJSON(t *testing.T) {
	got := RedactBody("not json")
	if got != "[non-JSON body]" {
		t.Errorf("non-JSON should return placeholder, got %q", got)
	}
}

func TestCollectHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "curl/7.0")
	r.Header.Set("Authorization", "Bearer secret")
	r.Header.Set("X-Custom", "value")

	headers := CollectHeaders(r)
	if headers["Authorization"] != "[REDACTED]" {
		t.Error("Authorization should be redacted")
	}
	if headers["X-Custom"] != "value" {
		t.Errorf("X-Custom = %q, want value", headers["X-Custom"])
	}
}

func TestIsAutomationUA(t *testing.T) {
	tests := []struct {
		ua   string
		want bool
	}{
		{"curl/7.88.1", true},
		{"python-requests/2.28.0", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", false},
		{"Go-http-client/2.0", true},
		{"sqlmap/1.7", true},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsAutomationUA(tt.ua); got != tt.want {
			t.Errorf("IsAutomationUA(%q) = %v, want %v", tt.ua, got, tt.want)
		}
	}
}

func TestGenerateFakeJWT(t *testing.T) {
	token, err := GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("fake JWT should have 3 parts, got %d", len(parts))
	}
	// Each part should be non-empty
	for i, p := range parts {
		if p == "" {
			t.Errorf("part %d is empty", i)
		}
	}
}

func TestGenerateFakeJWTUnique(t *testing.T) {
	t1, err := GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT: %v", err)
	}
	t2, err := GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT: %v", err)
	}
	if t1 == t2 {
		t.Error("consecutive fake JWTs should be unique")
	}
}

func TestGenerateFakeRefresh(t *testing.T) {
	r, err := GenerateFakeRefresh()
	if err != nil {
		t.Fatalf("GenerateFakeRefresh: %v", err)
	}
	if len(r) != 64 {
		t.Errorf("fake refresh token length = %d, want 64 hex chars", len(r))
	}
}

func TestFakeLoginResponse(t *testing.T) {
	resp, err := FakeLoginResponse()
	if err != nil {
		t.Fatalf("FakeLoginResponse: %v", err)
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", resp["token_type"])
	}
	if resp["expires_in"] != 900 {
		t.Errorf("expires_in = %v, want 900", resp["expires_in"])
	}
	at, ok := resp["access_token"].(string)
	if !ok || at == "" {
		t.Error("access_token should be a non-empty string")
	}
}

func TestLoggingMiddleware(t *testing.T) {
	a := NewAlerter("", nil, nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := LoggingMiddleware(a)(inner)
	req := httptest.NewRequest("GET", "/auth/login", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestResponseWriterCapturesStatus(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: w, status: 200}
	rw.WriteHeader(http.StatusNotFound)
	if rw.status != 404 {
		t.Errorf("status = %d, want 404", rw.status)
	}
}
