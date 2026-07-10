package adminapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
)

func TestLocalOnly_RejectsNonLoopback(t *testing.T) {
	handler := LocalOnly(false, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		remoteAddr string
		wantCode   int
	}{
		{"loopback v4", "127.0.0.1:12345", http.StatusOK},
		{"loopback v6", "[::1]:12345", http.StatusOK},
		{"external v4", "10.0.0.1:12345", http.StatusForbidden},
		{"external v6", "[2001:db8::1]:12345", http.StatusForbidden},
		{"private rfc1918", "192.168.1.1:12345", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/admin/status", nil)
			r.RemoteAddr = tt.remoteAddr
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tt.wantCode {
				t.Errorf("RemoteAddr=%s: got %d, want %d", tt.remoteAddr, w.Code, tt.wantCode)
			}
		})
	}
}

func TestRejectProxyHeaders_BlocksRelayedRequests(t *testing.T) {
	handler := RejectProxyHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, header := range proxyHeaders {
		t.Run(header, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/admin/status", nil)
			r.RemoteAddr = "127.0.0.1:12345"
			r.Header.Set(header, "1.2.3.4")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Errorf("header %s: got %d, want 403", header, w.Code)
			}
		})
	}

	// No proxy headers should pass
	t.Run("no-proxy-headers", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/admin/status", nil)
		r.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("no proxy headers: got %d, want 200", w.Code)
		}
	})
}

func TestSecurityHeaders_AreSet(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/admin/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store, no-cache, must-revalidate, private",
	}

	for k, v := range expected {
		if got := w.Header().Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
}

func TestRecovery_CatchesPanics(t *testing.T) {
	handler := Recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	r := httptest.NewRequest("GET", "/admin/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("panic handler: got %d, want 500", w.Code)
	}
}

func TestRecovery_DoesNotCatchKillswitch(t *testing.T) {
	handler := Recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(killswitchPrefix + "test killswitch")
	}))

	r := httptest.NewRequest("GET", "/admin/status", nil)
	w := httptest.NewRecorder()

	defer func() {
		if err := recover(); err == nil {
			t.Error("killswitch panic should not be caught by Recovery")
		}
	}()
	handler.ServeHTTP(w, r)
}

func TestLocalOnly_Killswitch_PanicsOnNonLoopback(t *testing.T) {
	handler := LocalOnly(true, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/admin/status", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()

	defer func() {
		if err := recover(); err == nil {
			t.Error("killswitch should panic on non-loopback request")
		}
	}()
	handler.ServeHTTP(w, r)
}

func TestMaxBody_LimitsRequestSize(t *testing.T) {
	handler := MaxBody(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read entire body — if oversized, MaxBytesReader returns an error
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Small body should pass
	r := httptest.NewRequest("POST", "/admin/auth/login", strings.NewReader("small"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("small body: got %d, want 200", w.Code)
	}

	// Oversized body should be limited by MaxBytesReader
	r = httptest.NewRequest("POST", "/admin/auth/login", strings.NewReader(strings.Repeat("x", 100)))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("large body: got %d, want 413", w.Code)
	}
}

func TestRBACCheck_RejectsMissingAdmin(t *testing.T) {
	handler := RBACCheck("keys:list")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/admin/keys", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("no admin in context: got %d, want 401", w.Code)
	}
}

func TestIsTOTPSetupPath(t *testing.T) {
	if !isTOTPSetupPath("/admin/admins/me/totp/setup") {
		t.Error("TOTP setup path should be recognized")
	}
	if !isTOTPSetupPath("/admin/admins/me/totp/verify") {
		t.Error("TOTP verify path should be recognized")
	}
	if isTOTPSetupPath("/admin/keys") {
		t.Error("/admin/keys should not be a TOTP setup path")
	}
}

func TestSecurityHeaders_HSTS(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/admin/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("HSTS header missing")
	}
	if !strings.Contains(hsts, "max-age=") {
		t.Errorf("HSTS missing max-age: %s", hsts)
	}
}

func TestSecurityHeaders_CSP_NoUnsafeInline(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/admin/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	csp := w.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP should not contain unsafe-inline: %s", csp)
	}
	if !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("CSP should restrict form-action: %s", csp)
	}
}

func TestRequestID_GeneratesUUID(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/admin/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	id := w.Header().Get("X-Request-ID")
	if id == "" {
		t.Error("X-Request-ID header missing")
	}
	if len(id) < 36 {
		t.Errorf("X-Request-ID too short (not UUID): %s", id)
	}
}

func TestRequestID_IgnoresClientHeader(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Client header should be stripped
		if r.Header.Get("X-Request-ID") != "" {
			t.Error("client X-Request-ID was not stripped")
		}
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/admin/status", nil)
	r.Header.Set("X-Request-ID", "attacker-injected\r\nEvil-Header: evil")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	id := w.Header().Get("X-Request-ID")
	if id == "attacker-injected\r\nEvil-Header: evil" {
		t.Error("X-Request-ID should not echo client value")
	}
}

func TestLoginRateLimit_BlocksExcessiveAttempts(t *testing.T) {
	rl := NewLoginRateLimit(3, time.Minute)
	handler := rl.Wrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First 3 should pass
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("POST", "/admin/auth/login", nil)
		r.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("attempt %d: got %d, want 200", i+1, w.Code)
		}
	}

	// 4th should be rate limited
	r := httptest.NewRequest("POST", "/admin/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("excess attempt: got %d, want 429", w.Code)
	}
}

func TestLoginRateLimit_Table(t *testing.T) {
	tests := []struct {
		name     string
		max      int
		window   time.Duration
		attempts int
		wantCode int
	}{
		{"allow under", 2, time.Minute, 2, http.StatusOK},
		{"block over", 1, time.Minute, 2, http.StatusTooManyRequests},
		{"zero max blocks second", 0, time.Minute, 1, http.StatusTooManyRequests},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewLoginRateLimit(tt.max, tt.window)
			h := rl.Wrap(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
			for i := 0; i < tt.attempts; i++ {
				r := httptest.NewRequest("POST", "/login", nil)
				r.RemoteAddr = "10.0.0.1:1"
				w := httptest.NewRecorder()
				h(w, r)
				if i == tt.attempts-1 {
					if w.Code != tt.wantCode {
						t.Errorf("final code=%d want=%d", w.Code, tt.wantCode)
					}
				}
			}
		})
	}
}

func TestConfigKeyPattern(t *testing.T) {
	valid := []string{"session.ttl", "max_retries", "debugMode", "a"}
	invalid := []string{"", "../etc/passwd", "key;DROP TABLE", "1starts_with_num", strings.Repeat("x", 65)}

	for _, k := range valid {
		if !configKeyPattern.MatchString(k) {
			t.Errorf("config key %q should be valid", k)
		}
	}
	for _, k := range invalid {
		if configKeyPattern.MatchString(k) {
			t.Errorf("config key %q should be invalid", k)
		}
	}
}

func TestGetSession(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want *model.AdminSession
	}{
		{"background", context.Background(), nil},
		{"no key", context.WithValue(context.Background(), ctxKey("other"), "x"), nil},
		{"wrong type", context.WithValue(context.Background(), adminSessionKey, "notsession"), nil},
		{"valid", func() context.Context {
			s := &model.AdminSession{ID: "sess-1", AdminID: "adm-1"}
			return context.WithValue(context.Background(), adminSessionKey, s)
		}(), &model.AdminSession{ID: "sess-1", AdminID: "adm-1"}},
		{"nil session stored", context.WithValue(context.Background(), adminSessionKey, (*model.AdminSession)(nil)), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetSession(tt.ctx)
			if (got == nil) != (tt.want == nil) || (got != nil && got.ID != tt.want.ID) {
				t.Errorf("GetSession() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestGetAdmin(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want *model.AdminUser
	}{
		{"background", context.Background(), nil},
		{"no key", context.WithValue(context.Background(), ctxKey("other"), "x"), nil},
		{"wrong type", context.WithValue(context.Background(), adminUserKey, 42), nil},
		{"valid", func() context.Context {
			a := &model.AdminUser{ID: "adm-1", Username: "root"}
			return context.WithValue(context.Background(), adminUserKey, a)
		}(), &model.AdminUser{ID: "adm-1", Username: "root"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetAdmin(tt.ctx)
			if (got == nil) != (tt.want == nil) || (got != nil && got.ID != tt.want.ID) {
				t.Errorf("GetAdmin() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestWithSession_Roundtrip(t *testing.T) {
	s := &model.AdminSession{ID: "s1"}
	ctx := WithSession(context.Background(), s)
	got := GetSession(ctx)
	if got == nil || got.ID != "s1" {
		t.Errorf("WithSession roundtrip got %+v", got)
	}
}

func TestWithAdmin_Roundtrip(t *testing.T) {
	a := &model.AdminUser{ID: "a1", Username: "u"}
	ctx := WithAdmin(context.Background(), a)
	got := GetAdmin(ctx)
	if got == nil || got.ID != "a1" {
		t.Errorf("WithAdmin roundtrip got %+v", got)
	}
}
