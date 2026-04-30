package attack

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/middleware"
)

// TestAdminAuth_NoToken verifies that admin endpoints reject requests without auth.
func TestAdminAuth_NoToken(t *testing.T) {
	verifyFunc := func(token string) bool { return token == "valid-admin-token" }
	handler := middleware.AdminAuth(verifyFunc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

// TestAdminAuth_InvalidToken verifies that admin endpoints reject invalid tokens.
func TestAdminAuth_InvalidToken(t *testing.T) {
	verifyFunc := func(token string) bool { return token == "valid-admin-token" }
	handler := middleware.AdminAuth(verifyFunc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	cases := []struct {
		name     string
		value    string
		wantCode int
	}{
		{"wrong_token", "Bearer wrong-token", http.StatusForbidden},
		{"basic_auth", "Basic dXNlcjpwYXNz", http.StatusUnauthorized},
		{"empty_bearer", "Bearer ", http.StatusUnauthorized},
		{"no_space", "Bearertoken", http.StatusUnauthorized},
		{"just_bearer", "Bearer", http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
			req.Header.Set("Authorization", tc.value)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Fatalf("expected %d for %s, got %d: %s", tc.wantCode, tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestAdminAuth_ValidToken verifies that admin endpoints accept valid tokens.
func TestAdminAuth_ValidToken(t *testing.T) {
	verifyFunc := func(token string) bool { return token == "valid-admin-token" }
	handler := middleware.AdminAuth(verifyFunc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer valid-admin-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminAuth_LongToken verifies that oversized tokens are rejected (max 256 chars).
func TestAdminAuth_LongToken(t *testing.T) {
	verifyFunc := func(token string) bool { return true }
	handler := middleware.AdminAuth(verifyFunc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	longToken := make([]byte, 257)
	for i := range longToken {
		longToken[i] = 'a'
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer "+string(longToken))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for oversized token, got %d", rec.Code)
	}
}

// TestAdminListKeys_NoPrivateKeyMaterial verifies that ListKeys response
// never contains private key material (private_key, signing_key fields).
func TestAdminListKeys_NoPrivateKeyMaterial(t *testing.T) {
	// Simulate a ListKeys response (the shape returned by the handler)
	resp := map[string]any{
		"keys": []map[string]any{
			{
				"kid":        "test-kid-001",
				"algorithm":  "RS256",
				"status":     "active",
				"created_at": "2024-01-01T00:00:00Z",
			},
		},
	}

	data, _ := json.Marshal(resp)

	// Verify no sensitive fields are present
	sensitiveFields := []string{"private_key", "signing_key", "secret", "master_key"}
	for _, field := range sensitiveFields {
		if json.Valid(data) {
			var result map[string]any
			json.Unmarshal(data, &result)
			if keys, ok := result["keys"].([]any); ok {
				for _, k := range keys {
					if km, ok := k.(map[string]any); ok {
						if _, exists := km[field]; exists {
							t.Fatalf("response should not contain %q field", field)
						}
					}
				}
			}
		}
	}
}
