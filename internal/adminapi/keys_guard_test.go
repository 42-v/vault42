package adminapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The key-management endpoints are the only way to rotate or revoke the JWT
// signing keys. When no keystore is wired they must refuse the request outright:
// a handler that fell through would nil-panic on h.keyStore, and a rotate that
// looked like it had succeeded while nothing rotated is worse than an error —
// an operator responding to a suspected key compromise would believe the key had
// been replaced.
func TestKeyEndpoints_RefuseWithoutKeystore(t *testing.T) {
	h := &Handler{} // keyStore deliberately nil

	tests := []struct {
		name string
		call func(w http.ResponseWriter, r *http.Request)
		req  *http.Request
	}{
		{"list", h.ListKeys, httptest.NewRequest(http.MethodGet, "/admin/keys", nil)},
		{"rotate", h.RotateKey, httptest.NewRequest(http.MethodPost, "/admin/keys/rotate", nil)},
		{"revoke", h.RevokeKey, httptest.NewRequest(http.MethodDelete, "/admin/keys/abc", nil)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.call(rec, tc.req)

			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", rec.Code)
			}
			if body := rec.Body.String(); !strings.Contains(body, "keystore_not_configured") {
				t.Errorf("body = %s, want keystore_not_configured", body)
			}
		})
	}
}
