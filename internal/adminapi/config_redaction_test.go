package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/tests/mocks"
)

// GET /admin/config is gated by ConfigRead, a viewer-tier permission. The
// auth.admin_config table it lists also holds admin_token_hash, the Argon2id
// hash of the CLI admin token (InitAdminToken/rotate-admin-token write it
// there). Returning the whole table hands a read-only admin offline-crackable
// credential material for a privileged CLI credential, the same class of secret
// the client and admin projections deliberately never expose. The credential
// key must be stripped from the response; ordinary runtime config survives.
func TestGetConfig_RedactsAdminTokenHash(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	h.adminConfig = &mocks.MockAdminConfigRepo{
		ListFn: func(context.Context) (map[string]string, error) {
			return map[string]string{
				"admin_token_hash": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g",
				"login_banner":     "Authorized use only",
			}, nil
		},
	}

	rec := httptest.NewRecorder()
	h.GetConfig(rec, withActor(httptest.NewRequest(http.MethodGet, "/admin/config", nil)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body struct {
		Entries map[string]string `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if _, leaked := body.Entries["admin_token_hash"]; leaked {
		t.Errorf("admin_token_hash returned to a config reader: %s, a viewer must not receive the CLI admin token hash", rec.Body.String())
	}
	if body.Entries["login_banner"] != "Authorized use only" {
		t.Errorf("non-sensitive config was dropped: entries = %v", body.Entries)
	}
}
