package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// The admin-user list must enforce the pagination cap: a request asking for
// more rows than maxListLimit is clamped, so the response can never return an
// unbounded set even when far more rows exist (OWASP API4/M06).
func TestListAdmins_EnforcesPaginationCap(t *testing.T) {
	repo := newFakeAdminRepo()
	for i := 0; i < maxListLimit+50; i++ {
		id := fmt.Sprintf("admin-%03d", i)
		repo.users[id] = &model.AdminUser{ID: id, Username: id, Role: "viewer"}
	}

	h := newTestHandler(repo, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.ListAdmins(rec, httptest.NewRequest(http.MethodGet, "/admin/admins?limit=10000", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp struct {
		Admins []map[string]any `json:"admins"`
		Total  int              `json:"total"`
		Limit  int              `json:"limit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Limit != maxListLimit {
		t.Errorf("limit = %d, want clamped to %d", resp.Limit, maxListLimit)
	}
	if len(resp.Admins) != maxListLimit {
		t.Errorf("returned %d admins, want capped at %d", len(resp.Admins), maxListLimit)
	}
	if resp.Total != maxListLimit+50 {
		t.Errorf("total = %d, want full count %d", resp.Total, maxListLimit+50)
	}
}
