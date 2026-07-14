package adminapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// App roles are the authorisation vocabulary. The endpoints that manage them are wired
// only when a role store is configured, and with a nil store they must refuse rather than
// dereference it — a nil-panic on the admin gateway takes down the break-glass surface at
// exactly the moment an operator is reaching for it.
//
// 503 says "this deployment has no role store", which is a different and more useful
// answer than a 404 that implies the endpoint does not exist.
func TestRoleEndpoints_RefuseWithoutAStore(t *testing.T) {
	h := &Handler{} // appRoles deliberately nil

	tests := []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		req  *http.Request
	}{
		{"create", h.CreateRole, httptest.NewRequest(http.MethodPost, "/admin/roles", strings.NewReader(`{"name":"editor"}`))},
		{"delete", h.DeleteRole, httptest.NewRequest(http.MethodDelete, "/admin/roles/editor", nil)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			tc.call(rec, adminCtx(tc.req)) // must not panic

			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", rec.Code)
			}
		})
	}
}
