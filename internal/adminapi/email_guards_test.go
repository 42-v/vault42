package adminapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The white-label email endpoints are wired only when a template store is configured. If
// one of them fell through with a nil store it would not return an error — it would
// dereference nil and take the whole admin gateway down with it, which on a
// break-glass surface is the worst possible time for the process to die.
//
// 503 is the right answer here rather than 404: the endpoint exists, the feature is
// simply not configured on this deployment, and an operator needs to be told the
// difference.
func TestEmailTemplateEndpoints_RefuseWithoutAStore(t *testing.T) {
	h := &Handler{} // emailTemplates deliberately nil

	tests := []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		req  *http.Request
	}{
		{"get", h.GetEmailTemplate, httptest.NewRequest(http.MethodGet, "/admin/email-templates/beon3/verify_email", nil)},
		{"put", h.PutEmailTemplate, httptest.NewRequest(http.MethodPut, "/admin/email-templates/beon3/verify_email", strings.NewReader(`{}`))},
		{"delete", h.DeleteEmailTemplate, httptest.NewRequest(http.MethodDelete, "/admin/email-templates/beon3/verify_email", nil)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			tc.call(rec, tc.req) // must not panic

			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", rec.Code)
			}
			if body := rec.Body.String(); !strings.Contains(body, "email_config_unavailable") {
				t.Errorf("body = %s, want email_config_unavailable", body)
			}
		})
	}
}
