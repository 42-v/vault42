package adminapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/tests/mocks"
)

// A template can be stored disabled — an operator staging a new verification mail before
// switching a tenant over to it. `enabled` is a *bool precisely so that "absent" and
// "false" are different: absent means "default it on", false means "the operator explicitly
// turned it off". Collapsing those two would silently publish a draft template to a
// tenant's users.
//
// The request also runs without an admin in context here. That is the shape of a
// mis-wired route (the auth middleware not applied), and the actor lookup must yield an
// empty string rather than dereference nil — the audit record is worth less than the
// gateway staying up.
func TestPutEmailTemplate_DisabledIsStoredAsDisabled(t *testing.T) {
	repo := newFakeTemplateRepo()

	h := &Handler{
		emailTemplates:  repo,
		auditLog:        audit.NewLogger(&mocks.MockAuditRepo{}, 0),
		maxTemplateSize: 1 << 20,
	}

	body := `{"subject":"Verify your email","html_content":"<p>Hello {{.AppName}}</p>","enabled":false}`
	req := httptest.NewRequest(http.MethodPut, "/admin/email-templates/beon3/verification", strings.NewReader(body))
	req.SetPathValue("app", "beon3")
	req.SetPathValue("name", "verification")
	rec := httptest.NewRecorder()

	h.PutEmailTemplate(rec, req) // no admin in context: must not panic

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	got := repo.items[repo.key("beon3", "verification")]
	if got == nil {
		t.Fatal("the template was never stored")
	}
	if got.Enabled {
		t.Error("a template explicitly saved as disabled was stored enabled — a draft would go out to the tenant's users")
	}
}
