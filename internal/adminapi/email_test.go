package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

// testAuditLogger returns an audit.Logger over an in-memory sink so the
// handlers' `if h.auditLog != nil` branches execute. A long flush interval keeps
// it from touching the (no-op) repo during the test.
func testAuditLogger() *audit.Logger {
	return audit.NewLogger(&mocks.MockAuditRepo{
		InsertFn:      func(context.Context, *model.AuditEntry) error { return nil },
		InsertBatchFn: func(context.Context, []*model.AuditEntry) error { return nil },
	}, time.Hour)
}

// fakeBrandingRepo is an in-memory EmailBrandingRepository. A non-nil errOn
// forces every method to fail, exercising the handlers' 500 paths.
type fakeBrandingRepo struct {
	items map[string]*model.EmailBranding
	err   error
}

func newFakeBrandingRepo() *fakeBrandingRepo {
	return &fakeBrandingRepo{items: map[string]*model.EmailBranding{}}
}

func (f *fakeBrandingRepo) Get(_ context.Context, app string) (*model.EmailBranding, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.items[app], nil
}

func (f *fakeBrandingRepo) List(_ context.Context) ([]*model.EmailBranding, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]*model.EmailBranding, 0, len(f.items))
	for _, b := range f.items {
		out = append(out, b)
	}
	return out, nil
}

func (f *fakeBrandingRepo) Upsert(_ context.Context, b *model.EmailBranding) error {
	if f.err != nil {
		return f.err
	}
	f.items[b.App] = b
	return nil
}

func (f *fakeBrandingRepo) Delete(_ context.Context, app string) error {
	if f.err != nil {
		return f.err
	}
	delete(f.items, app)
	return nil
}

// fakeTemplateRepo is an in-memory EmailTemplateRepository keyed by "app/name".
type fakeTemplateRepo struct {
	items map[string]*model.EmailTemplate
	err   error
}

func newFakeTemplateRepo() *fakeTemplateRepo {
	return &fakeTemplateRepo{items: map[string]*model.EmailTemplate{}}
}

func (f *fakeTemplateRepo) key(app, name string) string { return app + "/" + name }

func (f *fakeTemplateRepo) Get(_ context.Context, app, name string) (*model.EmailTemplate, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.items[f.key(app, name)], nil
}

func (f *fakeTemplateRepo) ListByApp(_ context.Context, app string) ([]*model.EmailTemplate, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []*model.EmailTemplate
	for _, t := range f.items {
		if t.App == app {
			out = append(out, t)
		}
	}
	return out, nil
}

func (f *fakeTemplateRepo) List(_ context.Context) ([]*model.EmailTemplate, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]*model.EmailTemplate, 0, len(f.items))
	for _, t := range f.items {
		out = append(out, t)
	}
	return out, nil
}

func (f *fakeTemplateRepo) Upsert(_ context.Context, t *model.EmailTemplate) error {
	if f.err != nil {
		return f.err
	}
	f.items[f.key(t.App, t.TemplateName)] = t
	return nil
}

func (f *fakeTemplateRepo) Delete(_ context.Context, app, name string) error {
	if f.err != nil {
		return f.err
	}
	delete(f.items, f.key(app, name))
	return nil
}

var (
	_ repository.EmailBrandingRepository = (*fakeBrandingRepo)(nil)
	_ repository.EmailTemplateRepository = (*fakeTemplateRepo)(nil)
)

// emailHandler builds a Handler with the email repos wired (or left nil to
// exercise the 503 unavailable path). An authenticated admin is put in every
// request context so the audit actor is populated.
func emailHandler(branding repository.EmailBrandingRepository, templates repository.EmailTemplateRepository) *Handler {
	h := &Handler{}
	h.SetEmailRepos(branding, templates, 4096)
	return h
}

// adminReq builds a request carrying an authenticated admin in context.
func adminReq(method, target, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	ctx := context.WithValue(r.Context(), adminUserKey, &model.AdminUser{ID: "adm-1", Username: "root"})
	return r.WithContext(ctx)
}

// withPathValue attaches Go 1.22 ServeMux path values, which the handlers read
// via r.PathValue but httptest.NewRequest does not populate.
func withPathValue(r *http.Request, kv map[string]string) *http.Request {
	for k, v := range kv {
		r.SetPathValue(k, v)
	}
	return r
}

// ===================== Branding =====================

func TestEmailBranding_Unavailable(t *testing.T) {
	h := &Handler{} // no email repos wired
	for _, tc := range []struct {
		name string
		call func(w http.ResponseWriter)
	}{
		{"list", func(w http.ResponseWriter) {
			h.ListEmailBranding(w, adminReq(http.MethodGet, "/admin/email-branding", ""))
		}},
		{"get", func(w http.ResponseWriter) {
			h.GetEmailBranding(w, withPathValue(adminReq(http.MethodGet, "/x", ""), map[string]string{"app": "acme"}))
		}},
		{"put", func(w http.ResponseWriter) {
			h.PutEmailBranding(w, withPathValue(adminReq(http.MethodPut, "/x", "{}"), map[string]string{"app": "acme"}))
		}},
		{"delete", func(w http.ResponseWriter) {
			h.DeleteEmailBranding(w, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"app": "acme"}))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.call(rec)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("nil repo should be 503, got %d", rec.Code)
			}
		})
	}
}

func TestListEmailBranding(t *testing.T) {
	repo := newFakeBrandingRepo()
	repo.items["acme"] = &model.EmailBranding{App: "acme", AppName: "Acme"}
	h := emailHandler(repo, nil)

	rec := httptest.NewRecorder()
	h.ListEmailBranding(rec, adminReq(http.MethodGet, "/admin/email-branding", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "acme") {
		t.Fatalf("branding missing: %s", rec.Body.String())
	}

	repo.err = context.DeadlineExceeded
	rec = httptest.NewRecorder()
	h.ListEmailBranding(rec, adminReq(http.MethodGet, "/admin/email-branding", ""))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("repo error should be 500, got %d", rec.Code)
	}
}

func TestGetEmailBranding(t *testing.T) {
	repo := newFakeBrandingRepo()
	repo.items["acme"] = &model.EmailBranding{App: "acme", AppName: "Acme"}
	h := emailHandler(repo, nil)

	tests := []struct {
		name string
		app  string
		want int
	}{
		{"found", "acme", http.StatusOK},
		{"absent", "ghost", http.StatusNotFound},
		{"invalid app", "Bad App!", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.GetEmailBranding(rec, withPathValue(adminReq(http.MethodGet, "/x", ""), map[string]string{"app": tt.app}))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}

	repo.err = context.DeadlineExceeded
	rec := httptest.NewRecorder()
	h.GetEmailBranding(rec, withPathValue(adminReq(http.MethodGet, "/x", ""), map[string]string{"app": "acme"}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("repo error should be 500, got %d", rec.Code)
	}
}

func TestPutEmailBranding(t *testing.T) {
	tests := []struct {
		name string
		app  string
		body string
		want int
	}{
		{"valid full", "acme", `{"app_name":"Acme","logo_url":"https://cdn.acme.test/logo.png","primary_color":"#00FF42","from_name":"Acme","from_address":"noreply@acme.test"}`, http.StatusOK},
		{"valid minimal", "acme", `{}`, http.StatusOK},
		{"invalid app", "Bad!", `{}`, http.StatusBadRequest},
		{"bad json", "acme", `{`, http.StatusBadRequest},
		{"app name too long", "acme", `{"app_name":"` + strings.Repeat("x", 256) + `"}`, http.StatusBadRequest},
		{"bad logo url", "acme", `{"logo_url":"http://insecure.test/l.png"}`, http.StatusBadRequest},
		{"loopback logo url", "acme", `{"logo_url":"https://localhost/l.png"}`, http.StatusBadRequest},
		{"bad color", "acme", `{"primary_color":"green"}`, http.StatusBadRequest},
		{"bad from address", "acme", `{"from_address":"not-an-email"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := emailHandler(newFakeBrandingRepo(), nil)
			rec := httptest.NewRecorder()
			h.PutEmailBranding(rec, withPathValue(adminReq(http.MethodPut, "/x", tt.body), map[string]string{"app": tt.app}))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestPutEmailBranding_CanonicalizesFromAddress(t *testing.T) {
	repo := newFakeBrandingRepo()
	h := emailHandler(repo, nil)
	rec := httptest.NewRecorder()
	// A display-name form must be stored as the bare address so the send-path
	// allowlist sees the same value the parser does.
	h.PutEmailBranding(rec, withPathValue(adminReq(http.MethodPut, "/x", `{"from_address":"Acme Support <noreply@acme.test>"}`), map[string]string{"app": "acme"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := repo.items["acme"].FromAddress; got != "noreply@acme.test" {
		t.Fatalf("from_address stored as %q, want canonical bare address", got)
	}
	if repo.items["acme"].UpdatedBy != "root" {
		t.Fatalf("UpdatedBy = %q, want the authenticated admin", repo.items["acme"].UpdatedBy)
	}
}

func TestEmailBranding_AuditLogged(t *testing.T) {
	// With a logger wired, Put and Delete take their audit branch.
	repo := newFakeBrandingRepo()
	h := emailHandler(repo, nil)
	h.auditLog = testAuditLogger()

	rec := httptest.NewRecorder()
	h.PutEmailBranding(rec, withPathValue(adminReq(http.MethodPut, "/x", `{"app_name":"Acme"}`), map[string]string{"app": "acme"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("put status = %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.DeleteEmailBranding(rec, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"app": "acme"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d", rec.Code)
	}
}

func TestEmailTemplate_AuditLogged(t *testing.T) {
	repo := newFakeTemplateRepo()
	h := emailHandler(nil, repo)
	h.auditLog = testAuditLogger()

	rec := httptest.NewRecorder()
	h.PutEmailTemplate(rec, withPathValue(adminReq(http.MethodPut, "/x", `{"subject":"Verify","html_content":"`+validHTML+`"}`), map[string]string{"app": "acme", "name": "verification"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("put status = %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.DeleteEmailTemplate(rec, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"app": "acme", "name": "verification"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d", rec.Code)
	}
}

func TestPutEmailBranding_RepoError(t *testing.T) {
	repo := newFakeBrandingRepo()
	repo.err = context.DeadlineExceeded
	h := emailHandler(repo, nil)
	rec := httptest.NewRecorder()
	h.PutEmailBranding(rec, withPathValue(adminReq(http.MethodPut, "/x", `{}`), map[string]string{"app": "acme"}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("repo error should be 500, got %d", rec.Code)
	}
}

func TestDeleteEmailBranding(t *testing.T) {
	repo := newFakeBrandingRepo()
	repo.items["acme"] = &model.EmailBranding{App: "acme"}
	h := emailHandler(repo, nil)

	rec := httptest.NewRecorder()
	h.DeleteEmailBranding(rec, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"app": "acme"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if _, ok := repo.items["acme"]; ok {
		t.Fatal("branding not deleted")
	}

	rec = httptest.NewRecorder()
	h.DeleteEmailBranding(rec, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"app": "Bad!"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid app should be 400, got %d", rec.Code)
	}

	repo.err = context.DeadlineExceeded
	rec = httptest.NewRecorder()
	h.DeleteEmailBranding(rec, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"app": "acme"}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("repo error should be 500, got %d", rec.Code)
	}
}

// ===================== Templates =====================

const validHTML = "<p>Hello {{.AppName}}, your code is {{.Code}}</p>"

func TestEmailTemplates_Unavailable(t *testing.T) {
	h := &Handler{}
	rec := httptest.NewRecorder()
	h.ListEmailTemplates(rec, adminReq(http.MethodGet, "/admin/email-templates", ""))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil repo should be 503, got %d", rec.Code)
	}
}

func TestListEmailTemplates(t *testing.T) {
	repo := newFakeTemplateRepo()
	repo.items["acme/verification"] = &model.EmailTemplate{App: "acme", TemplateName: "verification", Subject: "Hi"}
	h := emailHandler(nil, repo)

	t.Run("all", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ListEmailTemplates(rec, adminReq(http.MethodGet, "/admin/email-templates", ""))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "verification") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("by app", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ListEmailTemplates(rec, adminReq(http.MethodGet, "/admin/email-templates?app=acme", ""))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "verification") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("invalid app filter", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ListEmailTemplates(rec, adminReq(http.MethodGet, "/admin/email-templates?app=Bad!", ""))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("repo error", func(t *testing.T) {
		repo.err = context.DeadlineExceeded
		defer func() { repo.err = nil }()
		rec := httptest.NewRecorder()
		h.ListEmailTemplates(rec, adminReq(http.MethodGet, "/admin/email-templates", ""))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})
}

func TestGetEmailTemplate(t *testing.T) {
	repo := newFakeTemplateRepo()
	repo.items["acme/verification"] = &model.EmailTemplate{App: "acme", TemplateName: "verification", Subject: "Hi"}
	h := emailHandler(nil, repo)

	tests := []struct {
		name, app, tmpl string
		want            int
	}{
		{"found", "acme", "verification", http.StatusOK},
		{"absent", "acme", "password_reset", http.StatusNotFound},
		{"invalid app", "Bad!", "verification", http.StatusBadRequest},
		{"invalid name", "acme", "not_a_template", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.GetEmailTemplate(rec, withPathValue(adminReq(http.MethodGet, "/x", ""), map[string]string{"app": tt.app, "name": tt.tmpl}))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestEmailTemplate_RepoErrors(t *testing.T) {
	repo := newFakeTemplateRepo()
	repo.items["acme/verification"] = &model.EmailTemplate{App: "acme", TemplateName: "verification"}
	h := emailHandler(nil, repo)
	repo.err = context.DeadlineExceeded

	for _, tc := range []struct {
		name string
		call func(w http.ResponseWriter)
	}{
		{"get", func(w http.ResponseWriter) {
			h.GetEmailTemplate(w, withPathValue(adminReq(http.MethodGet, "/x", ""), map[string]string{"app": "acme", "name": "verification"}))
		}},
		{"put", func(w http.ResponseWriter) {
			h.PutEmailTemplate(w, withPathValue(adminReq(http.MethodPut, "/x", `{"subject":"Verify","html_content":"`+validHTML+`"}`), map[string]string{"app": "acme", "name": "verification"}))
		}},
		{"delete", func(w http.ResponseWriter) {
			h.DeleteEmailTemplate(w, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"app": "acme", "name": "verification"}))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.call(rec)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("repo error should be 500, got %d", rec.Code)
			}
		})
	}
}

func TestPutEmailTemplate(t *testing.T) {
	tests := []struct {
		name, app, tmpl, body string
		maxSize               int
		want                  int
	}{
		{"valid", "acme", "verification", `{"subject":"Verify","html_content":"` + validHTML + `"}`, 4096, http.StatusOK},
		{"invalid app", "Bad!", "verification", `{}`, 4096, http.StatusBadRequest},
		{"invalid name", "acme", "nope", `{}`, 4096, http.StatusBadRequest},
		{"bad json", "acme", "verification", `{`, 4096, http.StatusBadRequest},
		{"subject too long", "acme", "verification", `{"subject":"` + strings.Repeat("s", 256) + `","html_content":"` + validHTML + `"}`, 4096, http.StatusBadRequest},
		{"template too large", "acme", "verification", `{"subject":"Verify","html_content":"` + validHTML + `"}`, 5, http.StatusBadRequest},
		{"forbidden content", "acme", "verification", `{"subject":"Verify","html_content":"<script>alert(1)</script>"}`, 4096, http.StatusBadRequest},
		{"empty content", "acme", "verification", `{"subject":"Verify","html_content":""}`, 4096, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newFakeTemplateRepo()
			h := &Handler{}
			h.SetEmailRepos(nil, repo, tt.maxSize)
			rec := httptest.NewRecorder()
			h.PutEmailTemplate(rec, withPathValue(adminReq(http.MethodPut, "/x", tt.body), map[string]string{"app": tt.app, "name": tt.tmpl}))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestPutEmailTemplate_DefaultsEnabledAndRecordsActor(t *testing.T) {
	repo := newFakeTemplateRepo()
	h := emailHandler(nil, repo)
	rec := httptest.NewRecorder()
	h.PutEmailTemplate(rec, withPathValue(adminReq(http.MethodPut, "/x", `{"subject":"Verify","html_content":"`+validHTML+`"}`), map[string]string{"app": "acme", "name": "verification"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	stored := repo.items["acme/verification"]
	if stored == nil || !stored.Enabled {
		t.Fatal("template should default to enabled")
	}
	if stored.UpdatedBy != "root" || stored.CreatedBy != "root" {
		t.Fatalf("actor not recorded: created_by=%q updated_by=%q", stored.CreatedBy, stored.UpdatedBy)
	}
	if stored.ID == "" {
		t.Fatal("template ID not assigned")
	}
}

func TestDeleteEmailTemplate(t *testing.T) {
	repo := newFakeTemplateRepo()
	repo.items["acme/verification"] = &model.EmailTemplate{App: "acme", TemplateName: "verification"}
	h := emailHandler(nil, repo)

	rec := httptest.NewRecorder()
	h.DeleteEmailTemplate(rec, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"app": "acme", "name": "verification"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if _, ok := repo.items["acme/verification"]; ok {
		t.Fatal("template not deleted")
	}

	rec = httptest.NewRecorder()
	h.DeleteEmailTemplate(rec, withPathValue(adminReq(http.MethodDelete, "/x", ""), map[string]string{"app": "Bad!", "name": "verification"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid request should be 400, got %d", rec.Code)
	}
}

func TestPreviewEmailTemplate(t *testing.T) {
	h := &Handler{} // preview needs no repos
	t.Run("valid", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.PreviewEmailTemplate(rec, adminReq(http.MethodPost, "/admin/email-templates/preview", `{"subject":"Hi from {{.AppName}}","html_content":"`+validHTML+`"}`))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"valid":true`) {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("invalid content returns 200 valid:false", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.PreviewEmailTemplate(rec, adminReq(http.MethodPost, "/x", `{"subject":"Hi","html_content":"<script>x</script>"}`))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"valid":false`) {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("bad json", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.PreviewEmailTemplate(rec, adminReq(http.MethodPost, "/x", `{`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}
