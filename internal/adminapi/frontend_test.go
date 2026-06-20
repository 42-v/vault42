package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// Every page handler shares the same render path; one table covers them all.
func TestFrontendPagesRender(t *testing.T) {
	h := NewFrontendHandler()

	cases := []struct {
		name    string
		handler http.HandlerFunc
		title   string
	}{
		{"login", h.LoginPage, "Admin Login"},
		{"dashboard", h.Dashboard, "Dashboard"},
		{"users", h.UsersPage, "Users"},
		{"keys", h.KeysPage, "Signing Keys"},
		{"sessions", h.SessionsPage, "Sessions"},
		{"audit", h.AuditPage, "Audit Log"},
		{"clients", h.ClientsPage, "Service Clients"},
		{"admins", h.AdminsPage, "Admin Accounts"},
		{"config", h.ConfigPage, "Configuration"},
		{"user_detail", h.UserDetailPage, "User Detail"},
		{"totp_setup", h.TOTPSetupPage, "TOTP Setup"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/admin/"+tc.name, nil)
			tc.handler(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Fatalf("content-type = %q, want text/html prefix", ct)
			}
			if body := w.Body.String(); !strings.Contains(body, tc.title) {
				t.Fatalf("body missing title %q", tc.title)
			}
		})
	}
}

func TestServeStaticEmptyPath404s(t *testing.T) {
	h := NewFrontendHandler()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/static/", nil)
	h.ServeStatic(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestRender_UnknownPage(t *testing.T) {
	h := NewFrontendHandler()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	// call unexported render with bad page
	h.render(w, req, "no-such-page", pageData{Title: "x"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("unknown page status=%d want 500", w.Code)
	}
}

func TestRender_WithAdminInContext(t *testing.T) {
	h := NewFrontendHandler()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	admin := &model.AdminUser{ID: "a1", Username: "root", Role: "super_admin", TOTPVerified: true}
	ctx := WithAdmin(context.Background(), admin)
	req = req.WithContext(ctx)
	// login page uses render
	h.LoginPage(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "root") {
		t.Error("expected admin username in rendered page")
	}
}

func TestServeStaticMissingFile404s(t *testing.T) {
	h := NewFrontendHandler()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/static/does-not-exist.css", nil)
	h.ServeStatic(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestServeStaticCSSSetsContentType(t *testing.T) {
	h := NewFrontendHandler()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/static/style.css", nil)
	h.ServeStatic(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("Content-Type = %q, want text/css prefix", ct)
	}
}

func TestServeStaticJSSetsContentType(t *testing.T) {
	h := NewFrontendHandler()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/static/admin.js", nil)
	h.ServeStatic(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/javascript") {
		t.Fatalf("Content-Type = %q, want application/javascript prefix", ct)
	}
}

func TestRenderWithAdminInContext(t *testing.T) {
	h := NewFrontendHandler()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/dashboard", nil)
	ctx := WithAdmin(req.Context(), &model.AdminUser{
		ID: "00000000-0000-0000-0000-000000000099", Username: "v", Role: "super_admin", TOTPVerified: true,
	})
	h.Dashboard(w, req.WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}
