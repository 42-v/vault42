package adminapi

import (
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"path"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// FrontendHandler serves the server-rendered HTML admin dashboard.
type FrontendHandler struct {
	templates map[string]*template.Template
}

// pageData is the data passed to all HTML templates.
type pageData struct {
	Title   string
	Page    string
	Admin   *adminInfo
	Content any
}

// NewFrontendHandler creates a new frontend handler with parsed templates.
// Each page template is parsed independently with the layout to avoid
// {{define "page-content"}} collisions between pages.
func NewFrontendHandler() *FrontendHandler {
	base, err := template.ParseFS(templateFS, "templates/layout.html")
	if err != nil {
		log.Fatalf("admin-gateway: failed to parse layout template: %v", err)
	}

	pages := []string{
		"login", "dashboard", "users", "keys", "sessions",
		"audit", "clients", "admins", "config", "user_detail", "totp_setup",
	}

	templates := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		t, err := template.Must(base.Clone()).ParseFS(templateFS, "templates/"+page+".html")
		if err != nil {
			log.Fatalf("admin-gateway: failed to parse template %s: %v", page, err)
		}
		templates[page] = t
	}

	return &FrontendHandler{templates: templates}
}

func (f *FrontendHandler) render(w http.ResponseWriter, r *http.Request, page string, data pageData) {
	admin := GetAdmin(r.Context())
	if admin != nil {
		data.Admin = &adminInfo{
			ID:       admin.ID,
			Username: admin.Username,
			Role:     admin.Role,
			TOTP:     admin.TOTPVerified,
		}
	}
	data.Page = page

	tmpl, ok := f.templates[page]
	if !ok {
		log.Printf("admin-gateway: unknown page: %s", page)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, page+".html", data); err != nil {
		log.Printf("admin-gateway: template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// LoginPage serves the login page.
func (f *FrontendHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	f.render(w, r, "login", pageData{Title: "Admin Login"})
}

// Dashboard serves the main dashboard page.
func (f *FrontendHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	f.render(w, r, "dashboard", pageData{Title: "Dashboard"})
}

// UsersPage serves the users management page.
func (f *FrontendHandler) UsersPage(w http.ResponseWriter, r *http.Request) {
	f.render(w, r, "users", pageData{Title: "Users"})
}

// KeysPage serves the key management page.
func (f *FrontendHandler) KeysPage(w http.ResponseWriter, r *http.Request) {
	f.render(w, r, "keys", pageData{Title: "Signing Keys"})
}

// SessionsPage serves the session management page.
func (f *FrontendHandler) SessionsPage(w http.ResponseWriter, r *http.Request) {
	f.render(w, r, "sessions", pageData{Title: "Sessions"})
}

// AuditPage serves the audit log page.
func (f *FrontendHandler) AuditPage(w http.ResponseWriter, r *http.Request) {
	f.render(w, r, "audit", pageData{Title: "Audit Log"})
}

// ClientsPage serves the service clients page.
func (f *FrontendHandler) ClientsPage(w http.ResponseWriter, r *http.Request) {
	f.render(w, r, "clients", pageData{Title: "Service Clients"})
}

// AdminsPage serves the admin accounts page.
func (f *FrontendHandler) AdminsPage(w http.ResponseWriter, r *http.Request) {
	f.render(w, r, "admins", pageData{Title: "Admin Accounts"})
}

// ConfigPage serves the config management page.
func (f *FrontendHandler) ConfigPage(w http.ResponseWriter, r *http.Request) {
	f.render(w, r, "config", pageData{Title: "Configuration"})
}

// UserDetailPage serves the user detail page.
func (f *FrontendHandler) UserDetailPage(w http.ResponseWriter, r *http.Request) {
	f.render(w, r, "user_detail", pageData{Title: "User Detail"})
}

// TOTPSetupPage serves the TOTP enrollment page.
func (f *FrontendHandler) TOTPSetupPage(w http.ResponseWriter, r *http.Request) {
	f.render(w, r, "totp_setup", pageData{Title: "TOTP Setup"})
}

// ServeStatic serves embedded static files (CSS, JS).
func (f *FrontendHandler) ServeStatic(w http.ResponseWriter, r *http.Request) {
	// Strip /admin/static/ prefix to get the file path within staticFS
	filePath := strings.TrimPrefix(r.URL.Path, "/admin/static/")
	if filePath == "" {
		http.NotFound(w, r)
		return
	}

	// Read from embedded FS
	data, err := fs.ReadFile(staticFS, path.Join("static", filePath))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Set content type
	switch {
	case strings.HasSuffix(filePath, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(filePath, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	}

	// Cache-Control inherited from SecurityHeaders middleware (no-store).
	// Admin dashboard assets should never be publicly cached.
	if _, err := w.Write(data); err != nil { // #nosec G705 — data from go:embed, not user input
		log.Printf("admin-gateway: static write error: %v", err)
	}
}
