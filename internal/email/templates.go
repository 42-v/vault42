package email

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unicode/utf8"
)

// Template name constants identify the available email templates.
const (
	// TemplateVerification is the email verification template sent after registration.
	TemplateVerification = "verification"
	// TemplatePasswordReset is the password reset link template.
	TemplatePasswordReset = "password_reset"
	// TemplateNewDevice is the new device login notification template.
	TemplateNewDevice = "new_device"
	// TemplateAccountLocked is the account lockout notification template.
	TemplateAccountLocked = "account_locked"
	// Template2FASetup is the two-factor authentication setup confirmation template.
	Template2FASetup = "2fa_setup"
	// TemplateSuspiciousActivity is the suspicious activity alert template.
	TemplateSuspiciousActivity = "suspicious_activity"
	// TemplateEmailOTP is the email one-time password template for MFA fallback.
	TemplateEmailOTP = "email_otp"
	// TemplateNewLocation is the new-location (new country) login notice. It is
	// deliberately distinct from TemplateSuspiciousActivity: it renders the
	// country only and has no field for an IP, so the notice cannot carry one
	// (docs/PRIVACY.md P4, data minimisation to country granularity).
	TemplateNewLocation = "new_location"
)

//go:embed templates/*.html
var defaultTemplates embed.FS

// templateFS is the source of the built-in templates. It is a variable rather
// than the embed.FS directly so a test can substitute a corrupt filesystem and
// pin what NewTemplateRenderer does when the defaults cannot be loaded.
var templateFS fs.FS = defaultTemplates

// TemplateData holds the parameters used to render email templates.
// Not all fields are used by every template.
type TemplateData struct {
	AppName string
	URL     string
	Token   string
	IP      string
	Device  string
	Code    string
	// Country is the ISO 3166-1 alpha-2 country code shown in the new-location
	// notice. It is the ONLY location field that template carries: the notice is
	// reduced to country granularity so it can never quote the login IP.
	Country      string
	LogoURL      string
	PrimaryColor string
	Subject      string // populated internally during render
}

// Pre-compiled regexes for stripHTML to avoid per-call compilation.
var (
	tagRe   = regexp.MustCompile(`<[^>]*>`)
	spaceRe = regexp.MustCompile(`\s+`)
)

// unsafePattern matches dangerous content that must not appear in custom email
// templates. Beyond active scripting it also rejects the passive auto-loading
// vectors a credential-bearing email must never carry — meta-refresh redirects,
// <base> hijacks, <link>/<style>/<svg> external loads, any <form>, data: URIs,
// and CSS url() — so an admin-authored template cannot beacon a live
// verification/reset token or OTP code out to an arbitrary host.
// It allows benign structure a real HTML email needs (a <meta charset>/viewport,
// a <style> block of inline CSS) but rejects the beacon-capable subset: any
// http-equiv meta (refresh redirect), <base>, <link>, <svg>, <form>, data: URIs,
// and CSS url().
var unsafePattern = regexp.MustCompile(
	`(?i)` +
		`<\s*script|<\s*iframe|<\s*object|<\s*embed|` +
		`<\s*base|<\s*link|<\s*svg|<\s*form|` +
		`<\s*meta[^>]*http-equiv|` +
		`javascript\s*:|data\s*:|` +
		`\burl\s*\(|` +
		`\bon\w+\s*=|` +
		`\{\{\s*call\s|` +
		`\{\{\s*js\s`,
)

// TemplateRenderer renders email templates using go:embed defaults with
// optional file-system overrides. Each template is parsed independently
// with the shared base layout.
type TemplateRenderer struct {
	templates map[string]*template.Template
	defaults  TemplateData // branding defaults merged into every render call
}

func safeFuncMap() template.FuncMap {
	return template.FuncMap{
		"safeURL": func(s string) template.URL { // #nosec G203 -- safeURL validates scheme whitelist (https/http/relative only), rejects javascript: and data: URIs
			if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "/") {
				return template.URL(s)
			}
			return "" // reject javascript:, data:, and other unsafe schemes
		},
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"truncate": func(s string, n int) string {
			if utf8.RuneCountInString(s) <= n {
				return s
			}
			return string([]rune(s)[:n])
		},
	}
}

// NewTemplateRenderer creates a renderer that uses embedded default templates,
// optionally overridden by custom templates in overrideDir.
func NewTemplateRenderer(overrideDir string) (*TemplateRenderer, error) {
	r := &TemplateRenderer{
		templates: make(map[string]*template.Template),
	}

	// Read the base layout
	baseData, err := fs.ReadFile(templateFS, "templates/base.html")
	if err != nil {
		return nil, fmt.Errorf("email: read base template: %w", err)
	}

	names := []string{
		TemplateVerification, TemplatePasswordReset, TemplateNewDevice,
		TemplateAccountLocked, Template2FASetup, TemplateSuspiciousActivity,
		TemplateEmailOTP, TemplateNewLocation,
	}

	for _, name := range names {
		// Read default template
		contentData, err := fs.ReadFile(templateFS, "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("email: read template %s: %w", name, err)
		}

		// Check for override (reject symlinks and path traversal to prevent arbitrary file read).
		// A tripped guard skips only the override read; the embedded default still registers.
		if overrideDir != "" {
			overridePath := filepath.Clean(filepath.Join(overrideDir, name+".html"))
			cleanDir := filepath.Clean(overrideDir) + string(os.PathSeparator)
			if strings.HasPrefix(overridePath, cleanDir) {
				// Atomic open with O_NOFOLLOW to prevent symlink TOCTOU race.
				// This replaces the previous Lstat+ReadFile pattern where a symlink
				// could be swapped in between the check and the read.
				if f, err := os.OpenFile(overridePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0); err == nil { // #nosec G304 -- path validated: Clean + HasPrefix against override directory
					data, readErr := io.ReadAll(f)
					f.Close() // #nosec G104 -- closing read-only file; error is non-actionable
					if readErr == nil {
						if err := validateTemplate(data); err != nil {
							return nil, fmt.Errorf("email: unsafe template %s: %w", overridePath, err)
						}
						contentData = data
					}
				}
			}
		}

		// Parse base + content together
		tmpl := template.New(name).Funcs(safeFuncMap())
		tmpl, err = tmpl.Parse(string(baseData))
		if err != nil {
			return nil, fmt.Errorf("email: parse base for %s: %w", name, err)
		}
		tmpl, err = tmpl.Parse(string(contentData))
		if err != nil {
			return nil, fmt.Errorf("email: parse content for %s: %w", name, err)
		}

		r.templates[name] = tmpl
	}

	return r, nil
}

// SetDefaults configures branding defaults (LogoURL, PrimaryColor) that are
// merged into every Render call when the caller hasn't set them.
func (r *TemplateRenderer) SetDefaults(d TemplateData) {
	r.defaults = d
}

// Render returns the subject, HTML body, and plain-text body for the named template.
func (r *TemplateRenderer) Render(templateName string, data TemplateData) (string, string, string) {
	// Merge branding defaults
	if data.LogoURL == "" {
		data.LogoURL = r.defaults.LogoURL
	}
	if data.PrimaryColor == "" {
		data.PrimaryColor = r.defaults.PrimaryColor
	}
	tmpl, ok := r.templates[templateName]
	if !ok {
		return "Notification", "<p>Notification from " + template.HTMLEscapeString(data.AppName) + "</p>",
			"Notification from " + data.AppName
	}

	// Render subject
	var subBuf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&subBuf, "subject", data); err != nil {
		return "Notification", "", ""
	}
	subject := strings.TrimSpace(subBuf.String())

	// Render full HTML (base wraps content)
	data.Subject = subject
	var htmlBuf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&htmlBuf, "base", data); err != nil {
		return subject, "", ""
	}
	htmlBody := htmlBuf.String()

	// Generate plain text by stripping HTML tags
	textBody := stripHTML(htmlBody)

	return subject, htmlBody, textBody
}

// validateTemplate rejects templates containing unsafe patterns.
func validateTemplate(data []byte) error {
	if unsafePattern.Match(data) {
		return fmt.Errorf("template contains forbidden content (script/iframe/object/embed/meta/base/link/style/svg/form tags, javascript:/data: URIs, css url(), event handlers, or call/js directives)")
	}
	return nil
}

// stripHTML removes HTML tags and collapses whitespace for plain-text fallback.
func stripHTML(s string) string {
	s = tagRe.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = spaceRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// defaultRenderer is initialized at package load time with embedded templates only.
// Call [SetRenderer] to replace it with a custom-configured renderer; [NewMailer]
// falls back to it whenever it is handed a nil one, which is how
// internal/service and internal/handler build their mailers.
//
// It is an atomic pointer rather than a plain one because the sync.Once below
// does not make the publication safe on its own. A Once orders the goroutine
// inside Do against other goroutines that call Do, and against nothing else;
// NewMailer only reads the variable and never calls Do, so it inherits no
// ordering from it. Startup wiring publishes the configured
// renderer while request-escaping goroutines are already sending mail
// (internal/service finishes verification and reset mail asynchronously), which
// made the plain pointer a genuine data race rather than a theoretical one.
var (
	defaultRenderer atomic.Pointer[TemplateRenderer]
	setRendererOnce sync.Once
)

func init() {
	r, err := NewTemplateRenderer("")
	if err != nil {
		panic("email: failed to initialize default templates: " + err.Error())
	}
	defaultRenderer.Store(r)
}

// currentRenderer returns the package-level renderer every unsynchronized
// reader must go through.
func currentRenderer() *TemplateRenderer {
	return defaultRenderer.Load()
}

// SetRenderer replaces the package-level default renderer [NewMailer] falls back to.
// Call this once at startup after loading config to enable template overrides and branding.
// Subsequent calls are no-ops so the renderer a running process reads never changes twice.
func SetRenderer(r *TemplateRenderer) {
	setRendererOnce.Do(func() {
		defaultRenderer.Store(r)
	})
}
