package email

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestRenderVerification(t *testing.T) {
	subject, html, text := currentRenderer().Render(TemplateVerification, TemplateData{
		AppName:      "TestApp",
		URL:          "https://example.com/verify?token=abc",
		PrimaryColor: "#1a1a2e",
	})

	if !strings.Contains(subject, "Verify") {
		t.Errorf("subject should mention verify: %s", subject)
	}
	if !strings.Contains(html, "https://example.com/verify?token=abc") {
		t.Error("HTML should contain verification URL")
	}
	if !strings.Contains(text, "https://example.com/verify?token=abc") {
		t.Error("text should contain verification URL")
	}
	if !strings.Contains(html, "TestApp") {
		t.Error("HTML should contain app name")
	}
}

func TestRenderPasswordReset(t *testing.T) {
	subject, html, text := currentRenderer().Render(TemplatePasswordReset, TemplateData{
		AppName:      "TestApp",
		URL:          "https://example.com/reset?token=xyz",
		PrimaryColor: "#1a1a2e",
	})

	if !strings.Contains(subject, "Reset") {
		t.Error("subject should mention reset")
	}
	if !strings.Contains(html, "https://example.com/reset?token=xyz") {
		t.Error("HTML should contain reset URL")
	}
	if !strings.Contains(text, "1 hour") {
		t.Error("text should mention expiry")
	}
}

func TestRenderNewDevice(t *testing.T) {
	_, html, text := currentRenderer().Render(TemplateNewDevice, TemplateData{
		AppName:      "TestApp",
		IP:           "1.2.3.4",
		Device:       "Chrome on Windows",
		PrimaryColor: "#1a1a2e",
	})

	if !strings.Contains(html, "1.2.3.4") {
		t.Error("HTML should contain IP")
	}
	if !strings.Contains(text, "Chrome on Windows") {
		t.Error("text should contain device info")
	}
}

func TestRenderAccountLocked(t *testing.T) {
	_, html, _ := currentRenderer().Render(TemplateAccountLocked, TemplateData{
		AppName:      "TestApp",
		IP:           "5.6.7.8",
		PrimaryColor: "#1a1a2e",
	})

	if !strings.Contains(html, "5.6.7.8") {
		t.Error("HTML should contain the offending IP")
	}
}

func TestAllTemplatesNonEmpty(t *testing.T) {
	templates := []string{
		TemplateVerification, TemplatePasswordReset, TemplateNewDevice,
		TemplateAccountLocked, Template2FASetup, TemplateSuspiciousActivity,
	}

	for _, tmpl := range templates {
		subject, html, text := currentRenderer().Render(tmpl, TemplateData{AppName: "Test", PrimaryColor: "#1a1a2e"})
		if subject == "" {
			t.Errorf("template %s: empty subject", tmpl)
		}
		if html == "" {
			t.Errorf("template %s: empty HTML", tmpl)
		}
		if text == "" {
			t.Errorf("template %s: empty text", tmpl)
		}
	}
}

func TestNewTemplateRendererDefault(t *testing.T) {
	r, err := NewTemplateRenderer("")
	if err != nil {
		t.Fatalf("NewTemplateRenderer: %v", err)
	}
	subject, html, _ := r.Render(TemplateVerification, TemplateData{
		AppName:      "Vault",
		URL:          "https://vault.test/verify",
		PrimaryColor: "#1a1a2e",
	})
	if !strings.Contains(subject, "Verify") {
		t.Errorf("subject = %q, want verify mention", subject)
	}
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("HTML should contain DOCTYPE from base template")
	}
	if !strings.Contains(html, "vault.test/verify") {
		t.Error("HTML should contain verification URL")
	}
}

func TestTemplateRendererWithLogoURL(t *testing.T) {
	_, html, _ := currentRenderer().Render(TemplateVerification, TemplateData{
		AppName:      "Vault",
		URL:          "https://vault.test/verify",
		LogoURL:      "https://vault.test/logo.png",
		PrimaryColor: "#ff0000",
	})
	if !strings.Contains(html, "vault.test/logo.png") {
		t.Error("HTML should contain logo URL when set")
	}
	if !strings.Contains(html, "#ff0000") {
		t.Error("HTML should use primary color")
	}
}

func TestTemplateRendererUnknownTemplate(t *testing.T) {
	subject, html, text := currentRenderer().Render("nonexistent", TemplateData{AppName: "TestApp"})
	if subject != "Notification" {
		t.Errorf("unknown template subject = %q, want Notification", subject)
	}
	if !strings.Contains(html, "TestApp") {
		t.Error("unknown template HTML should contain app name")
	}
	if !strings.Contains(text, "TestApp") {
		t.Error("unknown template text should contain app name")
	}
}

func TestTemplateRendererOverride(t *testing.T) {
	dir := t.TempDir()
	// Write a custom verification template
	custom := `{{define "subject"}}Custom Subject - {{.AppName}}{{end}}
{{define "content"}}
<p>Custom content for {{.AppName}}</p>
{{end}}`
	os.WriteFile(filepath.Join(dir, "verification.html"), []byte(custom), 0o644)

	r, err := NewTemplateRenderer(dir)
	if err != nil {
		t.Fatalf("NewTemplateRenderer with override: %v", err)
	}
	subject, html, _ := r.Render(TemplateVerification, TemplateData{
		AppName:      "Vault",
		PrimaryColor: "#1a1a2e",
	})
	if !strings.Contains(subject, "Custom Subject") {
		t.Errorf("subject = %q, want custom subject", subject)
	}
	if !strings.Contains(html, "Custom content") {
		t.Error("HTML should contain custom content from override")
	}
}

// Render must not emit a half-built body when a template fails to execute.
//
// These two cases used to arrive through an override directory. They cannot any
// more: validateTemplate now renders an operator-authored template with canary
// data and refuses one that will not execute, so a {{.Nope}} override is
// rejected at construction rather than silently mailed as a blank notice. That
// is the better failure, and it leaves the embedded defaults as the only way to
// reach these branches -- defaults are trusted and deliberately not validated,
// which is exactly what makes them the right lever here.
func TestTemplateRendererExecuteErrorsProduceNoPartialBody(t *testing.T) {
	brokenDefault := func(t *testing.T, body string) *TemplateRenderer {
		t.Helper()
		fsys := apGoodTemplates()
		fsys["templates/"+TemplateVerification+".html"] = &fstest.MapFile{Data: []byte(body)}
		apUseTemplateFS(t, fsys)
		r, err := NewTemplateRenderer("")
		if err != nil {
			t.Fatalf("NewTemplateRenderer: %v", err)
		}
		return r
	}

	t.Run("subject execute error falls back to Notification", func(t *testing.T) {
		r := brokenDefault(t, `{{define "subject"}}{{.Nope}}{{end}}{{define "content"}}<p>x</p>{{end}}`)
		subject, html, text := r.Render(TemplateVerification, TemplateData{AppName: "Vault"})
		if subject != "Notification" {
			t.Errorf("subject = %q, want Notification", subject)
		}
		if html != "" || text != "" {
			t.Errorf("html/text = %q/%q, want empty on subject execute error", html, text)
		}
	})
	t.Run("content execute error keeps subject drops body", func(t *testing.T) {
		r := brokenDefault(t, `{{define "subject"}}RealSubject{{end}}{{define "content"}}{{.Nope}}{{end}}`)
		subject, html, text := r.Render(TemplateVerification, TemplateData{AppName: "Vault"})
		if subject != "RealSubject" {
			t.Errorf("subject = %q, want RealSubject", subject)
		}
		if html != "" || text != "" {
			t.Errorf("html/text = %q/%q, want empty on content execute error", html, text)
		}
	})
}

func TestTemplateRendererRejectsBrokenOverrideSyntax(t *testing.T) {
	dir := t.TempDir()
	broken := `{{define "subject"}}S{{end}}{{end}}`
	os.WriteFile(filepath.Join(dir, "verification.html"), []byte(broken), 0o644)

	_, err := NewTemplateRenderer(dir)
	if err == nil {
		t.Fatal("should reject a syntactically invalid override")
	}
	// The refusal now comes from validation rather than from the renderer's own
	// parse: validateTemplate has to compile the template to inspect what it
	// renders, so it is the first thing that sees the broken syntax. The
	// renderer's parse error still guards the embedded defaults, which are not
	// validated (TestNewTemplateRenderer_UnusableDefaultsFailAtConstruction).
	if !strings.Contains(err.Error(), "unsafe template") || !strings.Contains(err.Error(), "does not compile") {
		t.Errorf("err = %v, want the override refused as uncompilable", err)
	}
}

// The overrideDir "." trips the path-traversal guard (Clean drops the "./"
// prefix). The guard must skip only the override read, keeping the embedded
// default, and must not read files from the working directory.
func TestTemplateRendererRelativeOverrideDirIsSkipped(t *testing.T) {
	dir := t.TempDir()
	custom := `{{define "subject"}}Hijacked{{end}}{{define "content"}}<p>hijacked</p>{{end}}`
	os.WriteFile(filepath.Join(dir, "verification.html"), []byte(custom), 0o644)
	t.Chdir(dir)

	r, err := NewTemplateRenderer(".")
	if err != nil {
		t.Fatalf("NewTemplateRenderer: %v", err)
	}
	subject, html, _ := r.Render(TemplateVerification, TemplateData{
		AppName: "Vault",
		URL:     "https://vault.test/v",
	})
	if strings.Contains(subject, "Hijacked") || strings.Contains(html, "hijacked") {
		t.Error("guard tripped but the working-directory override was read")
	}
	if !strings.Contains(subject, "Verify") {
		t.Errorf("subject = %q, want the embedded default", subject)
	}
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("html should be the embedded default template")
	}
}

func TestTemplateRendererRejectsUnsafeScript(t *testing.T) {
	dir := t.TempDir()
	unsafe := `{{define "subject"}}Bad{{end}}
{{define "content"}}<script>alert('xss')</script>{{end}}`
	os.WriteFile(filepath.Join(dir, "verification.html"), []byte(unsafe), 0o644)

	_, err := NewTemplateRenderer(dir)
	if err == nil {
		t.Error("should reject template with <script> tag")
	}
}

func TestTemplateRendererRejectsUnsafeEventHandler(t *testing.T) {
	dir := t.TempDir()
	unsafe := `{{define "subject"}}Bad{{end}}
{{define "content"}}<img onerror="alert(1)" src="x">{{end}}`
	os.WriteFile(filepath.Join(dir, "verification.html"), []byte(unsafe), 0o644)

	_, err := NewTemplateRenderer(dir)
	if err == nil {
		t.Error("should reject template with event handlers")
	}
}

func TestTemplateRendererRejectsUnsafeIframe(t *testing.T) {
	dir := t.TempDir()
	unsafe := `{{define "subject"}}Bad{{end}}
{{define "content"}}<iframe src="https://evil.com"></iframe>{{end}}`
	os.WriteFile(filepath.Join(dir, "verification.html"), []byte(unsafe), 0o644)

	_, err := NewTemplateRenderer(dir)
	if err == nil {
		t.Error("should reject template with <iframe>")
	}
}

func TestTemplateRendererRejectsCallDirective(t *testing.T) {
	dir := t.TempDir()
	unsafe := `{{define "subject"}}Bad{{end}}
{{define "content"}}{{call .URL}}{{end}}`
	os.WriteFile(filepath.Join(dir, "verification.html"), []byte(unsafe), 0o644)

	_, err := NewTemplateRenderer(dir)
	if err == nil {
		t.Error("should reject template with {{call}}")
	}
}

func TestValidateTemplateSafeContent(t *testing.T) {
	safe := []byte(`{{define "subject"}}Hi{{end}}{{define "content"}}<p>Hello {{.AppName}}</p>{{end}}`)
	if err := validateTemplate(safe); err != nil {
		t.Errorf("safe template should pass validation: %v", err)
	}
}

func TestStripHTML(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"simple", "<p>Hello</p>", "Hello"},
		{"nested", "<div><p>Hello <b>World</b></p></div>", "Hello World"},
		{"entities", "&amp; &lt; &gt;", "& < >"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripHTML(tt.in)
			if got != tt.want {
				t.Errorf("stripHTML(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestAllTemplatesProduceValidHTML(t *testing.T) {
	templates := []string{
		TemplateVerification, TemplatePasswordReset, TemplateNewDevice,
		TemplateAccountLocked, Template2FASetup, TemplateSuspiciousActivity,
	}
	for _, name := range templates {
		t.Run(name, func(t *testing.T) {
			_, html, _ := currentRenderer().Render(name, TemplateData{
				AppName:      "Vault",
				URL:          "https://vault.test/action",
				IP:           "1.2.3.4",
				Device:       "Chrome",
				Code:         "ABC-123",
				PrimaryColor: "#1a1a2e",
			})
			if !strings.Contains(html, "<!DOCTYPE html>") {
				t.Error("should contain DOCTYPE")
			}
			if !strings.Contains(html, "</html>") {
				t.Error("should contain closing html tag")
			}
			if !strings.Contains(html, "Vault") {
				t.Error("should contain app name")
			}
		})
	}
}

// TestSafeFuncMap exercises the template func map (safeURL, upper, lower, truncate)
// for branches not necessarily hit by default renders.
func TestSafeFuncMap(t *testing.T) {
	fm := safeFuncMap()
	safeURL := fm["safeURL"].(func(string) template.URL)
	upper := fm["upper"].(func(string) string)
	lower := fm["lower"].(func(string) string)
	trunc := fm["truncate"].(func(string, int) string)

	t.Run("safeURL https", func(t *testing.T) {
		if got := safeURL("https://ex.com"); string(got) != "https://ex.com" {
			t.Errorf("safeURL https got %q", got)
		}
	})
	t.Run("safeURL http", func(t *testing.T) {
		if got := safeURL("http://ex.com"); string(got) != "http://ex.com" {
			t.Errorf("safeURL http got %q", got)
		}
	})
	t.Run("safeURL relative", func(t *testing.T) {
		if got := safeURL("/p"); string(got) != "/p" {
			t.Errorf("safeURL rel got %q", got)
		}
	})
	t.Run("safeURL unsafe js", func(t *testing.T) {
		if got := safeURL("javascript:alert(1)"); string(got) != "" {
			t.Errorf("safeURL js got %q", got)
		}
	})
	t.Run("safeURL data", func(t *testing.T) {
		if got := safeURL("data:x"); string(got) != "" {
			t.Errorf("safeURL data got %q", got)
		}
	})
	t.Run("upper", func(t *testing.T) {
		if upper("hello") != "HELLO" {
			t.Error("upper failed")
		}
	})
	t.Run("lower", func(t *testing.T) {
		if lower("HELLO") != "hello" {
			t.Error("lower failed")
		}
	})
	t.Run("truncate under", func(t *testing.T) {
		if trunc("abc", 10) != "abc" {
			t.Error("truncate under")
		}
	})
	t.Run("truncate over", func(t *testing.T) {
		if trunc("abcdef", 3) != "abc" {
			t.Error("truncate over")
		}
	})
	t.Run("truncate unicode", func(t *testing.T) {
		if trunc("caféX", 4) != "café" {
			t.Error("truncate unicode")
		}
	})
}

// TestSetDefaults_Table covers SetDefaults merging into Render for missing fields.
func TestSetDefaults_Table(t *testing.T) {
	tests := []struct {
		name       string
		defaults   TemplateData
		renderData TemplateData
		wantLogo   string
		wantColor  string
	}{
		{
			name:       "defaults used when empty",
			defaults:   TemplateData{LogoURL: "https://ex/logo.png", PrimaryColor: "#123456"},
			renderData: TemplateData{AppName: "X", URL: "https://ex/u"},
			wantLogo:   "https://ex/logo.png",
			wantColor:  "#123456",
		},
		{
			name:       "explicit overrides defaults",
			defaults:   TemplateData{LogoURL: "def", PrimaryColor: "defcol"},
			renderData: TemplateData{AppName: "X", LogoURL: "https://ex/explicit.png", PrimaryColor: "excol"},
			wantLogo:   "https://ex/explicit.png",
			wantColor:  "excol",
		},
		{
			name:       "partial default fill",
			defaults:   TemplateData{PrimaryColor: "#abc"},
			renderData: TemplateData{AppName: "X", LogoURL: "https://ex/onlylogo.png"},
			wantLogo:   "https://ex/onlylogo.png",
			wantColor:  "#abc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewTemplateRenderer("")
			if err != nil {
				t.Fatalf("new renderer: %v", err)
			}
			r.SetDefaults(tt.defaults)
			_, html, _ := r.Render(TemplateVerification, tt.renderData)
			if tt.wantLogo != "" && !strings.Contains(html, tt.wantLogo) {
				t.Errorf("logo %q not in html", tt.wantLogo)
			}
			if tt.wantColor != "" && !strings.Contains(html, tt.wantColor) {
				t.Errorf("color %q not in html", tt.wantColor)
			}
		})
	}
}

// TestSetRenderer_Table covers SetRenderer (once semantics) and default render path.
func TestSetRenderer_Table(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"set once"},
		{"set twice noop"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewTemplateRenderer("")
			if err != nil {
				t.Fatalf("renderer: %v", err)
			}
			// first set
			SetRenderer(r)
			// second set ignored
			r2, _ := NewTemplateRenderer("")
			SetRenderer(r2)

			subj, _, _ := currentRenderer().Render(TemplateVerification, TemplateData{AppName: "SRTest"})
			if subj == "" {
				t.Error("expected subject after SetRenderer")
			}
		})
	}
}
