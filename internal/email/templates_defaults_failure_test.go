package email

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// apAllTemplateNames is every template NewTemplateRenderer is required to
// register. A renderer missing one silently degrades that mail to the
// "Notification" stub, which is why the count is asserted rather than assumed.
var apAllTemplateNames = []string{
	TemplateVerification, TemplatePasswordReset, TemplateNewDevice,
	TemplateAccountLocked, Template2FASetup, TemplateSuspiciousActivity,
	TemplateEmailOTP,
}

// apUseTemplateFS swaps the built-in template source for one test.
func apUseTemplateFS(t *testing.T, sub fs.FS) {
	t.Helper()
	orig := templateFS
	templateFS = sub
	t.Cleanup(func() { templateFS = orig })
}

// apGoodTemplates is a minimal but valid stand-in for the embedded set.
func apGoodTemplates() fstest.MapFS {
	m := fstest.MapFS{
		"templates/base.html": &fstest.MapFile{
			Data: []byte(`{{define "base"}}<html><body>{{template "content" .}}</body></html>{{end}}`),
		},
	}
	for _, n := range apAllTemplateNames {
		m["templates/"+n+".html"] = &fstest.MapFile{
			Data: []byte(`{{define "subject"}}` + n + `{{end}}{{define "content"}}<p>` + n + `</p>{{end}}`),
		}
	}
	return m
}

// A renderer that cannot load its built-in templates must be refused at
// construction. Returning a usable renderer with an empty map instead would push
// the failure to send time, where Render falls back to a generic "Notification"
// body: every verification link, reset link and OTP would go out as a blank
// notice with the code stripped out, and nothing anywhere would have errored.
func TestNewTemplateRenderer_UnusableDefaultsFailAtConstruction(t *testing.T) {
	good := apGoodTemplates()

	missingBase := apGoodTemplates()
	delete(missingBase, "templates/base.html")

	missingContent := apGoodTemplates()
	delete(missingContent, "templates/"+TemplateEmailOTP+".html")

	brokenBase := apGoodTemplates()
	brokenBase["templates/base.html"] = &fstest.MapFile{Data: []byte(`{{define "base"}}{{ .Unclosed `)}

	brokenContent := apGoodTemplates()
	brokenContent["templates/"+TemplatePasswordReset+".html"] = &fstest.MapFile{Data: []byte(`{{define "subject"}}{{ end `)}

	tests := []struct {
		name string
		fsys fstest.MapFS
		want string
	}{
		{"the base layout is gone", missingBase, "read base template"},
		{"a template file is gone", missingContent, "read template " + TemplateEmailOTP},
		{"the base layout does not parse", brokenBase, "parse base for"},
		{"a template does not parse", brokenContent, "parse content for " + TemplatePasswordReset},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apUseTemplateFS(t, tc.fsys)

			r, err := NewTemplateRenderer("")
			if err == nil {
				t.Fatalf("NewTemplateRenderer succeeded with unusable defaults, returning %d templates", len(r.templates))
			}
			if r != nil {
				t.Error("a renderer was handed back alongside the error; a caller that ignores err would send blank mail")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name %q", err, tc.want)
			}
		})
	}

	apUseTemplateFS(t, good)
	if _, err := NewTemplateRenderer(""); err != nil {
		t.Fatalf("the control case must construct: %v", err)
	}
}

// The override directory comes from VAULT_EMAIL_TEMPLATES_DIR. A name that
// escapes it must be ignored, and 0.9.6 fixed the shape of "ignored" that
// mattered: a tripped guard once left the loop with zero templates registered
// and still returned a renderer and a nil error, so the operator saw a healthy
// start and every user got a blank notification instead of their reset link.
// The guard skips only the override read; the embedded default still registers.
func TestNewTemplateRenderer_TrippedTraversalGuardKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, TemplateVerification+".html"),
		[]byte(`{{define "subject"}}HIJACKED{{end}}{{define "content"}}<p>HIJACKED</p>{{end}}`), 0o600); err != nil {
		t.Fatalf("seed override: %v", err)
	}
	// A relative override directory does not survive the Clean+HasPrefix check,
	// so the guard trips on every name even though the files are right there.
	t.Chdir(dir)

	r, err := NewTemplateRenderer(".")
	if err != nil {
		t.Fatalf("NewTemplateRenderer: %v", err)
	}
	if r == nil {
		t.Fatal("no renderer")
	}
	if len(r.templates) != len(apAllTemplateNames) {
		t.Fatalf("registered %d templates, want %d: a tripped guard must not cost the embedded defaults",
			len(r.templates), len(apAllTemplateNames))
	}

	for _, name := range apAllTemplateNames {
		subject, html, text := r.Render(name, TemplateData{AppName: "Vault42", URL: "https://example.com/a", Code: "123456"})
		if subject == "Notification" || html == "" || text == "" {
			t.Errorf("%s fell back to the generic notification: subject=%q html-empty=%v", name, subject, html == "")
		}
		if strings.Contains(html, "HIJACKED") {
			t.Errorf("%s loaded a template from outside the override directory", name)
		}
	}
}
