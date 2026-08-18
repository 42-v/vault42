package email

import (
	"context"
	"strings"
	"testing"
)

func TestValidApp(t *testing.T) {
	valid := []string{"acme", "a", "app-1", "my_app", "x0", strings.Repeat("a", 64)}
	invalid := []string{"", "Acme", "-lead", "_lead", "a b", "app!", strings.Repeat("a", 65), "café"}
	for _, s := range valid {
		if !ValidApp(s) {
			t.Errorf("ValidApp(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if ValidApp(s) {
			t.Errorf("ValidApp(%q) = true, want false", s)
		}
	}
}

func TestWithAppAndFromContext(t *testing.T) {
	t.Run("valid slug round-trips", func(t *testing.T) {
		ctx := WithApp(context.Background(), "acme")
		if got := AppFromContext(ctx); got != "acme" {
			t.Fatalf("AppFromContext = %q, want acme", got)
		}
	})
	t.Run("invalid slug is ignored", func(t *testing.T) {
		ctx := WithApp(context.Background(), "Bad Slug!")
		if got := AppFromContext(ctx); got != "" {
			t.Fatalf("invalid slug stored: %q", got)
		}
	})
	t.Run("empty context returns empty", func(t *testing.T) {
		if got := AppFromContext(context.Background()); got != "" {
			t.Fatalf("AppFromContext(empty) = %q, want empty", got)
		}
	})
}

func TestValidHexColor(t *testing.T) {
	for _, s := range []string{"#00FF42", "#000000", "#abcdef"} {
		if !ValidHexColor(s) {
			t.Errorf("ValidHexColor(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "00FF42", "#FFF", "#gggggg", "#00FF4", "green"} {
		if ValidHexColor(s) {
			t.Errorf("ValidHexColor(%q) = true, want false", s)
		}
	}
}

func TestValidLogoURL(t *testing.T) {
	for _, s := range []string{"https://cdn.acme.test/logo.png", "https://example.com/a.svg"} {
		if !ValidLogoURL(s) {
			t.Errorf("ValidLogoURL(%q) = false, want true", s)
		}
	}
	// http, non-absolute, userinfo, and loopback/SSRF hosts are all rejected.
	for _, s := range []string{
		"http://acme.test/l.png",
		"/relative/l.png",
		"https://user:pass@acme.test/l.png",
		"https://localhost/l.png",
		"https://127.0.0.1/l.png",
		"https://::1/l.png",
		"ftp://acme.test/l.png",
		"",
	} {
		if ValidLogoURL(s) {
			t.Errorf("ValidLogoURL(%q) = true, want false", s)
		}
	}
}

func TestValidTemplateName(t *testing.T) {
	if !ValidTemplateName(TemplateVerification) {
		t.Errorf("ValidTemplateName(%q) = false, want true", TemplateVerification)
	}
	if ValidTemplateName("not_a_real_template") {
		t.Error("ValidTemplateName(unknown) = true, want false")
	}
}

func TestValidateTemplateContent(t *testing.T) {
	tests := []struct {
		name, subject, html string
		wantErr             bool
	}{
		{"valid", "Verify your email", "<p>Hi {{.AppName}}</p>", false},
		{"empty subject", "   ", "<p>ok</p>", true},
		{"empty html", "Subject", "   ", true},
		{"script tag", "Subject", "<script>alert(1)</script>", true},
		{"script in subject", "<script>alert(1)</script>", "<p>ok</p>", true},
		{"broken template", "Subject", "<p>{{.Unclosed</p>", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplateContent(tt.subject, tt.html)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTemplateContent err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCompileOverride_ParseErrorAfterValidation covers the two arms
// CompileOverride takes when its own Parse rejects content validateTemplate
// already accepted. The two parsers can disagree because they use different
// root names: guardTemplate parses under guardRootName, while CompileOverride
// parses the subject as "subject" and the body as "html". An override that
// defines a block by one of those two names is therefore valid to the guard and
// a redefinition of the root to CompileOverride, which is what makes these arms
// reachable rather than dead code.
func TestCompileOverride_ParseErrorAfterValidation(t *testing.T) {
	tests := []struct {
		name string
		ov   TemplateOverride
	}{
		{
			"subject defines a block named after its own root",
			TemplateOverride{Subject: `{{define "subject"}}x{{end}}Verify your email`, HTMLContent: "<p>Hi</p>"},
		},
		{
			"html defines a block named after its own root",
			TemplateOverride{Subject: "Verify your email", HTMLContent: `{{define "html"}}<p>x</p>{{end}}<p>Hi</p>`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Both halves must clear validateTemplate first. If either were
			// refused there, CompileOverride would return before its own Parse
			// and this test would be proving something else entirely.
			if err := validateTemplate([]byte(tt.ov.HTMLContent)); err != nil {
				t.Fatalf("validateTemplate(html) = %v, want it accepted so the Parse arm is what refuses", err)
			}
			if err := validateTemplate([]byte(tt.ov.Subject)); err != nil {
				t.Fatalf("validateTemplate(subject) = %v, want it accepted so the Parse arm is what refuses", err)
			}
			c, err := CompileOverride(tt.ov)
			if err == nil {
				t.Fatalf("CompileOverride accepted %+v, want the parse refusal", tt.ov)
			}
			if c != nil {
				t.Errorf("CompiledOverride = %+v, want nil alongside the error", c)
			}
			if !strings.Contains(err.Error(), "does not compile") {
				t.Errorf("err = %v, want it to say the template does not compile", err)
			}
			if !strings.Contains(err.Error(), "multiple definition") {
				t.Errorf("err = %v, want the redefinition parse error underneath", err)
			}
		})
	}
}

// TestCompiledOverride_RenderExecuteError covers the two arms render takes when
// executing the compiled subject or body fails. Reaching them needs a template
// the guard accepts and a real send breaks, and reading past the end of the app
// name is exactly that: validation renders with guardData's 27-character app
// name, so a slice to 20 succeeds there and then fails for every tenant whose
// name is shorter. A validated override is therefore not a rendering override,
// which is why render reports the failure instead of assuming it cannot happen.
func TestCompiledOverride_RenderExecuteError(t *testing.T) {
	tests := []struct {
		name string
		ov   TemplateOverride
	}{
		{"subject", TemplateOverride{Subject: `Hi {{slice .AppName 0 20}}`, HTMLContent: "<p>Hi</p>"}},
		{"html", TemplateOverride{Subject: "Verify your email", HTMLContent: `<p>{{slice .AppName 0 20}}</p>`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := CompileOverride(tt.ov)
			if err != nil {
				t.Fatalf("CompileOverride: %v, want it accepted so the failure is at execute time", err)
			}
			subject, html, text, err := c.render(TemplateData{AppName: "Acme", URL: "https://acme.test/v"})
			if err == nil {
				t.Fatal("render succeeded, want the execute error for the short app name")
			}
			if !strings.Contains(err.Error(), "out of range") {
				t.Errorf("err = %v, want the out-of-range execute error", err)
			}
			if subject != "" || html != "" || text != "" {
				t.Errorf("outputs = %q/%q/%q, want all empty on error", subject, html, text)
			}
			// The same override renders cleanly for a long enough app name, so
			// the refusal above is the data's doing and not the template's.
			if _, _, _, err := c.render(TemplateData{AppName: strings.Repeat("a", 20), URL: "https://acme.test/v"}); err != nil {
				t.Errorf("render with a long app name = %v, want it to succeed", err)
			}
		})
	}
}

func TestRenderPreview(t *testing.T) {
	t.Run("renders subject and body against sample data", func(t *testing.T) {
		subj, html, text, err := RenderPreview("Hi from {{.AppName}}", "<p>Code {{.Code}}</p>", SampleData())
		if err != nil {
			t.Fatalf("RenderPreview: %v", err)
		}
		if subj != "Hi from Example App" {
			t.Errorf("subject = %q", subj)
		}
		if !strings.Contains(html, "123456") {
			t.Errorf("html missing rendered code: %q", html)
		}
		if !strings.Contains(text, "123456") {
			t.Errorf("text (stripped html) missing code: %q", text)
		}
	})
	t.Run("invalid content is rejected", func(t *testing.T) {
		if _, _, _, err := RenderPreview("S", "<script>x</script>", SampleData()); err == nil {
			t.Fatal("RenderPreview accepted a script tag")
		}
	})
	t.Run("subject execute error is surfaced", func(t *testing.T) {
		subj, html, text, err := RenderPreview("{{.Missing}}", "<p>ok</p>", SampleData())
		if err == nil || !strings.Contains(err.Error(), "Missing") {
			t.Fatalf("err = %v, want an execute error mentioning Missing", err)
		}
		if subj != "" || html != "" || text != "" {
			t.Errorf("outputs = %q/%q/%q, want all empty on error", subj, html, text)
		}
	})
	t.Run("html execute error is surfaced", func(t *testing.T) {
		subj, html, text, err := RenderPreview("S", "<p>{{.Missing}}</p>", SampleData())
		if err == nil || !strings.Contains(err.Error(), "Missing") {
			t.Fatalf("err = %v, want an execute error mentioning Missing", err)
		}
		if subj != "" || html != "" || text != "" {
			t.Errorf("outputs = %q/%q/%q, want all empty on error", subj, html, text)
		}
	})
}
