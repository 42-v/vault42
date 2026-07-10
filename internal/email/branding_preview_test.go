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
}
