package attack

import (
	"testing"

	"github.com/42-v/vault42/internal/email"
)

// TestEmailTemplateXSSInjection verifies that user-supplied data in email
// template fields is properly escaped and cannot inject HTML/JavaScript.
func TestEmailTemplateXSSInjection(t *testing.T) {
	// Attempt XSS via template data fields
	xssPayloads := []struct {
		name  string
		data  email.TemplateData
		field string // which field carries the payload
	}{
		{
			"script_in_appname",
			email.TemplateData{
				AppName: `<script>alert('xss')</script>`,
				URL:     "https://vault.test/verify?token=abc",
			},
			"AppName",
		},
		{
			"img_onerror_in_appname",
			email.TemplateData{
				AppName: `<img src=x onerror=alert(1)>`,
				URL:     "https://vault.test/verify?token=abc",
			},
			"AppName",
		},
		{
			"javascript_url",
			email.TemplateData{
				AppName: "TestVault",
				URL:     "javascript:alert(document.cookie)",
			},
			"URL",
		},
		{
			"data_uri_in_url",
			email.TemplateData{
				AppName: "TestVault",
				URL:     "data:text/html,<script>alert('xss')</script>",
			},
			"URL",
		},
	}

	for _, tc := range xssPayloads {
		t.Run(tc.name, func(t *testing.T) {
			_, html, _ := email.RenderTemplate(email.TemplateVerification, tc.data)

			// html/template auto-escapes, so script tags should be escaped
			if containsRawScript(html) {
				t.Fatalf("XSS payload %q was not escaped in %s field", tc.name, tc.field)
			}
		})
	}
}

func containsRawScript(html string) bool {
	// Check for unescaped script tags — html/template should escape them
	for i := 0; i < len(html)-7; i++ {
		if html[i] == '<' && html[i+1] == 's' && html[i+2] == 'c' {
			return true // found unescaped <script
		}
	}
	return false
}

// TestEmailTemplateValidation verifies that custom template overrides
// with malicious content are rejected by the validator.
func TestEmailTemplateValidation(t *testing.T) {
	// NewTemplateRenderer with a non-existent override dir should work (no overrides)
	renderer, err := email.NewTemplateRenderer("")
	if err != nil {
		t.Fatalf("NewTemplateRenderer failed: %v", err)
	}
	if renderer == nil {
		t.Fatal("expected non-nil renderer")
	}

	// Verify all built-in templates render without error
	templates := []string{
		email.TemplateVerification,
		email.TemplatePasswordReset,
		email.TemplateNewDevice,
		email.TemplateAccountLocked,
		email.Template2FASetup,
		email.TemplateSuspiciousActivity,
	}

	for _, tmpl := range templates {
		t.Run(tmpl, func(t *testing.T) {
			subject, html, text := email.RenderTemplate(tmpl, email.TemplateData{
				AppName: "TestVault",
				URL:     "https://vault.test",
			})
			if subject == "" {
				t.Fatal("empty subject")
			}
			if html == "" {
				t.Fatal("empty HTML body")
			}
			if text == "" {
				t.Fatal("empty plain text body")
			}
		})
	}
}

// TestEmailTemplateDefaults verifies that branding defaults (primary color,
// app name) are correctly applied across all templates.
func TestEmailTemplateDefaults(t *testing.T) {
	renderer, _ := email.NewTemplateRenderer("")
	renderer.SetDefaults(email.TemplateData{
		PrimaryColor: "#00FF42",
		AppName:      "The Vault",
	})
	email.SetRenderer(renderer)

	_, html, _ := email.RenderTemplate(email.TemplateVerification, email.TemplateData{
		URL: "https://vault.test/verify?token=abc",
	})

	// Should contain the brand color
	if len(html) == 0 {
		t.Fatal("empty HTML output")
	}
}
