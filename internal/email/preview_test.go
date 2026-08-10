package email

import (
	"strings"
	"testing"
)

// RenderPreview used to compile the override twice and handle a parse error from
// each compile. Only the first of those error paths is reachable, because
// ValidateTemplateContent runs compileOverride on the same subject and body and
// returns its error, so the second compile was deleted down to its result.
//
// This pins the reachable half of that invariant: every template that fails to
// parse is rejected by the validation gate, with the validation gate's message,
// and no partially rendered output escapes. If a refactor ever moved the compile
// out of ValidateTemplateContent, this test fails rather than the admin UI
// silently rendering an unvalidated template.
func TestRenderPreviewRejectsUncompilableTemplateAtValidation(t *testing.T) {
	cases := map[string]struct{ subject, html string }{
		"unterminated action in subject": {"Hi {{.AppName", "<p>ok</p>"},
		"unterminated action in body":    {"Hi", "<p>{{.Code</p>"},
		"unknown function in body":       {"Hi", `<p>{{ exfiltrate .Code }}</p>`},
		"unclosed range in body":         {"Hi", "<p>{{range .Missing}}x</p>"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			subj, html, text, err := RenderPreview(tc.subject, tc.html, SampleData())
			if err == nil {
				t.Fatal("RenderPreview accepted a template that does not parse")
			}
			if !strings.Contains(err.Error(), "email: template does not compile") {
				t.Errorf("error = %v, want the ValidateTemplateContent compile error", err)
			}
			if subj != "" || html != "" || text != "" {
				t.Errorf("output escaped a rejected template: subject=%q html=%q text=%q", subj, html, text)
			}
		})
	}
}

// The complement: a template that parses renders through the single remaining
// compile, so the deletion did not remove the path that does the work.
func TestRenderPreviewRendersCompilableTemplate(t *testing.T) {
	subj, html, text, err := RenderPreview("Code for {{.AppName}}", "<p>Your code is {{.Code}}</p>", SampleData())
	if err != nil {
		t.Fatalf("RenderPreview: %v", err)
	}
	if subj != "Code for Example App" {
		t.Errorf("subject = %q", subj)
	}
	if !strings.Contains(html, "123456") {
		t.Errorf("html = %q, want the sample code rendered", html)
	}
	if !strings.Contains(text, "123456") {
		t.Errorf("text = %q, want the sample code in the plain-text fallback", text)
	}
}
