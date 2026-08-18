package attack

import (
	"context"
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/email"
)

// The email XSS claim used to be made through email.RenderTemplate, a
// package-level function with no non-test caller, and judged by a matcher that
// returned true for any "<sc" — so <section> was a hit and <SCRIPT, <img
// onerror= and <svg onload= were all misses.
//
// The path that ships is Mailer.Send: it resolves per-app branding, then either
// renders an operator override or falls through to the built-in template, and
// hands the result to the sender. Attacker-controlled data reaches both
// branches, so both are driven here, and the assertion is made on the bytes the
// sender was actually given.

// capturedMail is the last message a mailer handed its sender.
type capturedMail struct {
	subject, html, text string
	sent                bool
}

func (c *capturedMail) Send(_ context.Context, _ email.Address, _, subject, htmlBody, textBody string) error {
	c.subject, c.html, c.text, c.sent = subject, htmlBody, textBody, true
	return nil
}

// overrideStore serves one compiled operator override for one app, which is the
// white-label path a super_admin writes through.
type overrideStore struct {
	app      string
	branding email.Branding
	name     string
	override *email.CompiledOverride
}

func (s *overrideStore) Branding(_ context.Context, app string) (email.Branding, bool) {
	if app != s.app {
		return email.Branding{}, false
	}
	return s.branding, true
}

func (s *overrideStore) Template(_ context.Context, app, name string) (*email.CompiledOverride, bool) {
	if app != s.app || name != s.name || s.override == nil {
		return nil, false
	}
	return s.override, true
}

// The two properties asserted below are exact rather than pattern-matched. The
// scan they replace was `html[i] == '<' && html[i+1] == 's' && html[i+2] == 'c'`
// over the whole body: <section> was a hit, <SCRIPT and <img onerror= were
// misses, and an escaped payload sitting harmlessly in text was
// indistinguishable from a live one.

// requireMarkupEscaped asserts the payload's markup did not survive into body as
// markup: the raw bytes are absent and html.EscapeString's form of them is
// present. Removing the escaping from a template makes the first check fail and
// the second at the same time, and neither depends on guessing which constructs
// are dangerous.
func requireMarkupEscaped(t *testing.T, body, payload string) {
	t.Helper()
	if !strings.ContainsAny(payload, "<>") {
		return
	}
	if strings.Contains(body, payload) {
		t.Fatalf("the payload %q reached the delivered body unescaped:\n%s", payload, body)
	}
	if escaped := html.EscapeString(payload); !strings.Contains(body, escaped) {
		t.Fatalf("the payload %q is neither raw nor escaped as %q in the delivered body; "+
			"this assertion is measuring the wrong field:\n%s", payload, escaped, body)
	}
}

// urlAttr matches the value of every attribute a mail client will dereference.
var urlAttr = regexp.MustCompile(`(?i)\b(?:href|src|action)\s*=\s*"([^"]*)"`)

// requireNoLiveURLScheme asserts every dereferenced attribute in the body
// carries a scheme a mail client may follow. It is the URL half of the claim:
// html/template's URL filter and the template set's own safeURL guard are what
// blank a javascript: or data: link, and this fails if either is removed.
func requireNoLiveURLScheme(t *testing.T, body string) {
	t.Helper()
	matches := urlAttr.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		t.Fatalf("no href/src/action attribute found in the delivered body, so the URL "+
			"assertion covered nothing:\n%s", body)
	}
	for _, m := range matches {
		value := strings.TrimSpace(m[1])
		if value == "" {
			continue // the guard blanked it, which is the refusal
		}
		lower := strings.ToLower(value)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
			strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "cid:") ||
			strings.HasPrefix(lower, "#") {
			continue
		}
		t.Fatalf("a dereferenced attribute carries %q, which is not a scheme a mail client "+
			"may follow:\n%s", value, body)
	}
}

// mailerUnderTest builds a Mailer the way service wiring builds one, over the
// embedded templates, and returns it with the sender that captures what it sent.
func mailerUnderTest(t *testing.T, store email.OverrideStore) (*email.Mailer, *capturedMail) {
	t.Helper()
	renderer, err := email.NewTemplateRenderer("")
	if err != nil {
		t.Fatalf("NewTemplateRenderer: %v", err)
	}
	sent := &capturedMail{}
	return email.NewMailer(renderer, sent, store, email.Branding{AppName: "The Vault"}, nil), sent
}

// TestEmailTemplateXSSInjection drives the send path with attacker-controlled
// template data and asserts nothing live survives into the delivered body.
func TestEmailTemplateXSSInjection(t *testing.T) {
	payloads := []struct {
		name     string
		template string
		field    string
		payload  string
		data     email.TemplateData
	}{
		{"script_in_appname", email.TemplateVerification, "AppName", `<script>alert('xss')</script>`, email.TemplateData{
			AppName: `<script>alert('xss')</script>`, URL: "https://vault.test/verify?token=abc"}},
		{"uppercase_script_in_appname", email.TemplateVerification, "AppName", `<SCRIPT>alert(1)</SCRIPT>`, email.TemplateData{
			AppName: `<SCRIPT>alert(1)</SCRIPT>`, URL: "https://vault.test/verify?token=abc"}},
		{"img_onerror_in_appname", email.TemplateVerification, "AppName", `<img src=x onerror=alert(1)>`, email.TemplateData{
			AppName: `<img src=x onerror=alert(1)>`, URL: "https://vault.test/verify?token=abc"}},
		{"svg_onload_in_appname", email.TemplateVerification, "AppName", `<svg onload=alert(1)>`, email.TemplateData{
			AppName: `<svg onload=alert(1)>`, URL: "https://vault.test/verify?token=abc"}},
		{"base_hijack_in_appname", email.TemplateVerification, "AppName", `<base href="https://evil.test/">`, email.TemplateData{
			AppName: `<base href="https://evil.test/">`, URL: "https://vault.test/verify?token=abc"}},
		{"javascript_url", email.TemplateVerification, "URL", "javascript:alert(document.cookie)", email.TemplateData{
			AppName: "TestVault", URL: "javascript:alert(document.cookie)"}},
		{"data_uri_in_url", email.TemplatePasswordReset, "URL", "data:text/html,<script>alert('xss')</script>", email.TemplateData{
			AppName: "TestVault", URL: "data:text/html,<script>alert('xss')</script>"}},
		{"script_in_code", email.TemplateEmailOTP, "Code", `<script>alert('otp')</script>`, email.TemplateData{
			AppName: "TestVault", URL: "https://vault.test/verify?token=abc",
			Code: `<script>alert('otp')</script>`}},
		{"iframe_in_device", email.TemplateNewDevice, "Device", `<iframe src=javascript:alert(1)>`, email.TemplateData{
			AppName: "TestVault", URL: "https://vault.test/verify?token=abc",
			Device: `<iframe src=javascript:alert(1)>`}},
		{"script_in_country", email.TemplateNewLocation, "Country", `<script>alert(1)</script>`, email.TemplateData{
			AppName: "TestVault", URL: "https://vault.test/verify?token=abc",
			Country: `<script>alert(1)</script>`}},
		{"onerror_in_ip", email.TemplateAccountLocked, "IP", `<img src=x onerror=alert(1)>`, email.TemplateData{
			AppName: "TestVault", URL: "https://vault.test/verify?token=abc",
			IP: `<img src=x onerror=alert(1)>`}},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			mailer, sent := mailerUnderTest(t, nil)
			if err := mailer.Send(context.Background(), "", tc.template,
				"victim@example.com", tc.data); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if !sent.sent {
				t.Fatal("the mailer delivered nothing, so nothing was inspected")
			}
			requireMarkupEscaped(t, sent.html, tc.payload)
		})
	}
}

// TestEmailTemplateHostileURLIsNeverDereferenced is the URL half of the claim.
// Every link and image source in a delivered body has to carry a scheme a mail
// client may follow; a javascript: or data: link that survives is a live payload
// in the one message a user is most primed to click.
//
// The templates that render a URL are the two credential-bearing ones, and the
// logo comes from the per-app branding row an operator writes, so a hostile
// value can arrive from either side.
func TestEmailTemplateHostileURLIsNeverDereferenced(t *testing.T) {
	hostile := []string{
		"javascript:alert(document.cookie)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		" javascript:alert(1)",
		"JaVaScRiPt:alert(1)",
	}

	for _, tmpl := range []string{email.TemplateVerification, email.TemplatePasswordReset} {
		for _, bad := range hostile {
			t.Run(tmpl+"/url/"+bad, func(t *testing.T) {
				mailer, sent := mailerUnderTest(t, nil)
				if err := mailer.Send(context.Background(), "", tmpl, "victim@example.com",
					email.TemplateData{AppName: "TestVault", URL: bad}); err != nil {
					t.Fatalf("Send: %v", err)
				}
				requireNoLiveURLScheme(t, sent.html)
			})
			t.Run(tmpl+"/logo/"+bad, func(t *testing.T) {
				mailer, sent := mailerUnderTest(t, nil)
				if err := mailer.Send(context.Background(), "", tmpl, "victim@example.com",
					email.TemplateData{AppName: "TestVault", URL: "https://vault.test/v", LogoURL: bad}); err != nil {
					t.Fatalf("Send: %v", err)
				}
				requireNoLiveURLScheme(t, sent.html)
			})
		}
	}
}

// TestEmailTemplateXSSInjectionThroughAnOperatorOverride drives the other
// branch. An override is a full body replacement written by a super_admin;
// CompileOverride refuses live markup in the template itself, but the data
// interpolated into it is still attacker-controlled, and this is the branch
// Mailer.Send takes whenever an app has one stored. Nothing in the tree
// exercised it with a hostile payload.
func TestEmailTemplateXSSInjectionThroughAnOperatorOverride(t *testing.T) {
	override, err := email.CompileOverride(email.TemplateOverride{
		Subject:     "{{.AppName}} — verify your address",
		HTMLContent: `<p>Hello from {{.AppName}}. <a href="{{.URL}}">Verify</a> with {{.Code}}.</p>`,
	})
	if err != nil {
		t.Fatalf("CompileOverride on a benign template: %v", err)
	}
	store := &overrideStore{
		app:      "acme",
		branding: email.Branding{AppName: "Acme"},
		name:     email.TemplateVerification,
		override: override,
	}

	for _, tc := range []struct {
		name    string
		payload string
		data    email.TemplateData
	}{
		{"script_in_appname", `<script>alert(1)</script>`, email.TemplateData{
			AppName: `<script>alert(1)</script>`, URL: "https://vault.test/v", Code: "123456"}},
		{"javascript_url", "javascript:alert(1)", email.TemplateData{
			AppName: "Acme", URL: "javascript:alert(1)", Code: "123456"}},
		{"onerror_in_code", `<img src=x onerror=alert(1)>`, email.TemplateData{
			AppName: "Acme", URL: "https://vault.test/v", Code: `<img src=x onerror=alert(1)>`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mailer, sent := mailerUnderTest(t, store)
			if err := mailer.Send(context.Background(), "acme", email.TemplateVerification,
				"victim@example.com", tc.data); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if !strings.Contains(sent.html, "Verify") {
				t.Fatalf("the override was not the branch taken; body was:\n%s", sent.html)
			}
			requireMarkupEscaped(t, sent.html, tc.payload)
			requireNoLiveURLScheme(t, sent.html)
		})
	}
}

// TestEmailTemplateValidation verifies every built-in template renders a
// complete message through the send path — a body with no subject, no HTML or no
// plain-text alternative is one a mail client renders as blank or a filter drops.
func TestEmailTemplateValidation(t *testing.T) {
	for _, tmpl := range []string{
		email.TemplateVerification,
		email.TemplatePasswordReset,
		email.TemplateNewDevice,
		email.TemplateAccountLocked,
		email.Template2FASetup,
		email.TemplateSuspiciousActivity,
	} {
		t.Run(tmpl, func(t *testing.T) {
			mailer, sent := mailerUnderTest(t, nil)
			if err := mailer.Send(context.Background(), "", tmpl, "victim@example.com",
				email.TemplateData{URL: "https://vault.test", Code: "123456"}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if sent.subject == "" {
				t.Error("empty subject")
			}
			if sent.html == "" {
				t.Error("empty HTML body")
			}
			if sent.text == "" {
				t.Error("empty plain text body")
			}
		})
	}
}

// TestEmailTemplateDefaults verifies the branding a deployment configures
// actually reaches the delivered body. It used to assert len(html) != 0 after
// setting a brand colour, which held for any output at all.
func TestEmailTemplateDefaults(t *testing.T) {
	renderer, err := email.NewTemplateRenderer("")
	if err != nil {
		t.Fatalf("NewTemplateRenderer: %v", err)
	}
	renderer.SetDefaults(email.TemplateData{PrimaryColor: "#00FF42", AppName: "The Vault"})
	sent := &capturedMail{}
	mailer := email.NewMailer(renderer, sent, nil, email.Branding{AppName: "The Vault"}, nil)

	if err := mailer.Send(context.Background(), "", email.TemplateVerification,
		"victim@example.com", email.TemplateData{URL: "https://vault.test/verify?token=abc"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(sent.html, "#00FF42") {
		t.Errorf("the configured brand colour is absent from the delivered body:\n%s", sent.html)
	}
	if !strings.Contains(sent.html, "The Vault") {
		t.Errorf("the configured app name is absent from the delivered body:\n%s", sent.html)
	}
}
