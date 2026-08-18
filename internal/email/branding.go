package email

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/url"
	"regexp"
	"strings"
)

// Branding is the per-app white-label override resolved at send time. Empty
// fields fall back to the global defaults configured on the [Mailer].
type Branding struct {
	AppName      string
	LogoURL      string
	PrimaryColor string
	FromName     string
	FromAddress  string
}

// TemplateOverride is a per-app, per-type full replacement of an email body.
type TemplateOverride struct {
	Subject     string
	HTMLContent string
	TextContent string
}

// OverrideStore supplies per-app branding and template overrides to the
// [Mailer]. It is implemented by the service layer over the database. Lookups
// happen on the send path, so implementations should be cheap (and may cache).
// The bool result is false when there is no override for that app/template.
//
// Template returns an already-validated, already-parsed override. The type is
// deliberate: an implementation loading a row from the database has to put it
// through [CompileOverride], which is the only constructor, so the send path
// never turns a stored string into an executable template.
type OverrideStore interface {
	Branding(ctx context.Context, app string) (Branding, bool)
	Template(ctx context.Context, app, name string) (*CompiledOverride, bool)
}

// CompiledOverride is a per-app template override that has been validated and
// parsed. [CompileOverride] is the only way to build one, so possessing one is
// proof the content passed the same checks the admin write path applies
// (ASVS V1.3.7).
type CompiledOverride struct {
	subject *template.Template
	html    *template.Template
	text    string
}

// CompileOverride validates an override and parses it into executable
// templates, using the same safe function map (and therefore the same safeURL
// guard) as the global templates.
//
// It rejects the forbidden constructs — script/iframe/object/embed/base/link/
// svg/form, http-equiv meta, javascript: and data: URIs, CSS url(), event
// handlers, and the call/js template directives — before parsing, so no
// unvalidated admin-supplied string ever reaches html/template. Run it wherever
// a stored template is loaded, not where one is sent.
func CompileOverride(ov TemplateOverride) (*CompiledOverride, error) {
	if strings.TrimSpace(ov.Subject) == "" {
		return nil, fmt.Errorf("email: template subject is empty")
	}
	if strings.TrimSpace(ov.HTMLContent) == "" {
		return nil, fmt.Errorf("email: template html is empty")
	}
	if err := validateTemplate([]byte(ov.HTMLContent)); err != nil {
		return nil, err
	}
	if err := validateTemplate([]byte(ov.Subject)); err != nil {
		return nil, err
	}
	st, err := template.New("subject").Funcs(safeFuncMap()).Parse(ov.Subject)
	if err != nil {
		return nil, fmt.Errorf("email: template does not compile: %w", err)
	}
	ht, err := template.New("html").Funcs(safeFuncMap()).Parse(ov.HTMLContent)
	if err != nil {
		return nil, fmt.Errorf("email: template does not compile: %w", err)
	}
	return &CompiledOverride{subject: st, html: ht, text: ov.TextContent}, nil
}

// render executes the compiled override. The plain-text part falls back to the
// HTML with tags stripped when the override carries none.
func (c *CompiledOverride) render(data TemplateData) (subject, html, text string, err error) {
	var subBuf, htmlBuf bytes.Buffer
	if err := c.subject.Execute(&subBuf, data); err != nil {
		return "", "", "", err
	}
	subject = strings.TrimSpace(subBuf.String())
	data.Subject = subject
	if err := c.html.Execute(&htmlBuf, data); err != nil {
		return "", "", "", err
	}
	html = htmlBuf.String()
	text = c.text
	if strings.TrimSpace(text) == "" {
		text = stripHTML(html)
	}
	return subject, html, text, nil
}

// knownTemplateNames is the set of email types an override may target. Restricting
// to known names stops an admin from creating dead rows that never render.
var knownTemplateNames = map[string]bool{
	TemplateVerification:       true,
	TemplatePasswordReset:      true,
	TemplateNewDevice:          true,
	TemplateAccountLocked:      true,
	Template2FASetup:           true,
	TemplateSuspiciousActivity: true,
	TemplateEmailOTP:           true,
	TemplateNewLocation:        true,
}

// ValidTemplateName reports whether name is a known email template type.
func ValidTemplateName(name string) bool { return knownTemplateNames[name] }

var hexColorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// ValidHexColor reports whether s is a #RRGGBB colour.
func ValidHexColor(s string) bool { return hexColorRe.MatchString(s) }

// ValidLogoURL reports whether s is an absolute https URL with a public host.
// Logos are loaded by remote mail clients, so http, non-absolute URLs, embedded
// userinfo, and loopback hosts are rejected (the last to avoid a stored-SSRF
// foothold should the URL ever be fetched server-side).
func ValidLogoURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.") {
		return false
	}
	return true
}

// ValidateTemplateContent rejects custom email HTML that contains forbidden
// constructs (script/iframe/event handlers/template-execution directives) or
// fails to compile as a standalone template. Run it at admin write time so bad
// content never reaches storage; [CompileOverride], which it delegates to, runs
// again at load time so bad content that got there another way never renders.
func ValidateTemplateContent(subject, htmlContent string) error {
	_, err := CompileOverride(TemplateOverride{Subject: subject, HTMLContent: htmlContent})
	return err
}
