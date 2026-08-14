package email

import (
	"context"
	"fmt"
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
type OverrideStore interface {
	Branding(ctx context.Context, app string) (Branding, bool)
	Template(ctx context.Context, app, name string) (TemplateOverride, bool)
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
// content never reaches the send path.
func ValidateTemplateContent(subject, htmlContent string) error {
	if strings.TrimSpace(subject) == "" {
		return fmt.Errorf("email: template subject is empty")
	}
	if strings.TrimSpace(htmlContent) == "" {
		return fmt.Errorf("email: template html is empty")
	}
	if err := validateTemplate([]byte(htmlContent)); err != nil {
		return err
	}
	if err := validateTemplate([]byte(subject)); err != nil {
		return err
	}
	if _, _, err := compileOverride(subject, htmlContent); err != nil {
		return fmt.Errorf("email: template does not compile: %w", err)
	}
	return nil
}
