// Package email provides email sending capabilities for The Vault via a
// pluggable [Sender] interface. Implementations include [SMTPSender] and
// [SendGridSender]. Auth emails (verification, password reset, MFA code,
// lockout) are rendered by [TemplateRenderer], and the
// per-app white-label layer is applied by [Mailer].
package email

import "context"

// Address is an email sender identity. An empty Email means "use the sender's
// configured default address"; a non-empty Name is used as the display name.
// It lets the per-app white-label layer override the From line per tenant
// without each [Sender] implementation hard-coding a single address.
type Address struct {
	Name  string
	Email string
}

// Sender is the interface for sending emails. Implementations must handle both
// HTML and plain-text bodies for multipart/alternative delivery. The from
// argument selects the sender identity; a zero from (or empty from.Email) means
// the implementation uses its configured default address.
type Sender interface {
	Send(ctx context.Context, from Address, to, subject, htmlBody, textBody string) error
}
