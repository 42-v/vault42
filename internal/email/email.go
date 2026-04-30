// Package email provides email sending capabilities for The Vault via a
// pluggable [Sender] interface. Implementations include [SMTPSender] for
// direct SMTP delivery. Email templates for verification, password reset,
// new device alerts, and other notifications are provided by [RenderTemplate].
package email

import "context"

// Sender is the interface for sending emails. Implementations must handle
// both HTML and plain-text bodies for multipart/alternative delivery.
type Sender interface {
	Send(ctx context.Context, to, subject, htmlBody, textBody string) error
}
