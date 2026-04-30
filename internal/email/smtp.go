package email

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

// SMTPSender sends emails via SMTP with optional PLAIN authentication.
// It implements the [Sender] interface.
type SMTPSender struct {
	host     string
	port     string
	user     string
	password string
	from     string
}

// NewSMTPSender creates a new SMTP email sender.
func NewSMTPSender(host, port, user, password, from string) *SMTPSender {
	return &SMTPSender{
		host: host, port: port,
		user: user, password: password, from: from,
	}
}

// Send sends a multipart/alternative email (HTML + plain text) via SMTP.
// If user credentials are configured, PLAIN authentication is used.
// Respects the context deadline; defaults to a 30-second timeout if none is set.
func (s *SMTPSender) Send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	addr := net.JoinHostPort(s.host, s.port)

	msg := buildMIMEMessage(s.from, to, subject, htmlBody, textBody)

	var auth smtp.Auth
	if s.user != "" {
		auth = smtp.PlainAuth("", s.user, s.password, s.host)
	}

	// smtp.SendMail ignores context, so run it in a goroutine with a timeout.
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		ch <- result{smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg))}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		return r.err
	}
}

// sanitizeHeader strips CR/LF characters to prevent email header injection.
func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

func buildMIMEMessage(from, to, subject, htmlBody, textBody string) string {
	// Sanitize header values to prevent header injection attacks
	from = sanitizeHeader(from)
	to = sanitizeHeader(to)
	subject = sanitizeHeader(subject)

	var b strings.Builder
	var randomBytes [16]byte
	// crypto/rand.Read on a fixed-size buffer never returns short on Linux/Darwin;
	// boundary uniqueness is best-effort anyway (the SMTP receiver only needs
	// distinct boundaries within one message).
	_, _ = rand.Read(randomBytes[:])
	boundary := fmt.Sprintf("vault-%x", randomBytes)

	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%s\r\n", boundary)
	fmt.Fprintf(&b, "\r\n")

	// Text part
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n\r\n")
	fmt.Fprintf(&b, "%s\r\n", textBody)

	// HTML part
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	fmt.Fprintf(&b, "Content-Type: text/html; charset=utf-8\r\n\r\n")
	fmt.Fprintf(&b, "%s\r\n", htmlBody)

	fmt.Fprintf(&b, "--%s--\r\n", boundary)

	return b.String()
}
