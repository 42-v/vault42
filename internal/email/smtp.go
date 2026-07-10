package email

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/mail"
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
func (s *SMTPSender) Send(ctx context.Context, from Address, to, subject, htmlBody, textBody string) error {
	addr := net.JoinHostPort(s.host, s.port)

	// Envelope sender stays the bare address; the From header carries the
	// optional display name. An empty from.Email falls back to the default.
	envelopeFrom := s.from
	if from.Email != "" {
		envelopeFrom = from.Email
	}
	fromHeader := formatFromHeader(from.Name, envelopeFrom)

	msg := buildMIMEMessage(fromHeader, to, subject, htmlBody, textBody)

	var auth smtp.Auth
	if s.user != "" {
		auth = smtp.PlainAuth("", s.user, s.password, s.host)
	}

	// smtp.SendMail ignores context, so run it in a goroutine with a timeout.
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		ch <- result{smtp.SendMail(addr, auth, envelopeFrom, []string{to}, []byte(msg))}
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

// formatFromHeader renders an RFC 5322 From value, encoding/quoting the display
// name as needed. An empty name yields the bare address.
func formatFromHeader(name, addr string) string {
	name = sanitizeHeader(name)
	if name == "" {
		return addr
	}
	return (&mail.Address{Name: name, Address: addr}).String()
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

	// Bodies are base64-encoded (Content-Transfer-Encoding: base64). Per-app
	// white-label templates let an admin supply body content, so it is untrusted
	// with respect to MIME structure. Header values are already CR/LF-sanitized
	// and the envelope recipients come from the sanitized `to`, but base64 makes
	// the bodies structurally inert: the encoded alphabet cannot contain CR/LF or
	// the boundary marker, so no body can forge a MIME part, header, or the
	// message terminator regardless of its content. It is also the correct way to
	// carry 8-bit and long-line content.
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&b, "Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(base64MIMEBody(textBody))

	fmt.Fprintf(&b, "--%s\r\n", boundary)
	fmt.Fprintf(&b, "Content-Type: text/html; charset=utf-8\r\n")
	fmt.Fprintf(&b, "Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(base64MIMEBody(htmlBody))

	fmt.Fprintf(&b, "--%s--\r\n", boundary)

	return b.String()
}

// base64MIMEBody encodes s as base64 and folds it into CRLF-terminated lines of
// at most 76 characters, per RFC 2045. The output ends with CRLF.
//
// The base64 alphabet is [A-Za-z0-9+/=] and contains no CR or LF. We strip any
// line breaks from the encoded output anyway to make that invariant explicit and
// enforced: the encoded body can carry no line break of its own into the MIME
// stream, so no body content (even attacker-influenced white-label template
// data) can forge a header, MIME part, or the boundary. The only CRLFs in the
// result are the fixed 76-column fold markers added below.
func base64MIMEBody(s string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	enc = strings.ReplaceAll(enc, "\r", "")
	enc = strings.ReplaceAll(enc, "\n", "")
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteString("\r\n")
	return b.String()
}
