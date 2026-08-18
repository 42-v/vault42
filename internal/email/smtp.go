package email

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
)

// ErrSMTPNoSTARTTLS is returned when the SMTP server does not advertise
// STARTTLS and the sender was not explicitly told to accept a cleartext relay.
//
// Every message vault42 sends carries a bearer secret for the length of its
// TTL: a verification link, a password-reset link, an email one-time code. An
// on-path attacker who strips STARTTLS from the EHLO response reads all of them
// and, without this check, the send still reports success.
var ErrSMTPNoSTARTTLS = errors.New("email: SMTP server does not advertise STARTTLS and plaintext delivery was not permitted")

// SMTPSender sends emails via SMTP with optional PLAIN authentication.
// It implements the [Sender] interface.
type SMTPSender struct {
	host     string
	port     string
	user     string
	password string
	from     string
	// allowPlaintext permits delivery over an unupgraded connection. See
	// AllowPlaintext.
	allowPlaintext bool
}

// SMTPOption configures an [SMTPSender] at construction.
type SMTPOption func(*SMTPSender)

// AllowPlaintext permits delivery to a server that does not advertise STARTTLS.
//
// It exists for the one deployment where cleartext SMTP is not an exposure: a
// relay reached over loopback or a unix-domain-equivalent hop that never leaves
// the host. config.Load refuses the opt-out outside dev for any other SMTP_HOST
// for that reason. It is not a fallback — a server that does advertise STARTTLS
// is still upgraded — it only decides what happens when no upgrade is on offer.
func AllowPlaintext(allow bool) SMTPOption {
	return func(s *SMTPSender) { s.allowPlaintext = allow }
}

// NewSMTPSender creates a new SMTP email sender. STARTTLS is required unless
// [AllowPlaintext] is passed.
func NewSMTPSender(host, port, user, password, from string, opts ...SMTPOption) *SMTPSender {
	s := &SMTPSender{
		host: host, port: port,
		user: user, password: password, from: from,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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

	// The SMTP conversation ignores context, so run it in a goroutine and let
	// the caller's deadline win the select.
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		ch <- result{s.deliver(addr, envelopeFrom, to, []byte(msg))}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		return r.err
	}
}

// deliver runs one SMTP conversation. It replaces smtp.SendMail, whose TLS
// policy is opportunistic: SendMail upgrades when the server offers STARTTLS
// and sends in cleartext, reporting success, when it does not.
func (s *SMTPSender) deliver(addr, envelopeFrom, to string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("email: smtp connect %s: %w", addr, err)
	}
	defer c.Close() // #nosec G104 -- Quit below is the ordered close; this is the abort path

	// Extension sends EHLO on first use, so a server that refuses EHLO reports
	// no capabilities and is treated as offering no STARTTLS — the fail-closed
	// direction.
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("email: smtp starttls: %w", err)
		}
	} else if !s.allowPlaintext {
		return fmt.Errorf("%w (host %s)", ErrSMTPNoSTARTTLS, s.host)
	}

	// Each step is a closure so the whole conversation shares one error path:
	// an SMTP session that fails midway is a failed send regardless of which
	// verb the server refused.
	var steps []func() error
	if s.user != "" {
		steps = append(steps, func() error { return c.Auth(smtp.PlainAuth("", s.user, s.password, s.host)) })
	}
	var w io.WriteCloser
	steps = append(steps,
		func() error { return c.Mail(envelopeFrom) },
		func() error { return c.Rcpt(to) },
		func() (err error) { w, err = c.Data(); return err },
		func() error { _, err := w.Write(msg); return err },
		func() error { return w.Close() },
		c.Quit,
	)
	for _, step := range steps {
		if err := step(); err != nil {
			return fmt.Errorf("email: smtp send: %w", err)
		}
	}
	return nil
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
