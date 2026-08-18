package email

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// NewSMTPSender construction tests (~8 subtests)
// ---------------------------------------------------------------------------

func TestNewSMTPSenderFieldAssignment(t *testing.T) {
	s := NewSMTPSender("mail.example.com", "587", "user@example.com", "secret123", "noreply@example.com")

	if s.host != "mail.example.com" {
		t.Errorf("host = %q, want mail.example.com", s.host)
	}
	if s.port != "587" {
		t.Errorf("port = %q, want 587", s.port)
	}
	if s.user != "user@example.com" {
		t.Errorf("user = %q, want user@example.com", s.user)
	}
	if s.password != "secret123" {
		t.Errorf("password = %q, want secret123", s.password)
	}
	if s.from != "noreply@example.com" {
		t.Errorf("from = %q, want noreply@example.com", s.from)
	}
}

func TestNewSMTPSenderEmptyCredentials(t *testing.T) {
	s := NewSMTPSender("localhost", "25", "", "", "from@local")

	if s.user != "" {
		t.Errorf("user should be empty, got %q", s.user)
	}
	if s.password != "" {
		t.Errorf("password should be empty, got %q", s.password)
	}
}

func TestNewSMTPSenderDifferentPorts(t *testing.T) {
	tests := []struct {
		name string
		port string
	}{
		{"port_25", "25"},
		{"port_465", "465"},
		{"port_587", "587"},
		{"port_2525", "2525"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSMTPSender("smtp.test", tt.port, "u", "p", "f@t")
			if s.port != tt.port {
				t.Errorf("port = %q, want %q", s.port, tt.port)
			}
		})
	}
}

func TestNewSMTPSenderReturnsNonNil(t *testing.T) {
	s := NewSMTPSender("", "", "", "", "")
	if s == nil {
		t.Error("NewSMTPSender should never return nil")
	}
}

func TestNewSMTPSenderImplementsSenderInterface(t *testing.T) {
	var _ Sender = (*SMTPSender)(nil)
}

// ---------------------------------------------------------------------------
// buildMIMEMessage tests (~10 subtests)
// ---------------------------------------------------------------------------

func TestBuildMIMEMessageContainsBoundary(t *testing.T) {
	msg := buildMIMEMessage("a@b.c", "d@e.f", "Test", "<b>html</b>", "text")

	if !strings.Contains(msg, "vault-") {
		t.Error("message should contain boundary starting with 'vault-'")
	}
}

func TestBuildMIMEMessageUniqueBoundaries(t *testing.T) {
	msg1 := buildMIMEMessage("a@b.c", "d@e.f", "Test1", "<b>html</b>", "text")
	msg2 := buildMIMEMessage("a@b.c", "d@e.f", "Test2", "<b>html</b>", "text")

	// Extract boundaries
	extractBoundary := func(msg string) string {
		for _, line := range strings.Split(msg, "\r\n") {
			if strings.Contains(line, "boundary=") {
				parts := strings.SplitN(line, "boundary=", 2)
				if len(parts) == 2 {
					return parts[1]
				}
			}
		}
		return ""
	}

	b1 := extractBoundary(msg1)
	b2 := extractBoundary(msg2)
	if b1 == "" || b2 == "" {
		t.Fatal("could not extract boundaries")
	}
	if b1 == b2 {
		t.Error("boundaries should be unique between messages")
	}
}

func TestBuildMIMEMessageFromHeader(t *testing.T) {
	msg := buildMIMEMessage("sender@example.com", "rcpt@example.com", "Sub", "<b>h</b>", "t")
	if !strings.Contains(msg, "From: sender@example.com\r\n") {
		t.Error("missing From header")
	}
}

func TestBuildMIMEMessageToHeader(t *testing.T) {
	msg := buildMIMEMessage("s@e.com", "recipient@example.com", "Sub", "<b>h</b>", "t")
	if !strings.Contains(msg, "To: recipient@example.com\r\n") {
		t.Error("missing To header")
	}
}

func TestBuildMIMEMessageSubjectHeader(t *testing.T) {
	msg := buildMIMEMessage("s@e.com", "r@e.com", "Important Subject", "<b>h</b>", "t")
	if !strings.Contains(msg, "Subject: Important Subject\r\n") {
		t.Error("missing Subject header")
	}
}

func TestBuildMIMEMessageMIMEVersion(t *testing.T) {
	msg := buildMIMEMessage("s@e.com", "r@e.com", "Sub", "<b>h</b>", "t")
	if !strings.Contains(msg, "MIME-Version: 1.0\r\n") {
		t.Error("missing MIME-Version header")
	}
}

func TestBuildMIMEMessageMultipartAlternative(t *testing.T) {
	msg := buildMIMEMessage("s@e.com", "r@e.com", "Sub", "<b>h</b>", "t")
	if !strings.Contains(msg, "Content-Type: multipart/alternative") {
		t.Error("missing multipart/alternative Content-Type")
	}
}

func TestBuildMIMEMessageTextPart(t *testing.T) {
	msg := buildMIMEMessage("s@e.com", "r@e.com", "Sub", "<b>html</b>", "plain text body here")
	if !strings.Contains(msg, "Content-Type: text/plain; charset=utf-8") {
		t.Error("missing text/plain content type")
	}
	// The body is base64-encoded (Content-Transfer-Encoding: base64), so it must
	// appear encoded, not verbatim.
	if !strings.Contains(msg, base64.StdEncoding.EncodeToString([]byte("plain text body here"))) {
		t.Error("missing base64-encoded text body content")
	}
}

func TestBuildMIMEMessageHTMLPart(t *testing.T) {
	msg := buildMIMEMessage("s@e.com", "r@e.com", "Sub", "<h1>Hello World</h1>", "text")
	if !strings.Contains(msg, "Content-Type: text/html; charset=utf-8") {
		t.Error("missing text/html content type")
	}
	if !strings.Contains(msg, base64.StdEncoding.EncodeToString([]byte("<h1>Hello World</h1>"))) {
		t.Error("missing base64-encoded HTML body content")
	}
}

func TestBuildMIMEMessageFinalBoundary(t *testing.T) {
	msg := buildMIMEMessage("s@e.com", "r@e.com", "Sub", "<b>h</b>", "t")

	// Final boundary should end with --
	lines := strings.Split(msg, "\r\n")
	foundFinal := false
	for _, line := range lines {
		if strings.HasPrefix(line, "--vault-") && strings.HasSuffix(line, "--") {
			foundFinal = true
			break
		}
	}
	if !foundFinal {
		t.Error("message should end with final boundary marker (--boundary--)")
	}
}

// ---------------------------------------------------------------------------
// sanitizeHeader tests (~5 subtests)
// ---------------------------------------------------------------------------

func TestSanitizeHeaderPreservesNormal(t *testing.T) {
	input := "Hello World Subject Line"
	got := sanitizeHeader(input)
	if got != input {
		t.Errorf("normal header should be unchanged, got %q", got)
	}
}

func TestSanitizeHeaderUnicodePreserved(t *testing.T) {
	input := "Subject with unicode: \u00e9\u00e8\u00ea"
	got := sanitizeHeader(input)
	if got != input {
		t.Errorf("unicode should be preserved, got %q", got)
	}
}

func TestSanitizeHeaderStripsCR(t *testing.T) {
	got := sanitizeHeader("Line1\rLine2")
	if strings.Contains(got, "\r") {
		t.Error("CR should be stripped")
	}
	if got != "Line1Line2" {
		t.Errorf("got %q, want Line1Line2", got)
	}
}

func TestSanitizeHeaderStripsLF(t *testing.T) {
	got := sanitizeHeader("Line1\nLine2")
	if strings.Contains(got, "\n") {
		t.Error("LF should be stripped")
	}
	if got != "Line1Line2" {
		t.Errorf("got %q, want Line1Line2", got)
	}
}

func TestSanitizeHeaderStripsCRLF(t *testing.T) {
	got := sanitizeHeader("Line1\r\nLine2\r\nLine3")
	if got != "Line1Line2Line3" {
		t.Errorf("got %q, want Line1Line2Line3", got)
	}
}

// ---------------------------------------------------------------------------
// SMTP Send integration tests with mock server (~8 subtests)
// ---------------------------------------------------------------------------

// mockSMTPServer creates a minimal SMTP server for testing.
// It listens on a random port and records received messages.
type mockSMTPServer struct {
	listener net.Listener
	wg       sync.WaitGroup
	mu       sync.Mutex
	received []mockSMTPMessage
	auths    []string
	failData bool
	// advertiseSTARTTLS makes the mock announce the STARTTLS capability in its
	// EHLO response and answer the command with 220. It then hangs up instead of
	// serving a certificate, so the client's handshake fails: enough to prove the
	// upgrade was attempted without minting a throwaway CA per test.
	advertiseSTARTTLS bool
	starttls          int
}

type mockSMTPMessage struct {
	from string
	to   []string
	data string
}

func newMockSMTPServer(t *testing.T) *mockSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &mockSMTPServer{listener: ln}
	s.wg.Add(1)
	go s.serve()
	return s
}

func (s *mockSMTPServer) addr() string {
	return s.listener.Addr().String()
}

func (s *mockSMTPServer) port() string {
	_, port, _ := net.SplitHostPort(s.addr())
	return port
}

func (s *mockSMTPServer) close() {
	s.listener.Close()
	s.wg.Wait()
}

func (s *mockSMTPServer) messages() []mockSMTPMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]mockSMTPMessage{}, s.received...)
}

func (s *mockSMTPServer) starttlsAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.starttls
}

func (s *mockSMTPServer) authAttempts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.auths...)
}

func (s *mockSMTPServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *mockSMTPServer) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)

	write := func(msg string) {
		fmt.Fprintf(writer, "%s\r\n", msg)
		writer.Flush()
	}

	write("220 localhost ESMTP mock")

	var msg mockSMTPMessage
	inData := false
	var dataBuilder strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if inData {
			if line == "." {
				inData = false
				if s.failData {
					write("554 Transaction failed")
					return
				}
				msg.data = dataBuilder.String()
				s.mu.Lock()
				s.received = append(s.received, msg)
				s.mu.Unlock()
				write("250 Ok: queued")
				continue
			}
			dataBuilder.WriteString(line + "\r\n")
			continue
		}

		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			write("250-localhost Hello")
			write("250-AUTH PLAIN")
			if s.advertiseSTARTTLS {
				write("250-STARTTLS")
			}
			write("250 OK")
		case strings.HasPrefix(upper, "STARTTLS"):
			s.mu.Lock()
			s.starttls++
			s.mu.Unlock()
			write("220 Ready to start TLS")
			return
		case strings.HasPrefix(upper, "AUTH"):
			s.mu.Lock()
			s.auths = append(s.auths, line)
			s.mu.Unlock()
			write("235 Authentication succeeded")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			msg.from = extractAddr(line)
			write("250 Ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			msg.to = append(msg.to, extractAddr(line))
			write("250 Ok")
		case strings.HasPrefix(upper, "DATA"):
			write("354 Start mail input")
			inData = true
			dataBuilder.Reset()
		case strings.HasPrefix(upper, "QUIT"):
			write("221 Bye")
			return
		default:
			write("500 Unknown command")
		}
	}
}

func extractAddr(line string) string {
	start := strings.Index(line, "<")
	end := strings.Index(line, ">")
	if start >= 0 && end > start {
		return line[start+1 : end]
	}
	// Fallback: after the colon
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return line
}

func TestSendWithMockSMTPServer(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	sender := NewSMTPSender("127.0.0.1", srv.port(), "", "", "sender@test.com", AllowPlaintext(true))
	err := sender.Send(context.Background(), Address{}, "recipient@test.com", "Test Subject", "<b>HTML</b>", "text body")
	if err != nil {
		t.Fatalf("Send should succeed: %v", err)
	}

	msgs := srv.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].from != "sender@test.com" {
		t.Errorf("from = %q, want sender@test.com", msgs[0].from)
	}
	if len(msgs[0].to) != 1 || msgs[0].to[0] != "recipient@test.com" {
		t.Errorf("to = %v, want [recipient@test.com]", msgs[0].to)
	}
}

func TestSendMessageContainsSubject(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	sender := NewSMTPSender("127.0.0.1", srv.port(), "", "", "s@t.com", AllowPlaintext(true))
	sender.Send(context.Background(), Address{}, "r@t.com", "My Custom Subject", "<b>h</b>", "t")

	msgs := srv.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if !strings.Contains(msgs[0].data, "Subject: My Custom Subject") {
		t.Error("message data should contain the subject")
	}
}

func TestSendMessageContainsHTMLBody(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	sender := NewSMTPSender("127.0.0.1", srv.port(), "", "", "s@t.com", AllowPlaintext(true))
	sender.Send(context.Background(), Address{}, "r@t.com", "Sub", "<h1>Hello HTML</h1>", "text")

	msgs := srv.messages()
	if len(msgs) < 1 {
		t.Fatal("no messages received")
	}
	if !strings.Contains(msgs[0].data, base64.StdEncoding.EncodeToString([]byte("<h1>Hello HTML</h1>"))) {
		t.Error("message data should contain the base64-encoded HTML body")
	}
}

func TestSendMessageContainsTextBody(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	sender := NewSMTPSender("127.0.0.1", srv.port(), "", "", "s@t.com", AllowPlaintext(true))
	sender.Send(context.Background(), Address{}, "r@t.com", "Sub", "<b>h</b>", "Plain text content")

	msgs := srv.messages()
	if len(msgs) < 1 {
		t.Fatal("no messages received")
	}
	// The body is base64-encoded on the wire (Content-Transfer-Encoding: base64).
	if !strings.Contains(msgs[0].data, base64.StdEncoding.EncodeToString([]byte("Plain text content"))) {
		t.Error("message data should contain the base64-encoded text body")
	}
}

func TestSendConnectionRefused(t *testing.T) {
	// Use a port that is not listening
	sender := NewSMTPSender("127.0.0.1", "1", "", "", "s@t.com")
	err := sender.Send(context.Background(), Address{}, "r@t.com", "Sub", "<b>h</b>", "t")
	if err == nil {
		t.Error("Send should fail when connection is refused")
	}
}

func TestSendNoAuth(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	// Empty user means no auth
	sender := NewSMTPSender("127.0.0.1", srv.port(), "", "", "noauth@test.com", AllowPlaintext(true))
	err := sender.Send(context.Background(), Address{}, "r@t.com", "Sub", "<b>h</b>", "t")
	if err != nil {
		t.Fatalf("Send without auth should succeed: %v", err)
	}
}

func TestSendWithAuthAndFromOverride(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	sender := NewSMTPSender("127.0.0.1", srv.port(), "user", "secret", "default@test.com", AllowPlaintext(true))
	err := sender.Send(context.Background(), Address{Email: "tenant@acme.test"}, "r@t.com", "Sub", "<b>h</b>", "t")
	if err != nil {
		t.Fatalf("Send with auth should succeed: %v", err)
	}

	msgs := srv.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].from != "tenant@acme.test" {
		t.Errorf("envelope from = %q, want the per-app override tenant@acme.test", msgs[0].from)
	}

	wantAuth := "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00user\x00secret"))
	auths := srv.authAttempts()
	if len(auths) != 1 || auths[0] != wantAuth {
		t.Errorf("auth exchange = %v, want [%s]", auths, wantAuth)
	}
}

func TestSendContextCanceled(t *testing.T) {
	// A listener that never accepts: the TCP handshake completes via the kernel
	// backlog and the client blocks waiting for the greeting, so the pre-canceled
	// context deterministically wins the select.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	sender := NewSMTPSender("127.0.0.1", port, "", "", "s@t.com")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = sender.Send(ctx, Address{}, "r@t.com", "Sub", "<b>h</b>", "t")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Send with canceled context = %v, want context.Canceled", err)
	}
}

func TestSendMultipleMessages(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	sender := NewSMTPSender("127.0.0.1", srv.port(), "", "", "s@t.com", AllowPlaintext(true))

	for i := 0; i < 3; i++ {
		err := sender.Send(context.Background(), Address{}, fmt.Sprintf("r%d@t.com", i),
			fmt.Sprintf("Subject %d", i), "<b>h</b>", "t")
		if err != nil {
			t.Fatalf("Send %d failed: %v", i, err)
		}
	}

	msgs := srv.messages()
	if len(msgs) != 3 {
		t.Errorf("expected 3 messages, got %d", len(msgs))
	}
}

func TestSendInvalidHost(t *testing.T) {
	sender := NewSMTPSender("nonexistent.invalid.host.example", "587", "", "", "s@t.com")
	err := sender.Send(context.Background(), Address{}, "r@t.com", "Sub", "<b>h</b>", "t")
	if err == nil {
		t.Error("Send should fail with invalid host")
	}
}

// ---------------------------------------------------------------------------
// Template rendering additional tests (~5 subtests)
// ---------------------------------------------------------------------------

func TestRenderTemplateUnknownTemplate(t *testing.T) {
	subject, html, text := currentRenderer().Render("nonexistent_template", TemplateData{AppName: "TestApp"})
	if subject != "Notification" {
		t.Errorf("unknown template subject = %q, want Notification", subject)
	}
	if !strings.Contains(html, "TestApp") {
		t.Error("unknown template HTML should contain app name")
	}
	if !strings.Contains(text, "TestApp") {
		t.Error("unknown template text should contain app name")
	}
}

func TestRenderTemplate2FASetup(t *testing.T) {
	subject, html, text := currentRenderer().Render(Template2FASetup, TemplateData{
		AppName: "VaultTest",
		Code:    "ABC-DEF-GHI",
	})
	if !strings.Contains(subject, "Two-Factor") {
		t.Errorf("2FA setup subject should mention Two-Factor: %q", subject)
	}
	if !strings.Contains(html, "ABC-DEF-GHI") {
		t.Error("2FA setup HTML should contain backup codes")
	}
	if !strings.Contains(text, "ABC-DEF-GHI") {
		t.Error("2FA setup text should contain backup codes")
	}
}

func TestRenderTemplateSuspiciousActivity(t *testing.T) {
	subject, html, text := currentRenderer().Render(TemplateSuspiciousActivity, TemplateData{
		AppName: "VaultTest",
		IP:      "192.168.1.100",
	})
	if !strings.Contains(subject, "Suspicious") {
		t.Errorf("suspicious activity subject should mention Suspicious: %q", subject)
	}
	if !strings.Contains(html, "192.168.1.100") {
		t.Error("suspicious activity HTML should contain IP")
	}
	if !strings.Contains(text, "192.168.1.100") {
		t.Error("suspicious activity text should contain IP")
	}
}

func TestRenderTemplatePasswordResetURL(t *testing.T) {
	_, html, text := currentRenderer().Render(TemplatePasswordReset, TemplateData{
		AppName: "VaultTest",
		URL:     "https://vault.test/reset?token=abc123",
	})
	if !strings.Contains(html, "https://vault.test/reset?token=abc123") {
		t.Error("password reset HTML should contain reset URL")
	}
	if !strings.Contains(text, "https://vault.test/reset?token=abc123") {
		t.Error("password reset text should contain reset URL")
	}
}

func TestRenderTemplateNewDeviceDetails(t *testing.T) {
	_, html, text := currentRenderer().Render(TemplateNewDevice, TemplateData{
		AppName: "VaultTest",
		IP:      "10.0.0.1",
		Device:  "Firefox on Linux",
	})
	if !strings.Contains(html, "10.0.0.1") {
		t.Error("new device HTML should contain IP")
	}
	if !strings.Contains(html, "Firefox on Linux") {
		t.Error("new device HTML should contain device info")
	}
	if !strings.Contains(text, "10.0.0.1") {
		t.Error("new device text should contain IP")
	}
	if !strings.Contains(text, "Firefox on Linux") {
		t.Error("new device text should contain device info")
	}
}
