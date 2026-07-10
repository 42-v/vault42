package email

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSanitizeHeaderRemovesCRLF(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no injection", "Normal Subject", "Normal Subject"},
		{"CR injection", "Subject\rBcc: attacker@evil.com", "SubjectBcc: attacker@evil.com"},
		{"LF injection", "Subject\nBcc: attacker@evil.com", "SubjectBcc: attacker@evil.com"},
		{"CRLF injection", "Subject\r\nBcc: attacker@evil.com", "SubjectBcc: attacker@evil.com"},
		{"multiple CR", "a\rb\rc", "abc"},
		{"multiple LF", "a\nb\nc", "abc"},
		{"empty string", "", ""},
		{"only CRLF", "\r\n\r\n", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeHeader(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeHeader(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildMIMEMessageSanitizesHeaders(t *testing.T) {
	msg := buildMIMEMessage(
		"sender@example.com\r\nBcc: spy@evil.com",
		"victim@example.com\nBcc: spy@evil.com",
		"Hello\r\nBcc: spy@evil.com",
		"<html>body</html>",
		"text body",
	)

	// The message should NOT contain injected headers
	lines := strings.Split(msg, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Bcc:") {
			t.Errorf("injected Bcc header found: %q", line)
		}
	}

	// Verify legitimate headers are present
	if !strings.Contains(msg, "From: sender@example.com") {
		t.Error("sanitized From header should be present")
	}
	if !strings.Contains(msg, "To: victim@example.com") {
		t.Error("sanitized To header should be present")
	}
	if !strings.Contains(msg, "Subject: Hello") {
		t.Error("sanitized Subject header should be present")
	}
}

func TestBuildMIMEMessageStructure(t *testing.T) {
	msg := buildMIMEMessage("from@test.com", "to@test.com", "Test", "<b>html</b>", "text")

	if !strings.Contains(msg, "MIME-Version: 1.0") {
		t.Error("missing MIME-Version header")
	}
	if !strings.Contains(msg, "Content-Type: multipart/alternative") {
		t.Error("missing multipart/alternative Content-Type")
	}
	if !strings.Contains(msg, "Content-Type: text/plain") {
		t.Error("missing text/plain part")
	}
	if !strings.Contains(msg, "Content-Type: text/html") {
		t.Error("missing text/html part")
	}
	// Bodies are base64-encoded, so the raw content must NOT appear verbatim, and
	// each part must declare base64 transfer encoding.
	if strings.Contains(msg, "<b>html</b>") {
		t.Error("html body appears unencoded; it must be base64 Content-Transfer-Encoding")
	}
	if strings.Count(msg, "Content-Transfer-Encoding: base64") != 2 {
		t.Error("both parts must declare Content-Transfer-Encoding: base64")
	}
	if !strings.Contains(msg, base64.StdEncoding.EncodeToString([]byte("text"))) {
		t.Error("text body not present as base64")
	}
	if !strings.Contains(msg, base64.StdEncoding.EncodeToString([]byte("<b>html</b>"))) {
		t.Error("html body not present as base64")
	}
}
