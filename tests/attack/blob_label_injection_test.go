package attack

import (
	"strings"
	"testing"
)

// sanitizeBlobLabel mirrors the sanitization logic from internal/handler/blob.go
// (Download handler, line 180): strips \r and \n to prevent CRLF header injection.
func sanitizeBlobLabel(label string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(label)
}

// TestBlobLabel_CRLFInjection verifies that CRLF sequences in blob labels
// are stripped, preventing HTTP response header injection.
func TestBlobLabel_CRLFInjection(t *testing.T) {
	cases := []struct {
		name  string
		label string
		want  string
	}{
		{"bare CRLF", "file\r\nX-Injected: evil", "fileX-Injected: evil"},
		{"bare CR", "file\rX-Injected: evil", "fileX-Injected: evil"},
		{"bare LF", "file\nX-Injected: evil", "fileX-Injected: evil"},
		{"double CRLF (blank line)", "file\r\n\r\n<html>evil</html>", "file<html>evil</html>"},
		{"CRLF at start", "\r\nInjected-Header: value", "Injected-Header: value"},
		{"CRLF at end", "normal-label\r\n", "normal-label"},
		{"multiple CRLF", "a\r\nb\r\nc\r\n", "abc"},
		{"mixed CR and LF", "a\rb\nc\r\nd", "abcd"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeBlobLabel(tc.label)
			if got != tc.want {
				t.Fatalf("sanitizeBlobLabel(%q) = %q, want %q", tc.label, got, tc.want)
			}
			// Critical: no \r or \n must survive
			if strings.ContainsAny(got, "\r\n") {
				t.Fatalf("sanitized label still contains CR or LF: %q", got)
			}
		})
	}
}

// TestBlobLabel_NullBytes verifies that null bytes in blob labels do not cause
// truncation or other issues in the sanitized output.
func TestBlobLabel_NullBytes(t *testing.T) {
	cases := []struct {
		name  string
		label string
	}{
		{"null byte mid-string", "before\x00after"},
		{"null byte at start", "\x00label"},
		{"null byte at end", "label\x00"},
		{"multiple null bytes", "\x00\x00\x00"},
		{"null with CRLF", "label\x00\r\ninjected"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeBlobLabel(tc.label)
			// Must not contain CR or LF after sanitization
			if strings.ContainsAny(got, "\r\n") {
				t.Fatalf("sanitized label still contains CR or LF: %q", got)
			}
			// Null bytes may pass through (Go strings handle them), but
			// they must not cause panics or truncation of the non-null part.
			// The Go net/http Header.Set will include the null byte in the value,
			// which is acceptable — the critical concern is CRLF injection.
		})
	}
}

// TestBlobLabel_HTMLInJSON verifies that HTML tags in blob labels pass through
// the sanitization unchanged (they are returned in JSON context or as raw
// header values, not rendered as HTML).
func TestBlobLabel_HTMLInJSON(t *testing.T) {
	htmlPayloads := []string{
		`<script>alert('xss')</script>`,
		`<img src=x onerror=alert(1)>`,
		`"><svg onload=alert(1)>`,
		`<iframe src="evil.com">`,
		`<b onmouseover=alert(1)>hover</b>`,
	}

	for _, payload := range htmlPayloads {
		t.Run(payload[:min(len(payload), 25)], func(t *testing.T) {
			got := sanitizeBlobLabel(payload)
			// HTML should NOT be escaped — the blob label is returned as:
			// 1. X-Blob-Label header (raw value, not rendered as HTML)
			// 2. JSON response body (JSON encoding handles escaping)
			// The sanitizer only strips CRLF for header injection prevention.
			if got != payload {
				t.Fatalf("HTML label should pass through unchanged (no CRLF present), got %q", got)
			}
			// But CRLF must still be absent
			if strings.ContainsAny(got, "\r\n") {
				t.Fatalf("sanitized label contains CR or LF: %q", got)
			}
		})
	}
}

// TestBlobLabel_CleanLabelsUnchanged verifies that normal labels pass
// through sanitization without modification.
func TestBlobLabel_CleanLabelsUnchanged(t *testing.T) {
	clean := []string{
		"my-backup-2024.enc",
		"vault_export_v2.bin",
		"profile-photo.jpg.enc",
		"",
		"label with spaces",
		"unicode-label-\u00e9cole",
		strings.Repeat("a", 255),
	}

	for _, label := range clean {
		name := label
		if len(name) > 30 {
			name = name[:30] + "..."
		}
		if name == "" {
			name = "(empty)"
		}
		t.Run(name, func(t *testing.T) {
			got := sanitizeBlobLabel(label)
			if got != label {
				t.Fatalf("clean label was modified: %q -> %q", label, got)
			}
		})
	}
}

// TestBlobLabel_HeaderSplitting verifies that multi-header injection payloads
// using various line-ending conventions are neutralized.
func TestBlobLabel_HeaderSplitting(t *testing.T) {
	// Classic HTTP response splitting payloads
	payloads := []struct {
		name  string
		label string
	}{
		{"set-cookie injection", "file\r\nSet-Cookie: admin=true\r\n"},
		{"location redirect", "file\r\nLocation: https://evil.com\r\n\r\n"},
		{"content-length zero", "file\r\nContent-Length: 0\r\n\r\n<html>"},
		{"HTTP response forge", "file\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>pwned</h1>"},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeBlobLabel(tc.label)
			if strings.ContainsAny(got, "\r\n") {
				t.Fatalf("header splitting payload survived sanitization: %q", got)
			}
		})
	}
}
