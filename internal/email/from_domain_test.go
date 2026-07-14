package email

import (
	"strings"
	"testing"
)

// fromDomainAllowed gates the per-app From address in white-label email. It is a
// spoofing control: a tenant supplies its own From, and without this gate it
// could send mail as any domain the server can reach — including the operator's.
// The parsing matters as much as the allowlist, because a display name or a
// quoted local part can carry a second, different address.
func TestFromDomainAllowed(t *testing.T) {
	m := NewMailer(nil, nil, nil, Branding{}, []string{"example.com", "Mail.EXAMPLE.org"})

	tests := []struct {
		name string
		addr string
		want bool
	}{
		{"plain address on an allowed domain", "noreply@example.com", true},
		{"display-name wrapper on an allowed domain", "Vault <noreply@example.com>", true},
		{"the allowlist is case-insensitive", "noreply@MAIL.EXAMPLE.ORG", true},

		{"a domain that is not on the list", "noreply@evil.com", false},
		{"a subdomain is not the domain", "noreply@mail.example.com", false},

		// The smuggling cases: the string contains an allowed domain, but the
		// address that would actually be used is not on the list.
		{"allowed domain hidden in the display name", "noreply@example.com <attacker@evil.com>", false},
		{"allowed domain in a quoted local part", `"noreply@example.com"@evil.com`, false},

		{"unparseable", "not-an-address", false},
		{"empty", "", false},
		{"no domain part", "noreply@", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.fromDomainAllowed(tc.addr); got != tc.want {
				t.Errorf("fromDomainAllowed(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// With no allowlist configured the gate must be closed, not open: an operator who
// has not opted in to per-app From addresses must not silently get them.
func TestFromDomainAllowed_FailsClosedWithNoAllowlist(t *testing.T) {
	m := NewMailer(nil, nil, nil, Branding{}, nil)

	if m.fromDomainAllowed("noreply@example.com") {
		t.Error("an unconfigured allowlist allowed a per-app From address")
	}
}

// base64MIMEBody wraps at 76 columns per RFC 2045. A body that is not wrapped is
// rejected or mangled by strict MTAs, so the wrapping is not cosmetic.
func TestBase64MIMEBody_WrapsAt76Columns(t *testing.T) {
	long := strings.Repeat("vault42 white-label email body. ", 40)
	out := base64MIMEBody(long)

	if !strings.HasSuffix(out, "\r\n") {
		t.Error("body must end with CRLF")
	}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\r\n"), "\r\n") {
		if len(line) > 76 {
			t.Errorf("line of %d chars exceeds the 76-column MIME limit", len(line))
		}
	}

	// Short input must still be terminated, and must not be split.
	short := base64MIMEBody("hi")
	if strings.Count(short, "\r\n") != 1 {
		t.Errorf("short body was wrapped or left unterminated: %q", short)
	}
}
