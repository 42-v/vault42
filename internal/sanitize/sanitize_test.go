package sanitize

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"empty", "", 100, ""},
		{"trims whitespace", "  hello  ", 100, "hello"},
		{"escapes angle brackets", "<script>alert(1)</script>", 100, "&lt;script&gt;alert(1)&lt;/script&gt;"},
		{"escapes quotes", `he said "hello" & 'bye'`, 100, `he said &quot;hello&quot; & &#39;bye&#39;`},
		{"truncates to maxLen", "abcdef", 3, "abc"},
		{"exact maxLen", "abc", 3, "abc"},
		{"under maxLen", "ab", 3, "ab"},
		{"zero maxLen", "abc", 0, ""},
		{"trims then escapes", "  <b>  ", 100, "&lt;b&gt;"},
		{"truncates after escape", "<", 4, "&lt;"},
		{"unicode preserved", "caf\u00e9", 10, "caf\u00e9"},
		{"truncates cutting open entity", "foo&bar", 5, "foo"},
		{"truncates leaving & without ;", "x&y&z", 4, "x&y"},
		{"truncate keeps closed entity", "a&b;def", 5, "a&b;d"},
		{"maxLen 1", "x", 1, "x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := String(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("String(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestLocale(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty returns en", "", "en"},
		{"whitespace returns en", "   ", "en"},
		{"valid locale", "sk", "sk"},
		{"uppercase normalized", "EN-US", "en-us"},
		{"underscore allowed", "en_US", "en_us"},
		{"too long returns en", "abcdefghijk", "en"},
		{"numbers rejected", "en1", "en"},
		{"special chars rejected", "en;rm -rf", "en"},
		{"dot rejected", "en.UTF-8", "en"},
		{"slash rejected", "../../etc", "en"},
		{"max valid length", "abcdefghij", "abcdefghij"},
		{"single char", "a", "a"},
		{"hyphen", "en-GB", "en-gb"},
		{"all invalid after check", "en gb", "en"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Locale(tt.input)
			if got != tt.want {
				t.Errorf("Locale(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedirectPath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty returns empty", "", ""},
		{"valid root", "/", "/"},
		{"valid path", "/dashboard", "/dashboard"},
		{"valid nested", "/auth/callback?code=abc", "/auth/callback?code=abc"},
		{"no leading slash", "dashboard", ""},
		{"double slash (open redirect)", "//evil.com", ""},
		{"protocol in path", "/foo://bar", ""},
		{"backslash", "/foo\\bar", ""},
		{"absolute URL", "https://evil.com", ""},
		// The filler is a real path character. These cases were built from
		// string(make([]byte, n)), which is n NUL bytes, so "max valid length"
		// asserted that a path of 255 NULs comes back unchanged: it pinned the
		// missing control-character check as the intended contract, and it would
		// have passed a length check that had been deleted entirely, since a NUL
		// run is rejected on its own merits.
		{"too long", "/" + strings.Repeat("a", 256), ""},
		{"max valid length", "/" + strings.Repeat("a", 255), "/" + strings.Repeat("a", 255)},
		{"query with special", "/p?a=1&b=2", "/p?a=1&b=2"},
		{"empty after no slash", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedirectPath(tt.input)
			if got != tt.want {
				t.Errorf("RedirectPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// The server-side validator has to reject everything the client-side mirror in
// web/src/utils/safeRedirect.ts rejects, because it runs first and its output is
// what gets baked into the emailed verification link. Two rules matter and
// neither is expressible as "contains //".
//
// Control characters: a browser deletes tab, CR and LF from a URL before
// resolving it, so a value of "/\n//evil.com" is parsed as "///evil.com", which
// is protocol-relative and leaves the origin.
//
// Dot segments: "/..//evil.com" means "//evil.com" to any consumer that
// normalizes (new URL(), path.Clean) and "/..//evil.com" to one that does not.
// A validator that disagrees with its consumer about what a string means is a
// validator that can be talked around, so neither reading is accepted.
func TestRedirectPathRejectsWhatABrowserWouldResolveOffOrigin(t *testing.T) {
	hostile := []struct {
		name  string
		input string
	}{
		{"newline before a protocol-relative authority", "/\n//evil.com"},
		{"tab before a protocol-relative authority", "/\t//evil.com"},
		{"crlf before a protocol-relative authority", "/\r\n//evil.com"},
		{"null byte", "/\x00//evil.com"},
		{"escape sequence", "/\x1b[2J"},
		{"unicode line separator", "/\u2028//evil.com"},
		{"c1 next line", "/\u0085//evil.com"},
		{"parent dot segment collapsing to an authority", "/..//evil.com"},
		{"current dot segment", "/.//evil.com"},
		{"parent segment mid-path", "/app/../../evil.com"},
		{"trailing parent segment", "/app/.."},
		{"nested dot segment that survives one strip", "/..././/evil.com"},
	}
	for _, tt := range hostile {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedirectPath(tt.input); got != "" {
				t.Errorf("RedirectPath(%q) = %q, want \"\"; this value does not mean "+
					"the same thing to every consumer that resolves it", tt.input, got)
			}
		})
	}
}

// The rejections above must not cost the app its real deep links. A validator
// that fails closed on everything is not a validator, it is an outage: the
// verification mail would drop its redirect and land every new account on the
// generic page instead of the one it was invited to.
func TestRedirectPathStillAcceptsTheDeepLinksTheAppGenerates(t *testing.T) {
	for _, path := range []string{
		"/",
		"/dashboard",
		"/settings/security/2fa",
		"/2fa?tab=totp#webauthn",
		"/auth/callback?code=abc&state=xyz",
		"/storage/files/report.2026.pdf",
	} {
		if got := RedirectPath(path); got != path {
			t.Errorf("RedirectPath(%q) = %q, want it returned unchanged; this is a "+
				"route the app itself emits", path, got)
		}
	}
}

func TestAvatarURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty returns empty", "", ""},
		{"whitespace returns empty", "   ", ""},
		{"valid https", "https://example.com/avatar.png", "https://example.com/avatar.png"},
		{"http rejected", "http://example.com/avatar.png", ""},
		{"no protocol", "example.com/avatar.png", ""},
		{"javascript rejected", "javascript:alert(1)", ""},
		{"data rejected", "data:image/png;base64,abc", ""},
		{"too long", "https://" + string(make([]byte, 2048)), ""},
		{"max valid length", "https://x" + string(make([]byte, 2038)), "https://x" + string(make([]byte, 2038))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AvatarURL(tt.input)
			if got != tt.want {
				t.Errorf("AvatarURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Email answers a question about the string it was given, not about the address
// buried inside it.
//
// net/mail.ParseAddress implements the full RFC 5322 mailbox grammar, so it
// happily parses "admin <attacker@evil.com>" and hands back the inner address.
// The only caller, AuthService.Register in internal/service/auth.go, does not
// look at what parsing extracted: it stores the string it validated. Accepting
// the mailbox forms therefore writes a display name into the users.email column,
// where it becomes the address rendered in the profile and the account UI while
// the mail goes somewhere else entirely. It also splits the uniqueness check,
// since "admin <a@b.com>" and "a@b.com" are different rows to an exact-match
// lookup.
func TestEmailRejectsTheMailboxFormsThatHideADifferentAddress(t *testing.T) {
	hostile := []struct {
		name  string
		input string
	}{
		{"display name in front of the real address", "admin <attacker@evil.com>"},
		{"angle brackets alone", "<attacker@evil.com>"},
		{"display name with spaces", "Attacker Name <a@b.com>"},
		{"rfc 5322 comment after the address", "a@b.com (comment)"},
		{"comment before the address", "(comment) a@b.com"},
	}
	for _, tt := range hostile {
		t.Run(tt.name, func(t *testing.T) {
			if Email(tt.input) {
				t.Errorf("Email(%q) = true; the caller stores this whole string as the "+
					"user's address, so it must be an address and nothing else", tt.input)
			}
		})
	}
}

func TestEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid email", "user@example.com", true},
		{"valid with plus", "user+tag@example.com", true},
		{"valid with dots", "first.last@example.com", true},
		{"valid subdomain", "user@sub.example.com", true},
		{"empty", "", false},
		{"no at sign", "userexample.com", false},
		{"no domain", "user@", false},
		{"no local", "@example.com", false},
		{"spaces", "user @example.com", false},
		{"too long", string(make([]byte, 250)) + "@a.com", false},
		{"long exactly 254 ok if parse", "a@" + string(make([]byte, 250)) + ".com", false}, // will fail parse anyway or len
		{"valid longish", "user@ex.com", true},
		{"trailing dot domain rejected by parse", "u@ex.com.", false},
		{"exactly 254 len boundary", "u@" + string(make([]byte, 250)) + ".co", false},
		{"simple valid", "a@b.co", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Email(tt.input)
			if got != tt.want {
				t.Errorf("Email(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
