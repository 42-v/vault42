package sanitize

import (
	"net/mail"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzEmail drives the registration email sanitiser, not the dummy local
// validator in tests/fuzz. The interesting inputs are the erasure tombstone
// (deleted-<uuid>@deleted.invalid), mailbox forms that hide a different
// address, and unicode / punycode / quoted-local-part tricks that
// net/mail.ParseAddress accepts but this function must not store.
func FuzzEmail(f *testing.F) {
	f.Add("user@example.com")
	f.Add("user+tag@example.com")
	f.Add("first.last@sub.example.com")
	f.Add("")
	f.Add("@")
	f.Add("user@")
	f.Add("@domain.example")
	f.Add("user@deleted.invalid")
	f.Add("deleted-3f2504e0-4f89-11d3-9a0c-0305e82c3301@deleted.invalid")
	f.Add("deleted-3f2504e0-4f89-11d3-9a0c-0305e82c3301@Deleted.Invalid")
	f.Add("anything@DELETED.INVALID")
	f.Add("admin <attacker@evil.com>")
	f.Add("<attacker@evil.com>")
	f.Add("a@b.com (comment)")
	f.Add("(comment) a@b.com")
	f.Add(`"quoted local"@example.com`)
	f.Add(`"foo bar"@example.com`)
	f.Add("üser@example.com")
	f.Add("user@xn--n3h.com")
	f.Add("user@exämple.com")
	f.Add("user@[127.0.0.1]")
	f.Add("user@[IPv6:2001:db8::1]")
	f.Add("deleted-user@example.com")
	f.Add("user@deleted.example.com")
	f.Add("\x00@\x00")
	f.Add(strings.Repeat("a", 64) + "@" + strings.Repeat("b", 190) + ".com")
	f.Add("a@" + strings.Repeat("x", 250) + ".com")

	f.Fuzz(func(t *testing.T, email string) {
		ok := Email(email)

		if ok && len(email) > 254 {
			t.Fatalf("accepted an address longer than 254 bytes: %q", email)
		}
		if ok && strings.Contains(email, " ") && !strings.HasPrefix(email, `"`) {
			t.Fatalf("accepted an unquoted address containing a space: %q", email)
		}

		// Tombstone domain is refused in every spelling. EqualFold on the
		// domain is the rule; a substring of the local part is not.
		if at := strings.LastIndexByte(email, '@'); at >= 0 {
			if strings.EqualFold(email[at+1:], "deleted.invalid") && ok {
				t.Fatalf("accepted a tombstone-domain address %q; registering it squats the row erasure will write", email)
			}
		}

		if !ok {
			return
		}

		// An accepted value must be exactly the address ParseAddress extracted.
		// Anything else is a display name or comment that would be stored as
		// the account's email while mail is delivered elsewhere.
		addr, err := mail.ParseAddress(email)
		if err != nil {
			t.Fatalf("Email(%q) = true but mail.ParseAddress rejected it: %v", email, err)
		}
		if addr.Address != email {
			t.Fatalf("Email(%q) = true but ParseAddress extracted %q; the caller stores the input, not the extracted address", email, addr.Address)
		}
	})
}

// FuzzRedirectPath is the same-origin relative-path validator used for
// post-login and emailed verification redirects (the OAuth2-adjacent
// redirect_uri surface on this server).
func FuzzRedirectPath(f *testing.F) {
	f.Add("/")
	f.Add("/dashboard")
	f.Add("/auth/callback?code=abc&state=xyz")
	f.Add("/2fa?tab=totp#webauthn")
	f.Add("")
	f.Add("//evil.com")
	f.Add("/\n//evil.com")
	f.Add("/\t//evil.com")
	f.Add("/..//evil.com")
	f.Add("/.//evil.com")
	f.Add("/app/../../evil.com")
	f.Add("https://evil.com")
	f.Add("javascript:alert(1)")
	f.Add("/foo\\bar")
	f.Add("/foo://bar")
	f.Add("/" + strings.Repeat("a", 255))
	f.Add("/" + strings.Repeat("a", 256))
	f.Add("/\u2028//evil.com")
	f.Add("/\x85//evil.com")
	f.Add("/\x85")

	f.Fuzz(func(t *testing.T, path string) {
		got := RedirectPath(path)
		if got == "" {
			return
		}
		if got != path {
			t.Fatalf("RedirectPath rewrote %q to %q; it must return the input unchanged or empty", path, got)
		}
		if !strings.HasPrefix(got, "/") || strings.HasPrefix(got, "//") {
			t.Fatalf("accepted a non-same-origin path %q", got)
		}
		if strings.Contains(got, "\\") || strings.Contains(got, "://") {
			t.Fatalf("accepted a path with a scheme or backslash: %q", got)
		}
		if strings.ContainsFunc(got, func(r rune) bool {
			return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == '\u2028' || r == '\u2029'
		}) {
			t.Fatalf("accepted a path containing a URL control character: %q", got)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("accepted a non-UTF-8 path: %q", got)
		}
		check := got
		if i := strings.IndexAny(check, "?#"); i >= 0 {
			check = check[:i]
		}
		for _, segment := range strings.Split(check, "/") {
			if segment == "." || segment == ".." {
				t.Fatalf("accepted a path with a dot segment: %q", got)
			}
		}
	})
}
