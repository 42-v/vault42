// Package sanitize provides input validation and sanitization functions for user-supplied data.
package sanitize

import (
	"net/mail"
	"strings"
	"unicode/utf8"
)

var htmlReplacer = strings.NewReplacer("<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")

// String trims whitespace, escapes HTML entities, and truncates to maxLen runes.
// Truncation respects UTF-8 boundaries and avoids splitting HTML entities.
func String(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	s = htmlReplacer.Replace(s)
	if utf8.RuneCountInString(s) > maxLen {
		runes := []rune(s)
		s = string(runes[:maxLen])
		// Walk back past any truncated HTML entity (& without closing ;)
		if i := strings.LastIndex(s, "&"); i >= 0 && !strings.Contains(s[i:], ";") {
			s = s[:i]
		}
	}
	return s
}

// Locale validates and normalizes a BCP 47 locale tag.
// Returns "en" for empty or invalid input.
func Locale(locale string) string {
	locale = strings.TrimSpace(locale)
	if locale == "" {
		return "en"
	}
	if len(locale) > 10 {
		return "en"
	}
	for _, c := range locale {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_') {
			return "en"
		}
	}
	return strings.ToLower(locale)
}

// RedirectPath returns path unchanged when it is provably a same-origin relative
// path, and "" otherwise.
//
// The rules mirror web/src/utils/safeRedirect.ts, the validator that runs last
// before router.push. This one runs first, and its output is what gets baked
// into an emailed verification link, so the two have to agree: a value only this
// side accepts becomes a dead link, and a value only this side accepts that some
// other consumer resolves differently becomes an open redirect.
func RedirectPath(path string) string {
	if path == "" || len(path) > 256 {
		return ""
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return ""
	}
	if strings.Contains(path, "\\") || strings.Contains(path, "://") {
		return ""
	}
	// A browser deletes tab, CR and LF from a URL before it resolves it, so
	// "/\n//evil.com" reaches the parser as "///evil.com": protocol-relative, and
	// off the origin. The rest of C0, DEL, C1 and the Unicode line separators go
	// with them rather than trusting every downstream parser to agree about which
	// of them are stripped, which are rejected, and which pass through.
	if strings.ContainsFunc(path, isURLControl) {
		return ""
	}
	// A dot segment means one thing to a consumer that normalizes ("/..//evil.com"
	// collapses to the protocol-relative "//evil.com" under new URL() and under
	// path.Clean) and another to one that does not. Rejecting is the only reading
	// both agree on, and it is why a single collapsing pass would not do: strip
	// "../" once from "/..././/evil.com" and what is left is "/..//evil.com".
	if hasDotSegment(path) {
		return ""
	}
	return path
}

// isURLControl reports whether r is a character no two URL consumers handle the
// same way: the C0 range, DEL, C1 (0x9b alone opens a control sequence on an
// 8-bit terminal), and the Unicode line separators.
func isURLControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == '\u2028' || r == '\u2029'
}

// hasDotSegment reports whether any segment of the path component is "." or "..".
// The query and fragment are excluded: they are opaque to path resolution, and a
// route legitimately carries them.
func hasDotSegment(path string) bool {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// AvatarURL validates and sanitizes an HTTPS-only URL.
func AvatarURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if !strings.HasPrefix(rawURL, "https://") {
		return ""
	}
	if len(rawURL) > 2048 {
		return ""
	}
	return rawURL
}

// Email reports whether email is an address and nothing else.
//
// net/mail.ParseAddress implements the whole RFC 5322 mailbox grammar, so it
// also accepts "Admin <attacker@evil.com>" and "user@example.com (comment)" and
// returns the address it dug out. Callers store the string they validated rather
// than that extracted address, so anything that is not exactly the address is
// rejected here: otherwise a display name ends up in the email column, shown as
// the account's address while the mail goes elsewhere, and the exact-match
// uniqueness lookup treats it as a second, unrelated account.
func Email(email string) bool {
	if len(email) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	return addr.Address == email
}
