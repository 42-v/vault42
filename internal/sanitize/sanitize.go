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

// RedirectPath validates a redirect path is safe (relative, no protocol, no double-slash).
func RedirectPath(path string) string {
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "://") || strings.Contains(path, "\\") {
		return ""
	}
	if len(path) > 256 {
		return ""
	}
	return path
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

// Email validates an email address format.
func Email(email string) bool {
	if len(email) > 254 {
		return false
	}
	_, err := mail.ParseAddress(email)
	return err == nil
}
