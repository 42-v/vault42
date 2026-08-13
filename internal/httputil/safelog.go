package httputil

import (
	"net"
	"strings"
)

// SafeLogValue replaces every character that can forge a log record or drive a
// terminal with '_', to prevent log injection (CWE-117, OWASP). Use on any value
// logged that could theoretically contain attacker-influenced data.
//
// The set is wider than CR/LF/NUL/tab because a log line has two readers and
// each has its own escape hatch. A log shipper splits records on U+0085, U+2028
// and U+2029 as readily as on a newline. A terminal acts on what it is sent:
// ESC opens a control sequence that can clear the screen, reposition the cursor
// over records already printed, or set the window title, U+009B opens the same
// sequence on its own in 8-bit mode, and backspace alone is enough to rewrite a
// line as it is drawn. Neutralizing only the characters that end a line would
// leave an operator's terminal as the injection point.
func SafeLogValue(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f, r == '\u2028', r == '\u2029':
			return '_'
		}
		return r
	}, s)
}

// ObfuscatedIP returns a privacy-preserving rendering of an IP address suitable
// for logs. IPv4 has its last octet zeroed (192.168.1.42 -> 192.168.1.0); IPv6
// has its lower 64 bits zeroed (2001:db8::1 -> 2001:db8::). Returns
// "invalid_ip" for unparseable input. This satisfies CWE-359 / GDPR
// pseudonymization requirements while preserving /24 (or /64) granularity for
// rate-limit and abuse-pattern correlation.
func ObfuscatedIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return "invalid_ip"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}
