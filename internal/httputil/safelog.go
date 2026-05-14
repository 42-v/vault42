package httputil

import (
	"net"
	"strings"
)

// SafeLogValue strips control characters (newlines, null bytes, carriage returns,
// tabs) from a string to prevent log injection (CWE-117, OWASP). Use on any
// value logged that could theoretically contain attacker-influenced data.
func SafeLogValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\x00' || r == '\t' {
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
