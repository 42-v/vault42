package httputil

import "strings"

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
