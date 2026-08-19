package httputil

import (
	"context"
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
//
// A "host:port" pair is accepted and masked as its host, because that is the
// shape of r.RemoteAddr and a caller who has only that should not have to
// remember to split it first. Rejecting it would be the worse failure of the
// two: the address would be replaced by "invalid_ip" rather than by its
// network, so the line would lose its diagnostic without anything reporting a
// problem.
func ObfuscatedIP(s string) string {
	s = strings.TrimSpace(s)
	ip := net.ParseIP(s)
	if ip == nil {
		if host, _, err := net.SplitHostPort(s); err == nil {
			ip = net.ParseIP(host)
		}
	}
	if ip == nil {
		return "invalid_ip"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

// clientIPCtxKey is the request-context slot holding the address the edge
// resolved for this request.
type clientIPCtxKey struct{}

// WithClientIP returns a context carrying the resolved client address.
//
// It lives here rather than in the middleware package so the service layer,
// which only ever receives a context, can key per-source state on the same
// address the rate limiter used without importing the HTTP middleware.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPCtxKey{}, ip)
}

// ClientIPFromContext returns the address WithClientIP stored, or "" when the
// context did not come through the HTTP edge (background sweepers, CLI, tests).
//
// An empty result must always be safe to act on: it means "source unknown", not
// "source trusted".
func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPCtxKey{}).(string)
	return ip
}
