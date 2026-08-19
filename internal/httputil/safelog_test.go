package httputil

import "testing"

func TestSafeLogValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"clean", "normal value", "normal value"},
		{"strips crlf null tab", "evil\r\ninjected:Authorization\tBearer foo\x00", "evil__injected:Authorization_Bearer foo_"},
		{"multiple", "a\nb\rc\td\x00e", "a_b_c_d_e"},
		{"only controls", "\r\n\t\x00", "____"},
		{"unicode kept", "café\tline", "café_line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SafeLogValue(tt.input)
			if got != tt.want {
				t.Errorf("SafeLogValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// A log line is read in a terminal, so an escape sequence that survives
// SafeLogValue is acted on rather than displayed. ESC is reachable from an
// unauthenticated request: net/url rejects only raw control bytes in the request
// line, so "GET /auth/%1b%5b2J" arrives with r.URL.Path = "/auth/\x1b[2J", and
// middleware/logger.go puts that path through SafeLogValue on every request. An
// operator tailing the log then has the screen cleared and the cursor moved back
// over earlier records, which lets a remote caller paint over the evidence of
// what it just did.
//
// U+009B is here because it is the C1 single-character CSI introducer: a
// terminal in 8-bit mode acts on it with no ESC in front of it at all. U+0085,
// U+2028 and U+2029 are here because log shippers and JSON viewers treat them as
// record separators, which is the same record-forging outcome as a bare newline.
func TestSafeLogValueNeutralizesEveryCharacterThatCanDriveATerminal(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"escape clears the screen", "user\x1b[2J\x1b[1;1Hforged", "user_[2J_[1;1Hforged"},
		{"escape sets the window title", "user\x1b]0;pwned\x07", "user_]0;pwned_"},
		{"bell", "user\aalert", "user_alert"},
		{"backspace rewrites the line", "admin\b\b\b\b\buser", "admin_____user"},
		{"vertical tab", "user\vsplit", "user_split"},
		{"form feed", "user\fsplit", "user_split"},
		{"delete", "user\x7fx", "user_x"},
		{"c1 csi introducer", "user\u009b2Jforged", "user_2Jforged"},
		{"c1 next line", "user\u0085forged", "user_forged"},
		{"unicode line separator", "user\u2028forged", "user_forged"},
		{"unicode paragraph separator", "user\u2029forged", "user_forged"},
		{"printable latin survives", "café user", "café user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SafeLogValue(tt.input); got != tt.want {
				t.Errorf("SafeLogValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestObfuscatedIP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", "invalid_ip"},
		{"whitespace", "  ", "invalid_ip"},
		{"invalid", "not-an-ip", "invalid_ip"},
		{"ipv4", "203.0.113.42", "203.0.113.0"},
		{"ipv4 with space", " 203.0.113.99 ", "203.0.113.0"},
		{"ipv4 zero", "127.0.0.1", "127.0.0.0"},
		{"ipv6", "2001:db8::cafe:1", "2001:db8::"},
		{"ipv6 full", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::"},
		{"ipv4 mapped", "::ffff:192.0.2.1", "192.0.2.0"},
		// A caller with only r.RemoteAddr in hand has a host:port pair. Before
		// this was handled it fell through to "invalid_ip", so the one function
		// whose job is to keep a full address out of a log line silently threw
		// away the address instead of masking it, and nothing said so.
		{"ipv4 with port", "203.0.113.42:5555", "203.0.113.0"},
		{"ipv6 with port", "[2001:db8::cafe:1]:5555", "2001:db8::"},
		{"host is not an address", "not-an-ip:99", "invalid_ip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ObfuscatedIP(tt.input)
			if got != tt.want {
				t.Errorf("ObfuscatedIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
