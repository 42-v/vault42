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
