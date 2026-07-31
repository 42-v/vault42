package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The embedded profile sets REAL_IP_HEADER=X-Forwarded-For, so the "authoritative
// proxy header" is a comma-joined list whose left side is attacker-supplied.
// ClientIP must return a single validated address for every hostile shape, never
// the raw header string.
func TestClientIPRealIPHeaderAlwaysReturnsSingleIP(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	SetRealIPHeader("X-Forwarded-For")
	defer func() {
		SetTrustedProxies(nil)
		SetRealIPHeader("")
	}()

	const remote = "10.0.0.5"

	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{"absent", nil, remote},
		{"empty", []string{""}, remote},
		{"separators only", []string{", ,,"}, remote},
		{"single spoofed entry", []string{"attacker-controlled"}, remote},
		{"not an ip", []string{"evil.example.com"}, remote},
		{"spoofed prefix, proxy appended peer", []string{"attacker-controlled, 203.0.113.9"}, "203.0.113.9"},
		{"spoofed prefix, appended trusted hop", []string{"attacker-controlled, 10.0.0.5"}, remote},
		{"chain with whitespace", []string{"  1.2.3.4 ,   203.0.113.9  "}, "203.0.113.9"},
		{"ipv4 with port", []string{"203.0.113.9:5555"}, "203.0.113.9"},
		{"ipv6 plain", []string{"2001:db8::1"}, "2001:db8::1"},
		{"ipv6 bracketed", []string{"[2001:db8::1]"}, "2001:db8::1"},
		{"ipv6 bracketed with port", []string{"[2001:db8::1]:443"}, "2001:db8::1"},
		{"ipv6 expanded is canonicalised", []string{"2001:0db8:0000:0000:0000:0000:0000:0001"}, "2001:db8::1"},
		{"multiple header lines take the last", []string{"1.2.3.4", "203.0.113.9"}, "203.0.113.9"},
		{"junk tail falls through to the xff walk", []string{"203.0.113.9, junk"}, "203.0.113.9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = remote + ":1234"
			for _, v := range tt.values {
				req.Header.Add("X-Forwarded-For", v)
			}

			got := ClientIP(req)
			if got != tt.want {
				t.Errorf("ClientIP = %q, want %q", got, tt.want)
			}
			if net.ParseIP(got) == nil {
				t.Errorf("ClientIP returned %q, which is not an IP", got)
			}
		})
	}
}

// The rate-limit bucket key is derived from ClientIP, so a client-supplied
// X-Forwarded-For prefix must not change it. If it did, varying the prefix per
// request would mint an unlimited number of buckets and defeat both the rate
// limiter and the IP lockout.
func TestIPRateLimitKeyIgnoresSpoofedXFFPrefix(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	SetRealIPHeader("X-Forwarded-For")
	defer func() {
		SetTrustedProxies(nil)
		SetRealIPHeader("")
	}()

	prefixes := []string{"", "1.1.1.1, ", "2.2.2.2, ", "attacker, ", "9.9.9.9, 8.8.8.8, ", "[::1]:9, "}
	keys := make(map[string]struct{})
	for _, p := range prefixes {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.5:1234"
		req.Header.Set("X-Forwarded-For", p+"203.0.113.9")
		keys[IPRateLimitKey(req)] = struct{}{}
	}

	if len(keys) != 1 {
		t.Fatalf("spoofed XFF prefixes produced %d distinct rate-limit buckets, want 1: %v", len(keys), keys)
	}
	if _, ok := keys["ip:203.0.113.9"]; !ok {
		t.Errorf("bucket key = %v, want ip:203.0.113.9", keys)
	}
}
