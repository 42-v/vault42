package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStripPortIPv4(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.2.3.4:8080", "1.2.3.4"},
		{"10.0.0.1:443", "10.0.0.1"},
		{"1.2.3.4", "1.2.3.4"},
	}
	for _, tt := range tests {
		got := stripPort(tt.input)
		if got != tt.want {
			t.Errorf("stripPort(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestStripPortIPv6(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"[::1]:8080", "::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[fe80::1%25eth0]:9090", "fe80::1%25eth0"},
		{"::1", "::1"}, // no port, should return as-is
	}
	for _, tt := range tests {
		got := stripPort(tt.input)
		if got != tt.want {
			t.Errorf("stripPort(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestClientIPNoTrustedProxies(t *testing.T) {
	// When no trusted proxies are configured, XFF should be ignored
	SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")

	ip := ClientIP(req)
	if ip != "1.2.3.4" {
		t.Errorf("ClientIP should return RemoteAddr when no proxies configured, got %q", ip)
	}
}

func TestClientIPTrustedProxy(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.2")

	ip := ClientIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("ClientIP should return first non-trusted IP from XFF, got %q", ip)
	}
}

func TestClientIPUntrustedDirectConnection(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.50:1234" // Not a trusted proxy
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	ip := ClientIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("ClientIP should return RemoteAddr when remote is not trusted, got %q", ip)
	}
}

func TestClientIPIPv6RemoteAddr(t *testing.T) {
	SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:8080"

	ip := ClientIP(req)
	if ip != "::1" {
		t.Errorf("ClientIP should handle IPv6 RemoteAddr, got %q", ip)
	}
}

func TestSetTrustedProxiesInvalidEntry(t *testing.T) {
	// Should not panic on invalid entries, just skip them
	SetTrustedProxies([]string{"invalid-not-a-cidr", "10.0.0.0/8"})

	// Only the valid entry should be stored
	if len(loadTrustedProxyCIDRs()) != 1 {
		t.Errorf("expected 1 trusted proxy CIDR, got %d", len(loadTrustedProxyCIDRs()))
	}

	SetTrustedProxies(nil)
}

func TestSetTrustedProxiesBareIPv6(t *testing.T) {
	SetTrustedProxies([]string{"::1"})
	defer SetTrustedProxies(nil)

	if len(loadTrustedProxyCIDRs()) != 1 {
		t.Errorf("expected 1 trusted proxy CIDR for bare IPv6, got %d", len(loadTrustedProxyCIDRs()))
	}

	if !isTrustedProxy("::1") {
		t.Error("::1 should be a trusted proxy")
	}
}
