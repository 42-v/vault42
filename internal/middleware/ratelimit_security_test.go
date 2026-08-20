package middleware

import (
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

// The ClientIP cases that used to sit here are rows in TestClientIP
// (ratelimit_coverage_test.go), which is the one table for address resolution.

func TestSetTrustedProxiesInvalidEntry(t *testing.T) {
	SetTrustedProxies([]string{"invalid-not-a-cidr", "10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	if n := len(loadTrustedProxyCIDRs()); n != 1 {
		t.Errorf("stored %d trusted proxy CIDRs, want 1: the unparseable entry should be dropped", n)
	}
	if !isTrustedProxy("10.1.2.3") {
		t.Error("the valid entry stopped working because an unparseable neighbor was in the list")
	}
	// A parse failure that widened the list instead of dropping the entry would
	// make every peer a trusted proxy, which is leftmost XFF trust for anyone.
	if isTrustedProxy("203.0.113.1") {
		t.Error("an address outside the one valid CIDR is trusted, so the invalid entry was not dropped")
	}
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
