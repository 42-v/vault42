package httputil

import "testing"

func TestSafeLogValueStripsCRLF(t *testing.T) {
	got := SafeLogValue("evil\r\ninjected:Authorization\tBearer foo\x00")
	want := "evil__injected:Authorization_Bearer foo_"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestObfuscatedIPv4MasksLastOctet(t *testing.T) {
	if got := ObfuscatedIP("203.0.113.42"); got != "203.0.113.0" {
		t.Fatalf("got %q want 203.0.113.0", got)
	}
}

func TestObfuscatedIPv6MasksLower64(t *testing.T) {
	if got := ObfuscatedIP("2001:db8::cafe:1"); got != "2001:db8::" {
		t.Fatalf("got %q want 2001:db8::", got)
	}
}

func TestObfuscatedIPInvalid(t *testing.T) {
	if got := ObfuscatedIP("not-an-ip"); got != "invalid_ip" {
		t.Fatalf("got %q want invalid_ip", got)
	}
}
