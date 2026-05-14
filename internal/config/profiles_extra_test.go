package config

import "testing"

func TestApplyProfileDefaults_Embedded(t *testing.T) {
	c := &Config{Profile: ProfileEmbedded}
	applyProfileDefaults(c)
	if c.ListenAddr != ":8443" {
		t.Fatalf("ListenAddr = %q, want :8443", c.ListenAddr)
	}
	if c.CacheBackend != "memory" {
		t.Fatalf("CacheBackend = %q, want memory", c.CacheBackend)
	}
	if !c.TLSEnabled {
		t.Fatal("TLSEnabled should default true on embedded")
	}
}

func TestApplyProfileDefaults_Honeypot(t *testing.T) {
	c := &Config{Profile: ProfileHoneypot}
	applyProfileDefaults(c)
	if c.ListenAddr == "" {
		t.Fatal("honeypot profile did not seed ListenAddr")
	}
}
