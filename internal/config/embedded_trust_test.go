package config

import (
	"testing"
)

// TestEmbeddedTrustedUpstream_AutoFill verifies the one-switch shortcut for
// vault42 deployed behind a sibling reverse proxy on the same private network
// (e.g. Hermod coordinator → vault42 in a microk8s pod). Setting
// VAULT_EMBEDDED_TRUSTED_UPSTREAM=true must auto-trust RFC1918 + IPv6 ULA
// + loopback ranges and pick X-Forwarded-For as the real-IP header — without
// requiring the operator to also set TRUSTED_PROXIES + REAL_IP_HEADER.
func TestEmbeddedTrustedUpstream_AutoFill(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "embedded")
	t.Setenv("VAULT_EMBEDDED_TRUSTED_UPSTREAM", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if !cfg.EmbeddedTrustedUpstream {
		t.Fatalf("EmbeddedTrustedUpstream = false, want true")
	}

	wantCIDRs := map[string]bool{
		"10.0.0.0/8":     true,
		"172.16.0.0/12":  true,
		"192.168.0.0/16": true,
		"fc00::/7":       true,
		"127.0.0.0/8":    true,
		"::1/128":        true,
	}
	if len(cfg.TrustedProxies) != len(wantCIDRs) {
		t.Fatalf("TrustedProxies len = %d, want %d (got %v)", len(cfg.TrustedProxies), len(wantCIDRs), cfg.TrustedProxies)
	}
	for _, got := range cfg.TrustedProxies {
		if !wantCIDRs[got] {
			t.Errorf("unexpected proxy CIDR %q", got)
		}
	}

	if cfg.RealIPHeader != "X-Forwarded-For" {
		t.Errorf("RealIPHeader = %q, want X-Forwarded-For", cfg.RealIPHeader)
	}
}

// TestEmbeddedTrustedUpstream_ExplicitWins guarantees that when the operator
// supplies their own TRUSTED_PROXIES / REAL_IP_HEADER, the embedded shortcut
// does NOT clobber them. Explicit > convenience.
func TestEmbeddedTrustedUpstream_ExplicitWins(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "embedded")
	t.Setenv("VAULT_EMBEDDED_TRUSTED_UPSTREAM", "true")
	t.Setenv("TRUSTED_PROXIES", "10.42.0.0/16")
	t.Setenv("REAL_IP_HEADER", "CF-Connecting-IP")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(cfg.TrustedProxies) != 1 || cfg.TrustedProxies[0] != "10.42.0.0/16" {
		t.Errorf("TrustedProxies = %v, want [10.42.0.0/16]", cfg.TrustedProxies)
	}
	if cfg.RealIPHeader != "CF-Connecting-IP" {
		t.Errorf("RealIPHeader = %q, want CF-Connecting-IP", cfg.RealIPHeader)
	}
}

// TestEmbeddedTrustedUpstream_DisabledLeavesEmpty proves the toggle is
// strictly opt-in: without VAULT_EMBEDDED_TRUSTED_UPSTREAM, no proxies are
// trusted. A misconfigured deployment must fail closed (XFF ignored).
func TestEmbeddedTrustedUpstream_DisabledLeavesEmpty(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "embedded")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.EmbeddedTrustedUpstream {
		t.Errorf("EmbeddedTrustedUpstream = true, want false (default)")
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Errorf("TrustedProxies = %v, want []", cfg.TrustedProxies)
	}
	if cfg.RealIPHeader != "" {
		t.Errorf("RealIPHeader = %q, want \"\"", cfg.RealIPHeader)
	}
}
