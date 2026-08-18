package config

import (
	"strings"
	"testing"
)

// The strict posture is the one a deployment gets without configuring anything,
// because a control an operator has to switch on is a control most deployments
// run without. Dev is the exception and it is an exception about topology
// rather than about rigor: a developer's issuer runs on the local host, which
// is the one address the private-address rule would otherwise refuse.
func TestOutboundPrivateAddressesAreRefusedOutsideDevByDefault(t *testing.T) {
	for _, tc := range []struct {
		profile string
		want    bool
	}{
		{"production", false},
		{"embedded", false},
		{"honeypot", false},
		{"dev", true},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", tc.profile)
			c, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if c.OutboundAllowPrivate != tc.want {
				t.Fatalf("%s profile: OutboundAllowPrivate = %v, want %v", tc.profile, c.OutboundAllowPrivate, tc.want)
			}
		})
	}
}

// An operator whose identity provider is a pod in the same cluster has to be
// able to say so, in either direction: the dev default must be overridable
// downwards as well as the production default upwards, or the variable only
// works for the deployments that already agreed with it.
func TestOutboundPrivateAddressesFollowTheOperatorWhenSet(t *testing.T) {
	t.Run("on in production", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "production")
		t.Setenv("VAULT_OUTBOUND_ALLOW_PRIVATE", "true")
		c, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !c.OutboundAllowPrivate {
			t.Fatal("VAULT_OUTBOUND_ALLOW_PRIVATE=true did not take in the production profile")
		}
	})
	t.Run("off in dev", func(t *testing.T) {
		t.Setenv("VAULT_PROFILE", "dev")
		t.Setenv("VAULT_OUTBOUND_ALLOW_PRIVATE", "false")
		c, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if c.OutboundAllowPrivate {
			t.Fatal("VAULT_OUTBOUND_ALLOW_PRIVATE=false did not take in the dev profile")
		}
	})
}

func TestOutboundAllowedHostsAreNormalizedForComparison(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_OUTBOUND_ALLOWED_HOSTS", " WWW.GoogleAPIs.com , ,keys.okta.test ")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"www.googleapis.com", "keys.okta.test"}
	if len(c.OutboundAllowedHosts) != len(want) {
		t.Fatalf("OutboundAllowedHosts = %q, want %q", c.OutboundAllowedHosts, want)
	}
	for i, h := range want {
		if c.OutboundAllowedHosts[i] != h {
			t.Fatalf("OutboundAllowedHosts[%d] = %q, want %q", i, c.OutboundAllowedHosts[i], h)
		}
	}
}

// Both widenings are legitimate topologies, so neither refuses to boot -- the
// convention warnOnDegradedControls exists for. A deployment already running one
// of them must not stop starting on upgrade; the cost of getting it wrong is a
// weaker deployment rather than an open door.
func TestOutboundWideningsDoNotRefuseToBoot(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_OUTBOUND_ALLOW_PRIVATE", "true")
	t.Setenv("VAULT_OUTBOUND_ALLOWED_HOSTS", "www.googleapis.com")
	if err := loadAndValidate(t); err != nil {
		t.Fatalf("refused to start on two legitimate topologies: %v", err)
	}
}

// What neither widening may do is take effect silently. A deployment reachable
// into its own network, or one that has handed a provider's document a host
// outside the issuer's domain, has to say so where an operator reading startup
// output will see it -- and the strict default must stay quiet, because a
// warning that fires on the safe case is a warning operators learn to skip.
func TestOutboundWideningsWarnAtStartup(t *testing.T) {
	t.Run("private addresses outside dev", func(t *testing.T) {
		logged := cliconfigCaptureLog(t, (&Config{Profile: ProfileProduction, OutboundAllowPrivate: true}).warnOnDegradedControls)
		if !strings.Contains(logged, "SECURITY WARNING") || !strings.Contains(logged, "VAULT_OUTBOUND_ALLOW_PRIVATE") {
			t.Errorf("a production deployment reachable into its own network said nothing at startup; log was:\n%s", logged)
		}
		if !strings.Contains(logged, "production") {
			t.Errorf("the warning does not name the profile it fired in; log was:\n%s", logged)
		}
	})

	t.Run("an allowed host", func(t *testing.T) {
		c := &Config{Profile: ProfileProduction, OutboundAllowedHosts: []string{"www.googleapis.com"}}
		logged := cliconfigCaptureLog(t, c.warnOnDegradedControls)
		if !strings.Contains(logged, "SECURITY WARNING") || !strings.Contains(logged, "www.googleapis.com") {
			t.Errorf("startup said nothing about the host the operator widened to; log was:\n%s", logged)
		}
	})

	t.Run("the strict default says nothing", func(t *testing.T) {
		logged := cliconfigCaptureLog(t, (&Config{Profile: ProfileProduction}).warnOnDegradedControls)
		if strings.Contains(logged, "VAULT_OUTBOUND_ALLOW_PRIVATE") || strings.Contains(logged, "VAULT_OUTBOUND_ALLOWED_HOSTS") {
			t.Errorf("the strict default warned about itself; log was:\n%s", logged)
		}
	})

	t.Run("dev does not warn about its own default", func(t *testing.T) {
		logged := cliconfigCaptureLog(t, (&Config{Profile: ProfileDev, OutboundAllowPrivate: true}).warnOnDegradedControls)
		if strings.Contains(logged, "VAULT_OUTBOUND_ALLOW_PRIVATE") {
			t.Errorf("the dev profile warned about its own default; log was:\n%s", logged)
		}
	})
}
