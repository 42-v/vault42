package config

import (
	"strings"
	"testing"
)

// The shipped chart leaves trustedProxies empty and sets neither proxy header,
// which is the configuration that costs the most and announced itself the least:
// ClientIP falls back to the peer address, so behind an ingress every client in
// the deployment shares one source, and the per-source account lockout collapses
// into an account-wide lock at the low threshold.
//
// The warning used to be nested inside the loop over the two header settings, so
// it could only fire for an operator who had already set one of them. The default
// deployment — the one that most needs telling — got nothing.
func TestAnEmptyTrustedProxiesWarnsOnItsOwn(t *testing.T) {
	c := &Config{}
	out := cliconfigCaptureLog(t, c.warnOnDegradedControls)

	if !strings.Contains(out, "TRUSTED_PROXIES is empty") {
		t.Errorf("a config with no trusted proxies and no headers set logged no warning about it:\n%s", out)
	}
	if !strings.Contains(out, "lockout") {
		t.Errorf("the warning does not name the lockout consequence, which is the sharp one:\n%s", out)
	}
}

// The header-specific lines are still worth emitting — a header that is set and
// never read is its own mistake — but they are an additional detail now, not the
// trigger.
func TestAHeaderSetWithoutTrustedProxiesIsStillNamed(t *testing.T) {
	c := &Config{RealIPHeader: "X-Real-IP"}
	out := cliconfigCaptureLog(t, c.warnOnDegradedControls)

	if !strings.Contains(out, "REAL_IP_HEADER is set but TRUSTED_PROXIES is empty") {
		t.Errorf("a header set with no trusted proxies was not named:\n%s", out)
	}
}

// A deployment that has configured its proxies gets neither line. The warning is
// about a real degradation, so firing it unconditionally would train operators to
// ignore it.
func TestAConfiguredTrustedProxyListWarnsAboutNeither(t *testing.T) {
	c := &Config{TrustedProxies: []string{"10.0.0.0/8"}, RealIPHeader: "X-Real-IP"}
	out := cliconfigCaptureLog(t, c.warnOnDegradedControls)

	if strings.Contains(out, "TRUSTED_PROXIES is empty") {
		t.Errorf("a configured proxy list still warned about an empty one:\n%s", out)
	}
}
