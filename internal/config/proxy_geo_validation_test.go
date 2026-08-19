package config

import (
	"strings"
	"testing"
)

// A geo list with no header to read the country from is a control that cannot
// fire.
//
// middleware.IPAccess runs the geo ladder only when GEO_IP_HEADER is set, so
// GEO_BLOCKLIST=RU,CN,KP with no header refuses nobody: every request from
// every country reaches /auth/login, /auth/register and the client-credentials
// grant, and the operator's evidence that the fence exists is the value they
// set. Nothing logged it and /readyz reported healthy.
func TestValidateRefusesAGeoListWithNoHeaderToReadTheCountryFrom(t *testing.T) {
	t.Run("blocklist", func(t *testing.T) {
		c := prodConfig()
		c.GeoBlocklist = []string{"RU", "KP"}
		c.TrustedProxies = []string{"10.0.0.0/8"}

		err := c.Validate()
		if err == nil {
			t.Fatal("a geo blocklist with no GEO_IP_HEADER was accepted; the fence never fires and nothing says so")
		}
		if !strings.Contains(err.Error(), "GEO_IP_HEADER") {
			t.Fatalf("error %q does not name GEO_IP_HEADER", err)
		}
	})

	t.Run("allowlist", func(t *testing.T) {
		c := prodConfig()
		c.GeoAllowlist = []string{"SK"}
		c.TrustedProxies = []string{"10.0.0.0/8"}

		if err := c.Validate(); err == nil {
			t.Fatal("a geo allowlist with no GEO_IP_HEADER was accepted")
		}
	})
}

// The country header is believed only from a trusted hop, the same contract
// ClientIP applies to X-Forwarded-For. With TRUSTED_PROXIES empty the country
// is never read, so a blocklist blocks nobody and an allowlist denies
// everybody: the same configuration is either a silently dead fence or a total
// outage depending on which list the operator wrote, and neither is visible at
// startup.
func TestValidateRefusesAGeoHeaderWithNoTrustedProxyToBelieveItFrom(t *testing.T) {
	c := prodConfig()
	c.GeoIPHeader = "CF-IPCountry"
	c.GeoBlocklist = []string{"RU"}

	err := c.Validate()
	if err == nil {
		t.Fatal("a geo header with no TRUSTED_PROXIES was accepted; middleware never reads the header, so the fence is dead")
	}
	if !strings.Contains(err.Error(), "TRUSTED_PROXIES") {
		t.Fatalf("error %q does not name TRUSTED_PROXIES", err)
	}
}

// The negative control: a complete geo configuration must load. Geo-fencing is
// a supported feature, and a check that refused the working shape would be
// worse than the gap it closes.
func TestACompleteGeoConfigurationValidates(t *testing.T) {
	c := prodConfig()
	c.GeoIPHeader = "CF-IPCountry"
	c.GeoBlocklist = []string{"RU"}
	c.TrustedProxies = []string{"10.0.0.0/8"}

	if err := c.Validate(); err != nil {
		t.Fatalf("a complete geo configuration was rejected: %v", err)
	}
}

// Country codes are ISO 3166-1 alpha-2 and are compared against the header
// value verbatim. GEO_BLOCKLIST=UK matches nothing, because the code for the
// United Kingdom is GB, and an operator reading their own config back sees a
// country they believe is blocked.
func TestLoadRefusesACountryCodeThatIsNotTwoLetters(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("GEO_BLOCKLIST", "RU,CHN")

	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted a three-letter country code; it can never match the header and silently blocks nothing")
	}
	if !strings.Contains(err.Error(), "GEO_BLOCKLIST") {
		t.Fatalf("error %q does not name GEO_BLOCKLIST", err)
	}
}

// Length is not the whole rule. A two-character entry that is not two letters
// passes a length test and still matches nothing, because the middleware
// compares the code against the header value verbatim. GEO_BLOCKLIST=R7 is a
// shifted keystroke away from RU, and the deployment that results refuses
// nobody while the manifest records a country the operator believes is banned.
func TestLoadRefusesATwoCharacterCountryCodeThatIsNotTwoLetters(t *testing.T) {
	tests := []struct {
		key   string
		value string
	}{
		{"GEO_BLOCKLIST", "R7"},
		{"GEO_ALLOWLIST", "S-"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv(tt.key, tt.value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted %s=%q; it can never match the header, so the fence covers nothing", tt.key, tt.value)
			}
			if !strings.Contains(err.Error(), tt.key) {
				t.Errorf("error %q does not name %s", err, tt.key)
			}
			if !strings.Contains(err.Error(), tt.value) {
				t.Errorf("error %q does not quote the offending entry %q", err, tt.value)
			}
			if !strings.Contains(err.Error(), "alpha-2") {
				t.Errorf("error %q does not say what a legal entry looks like", err)
			}
		})
	}
}

// A proxy header nobody is trusted to set is a header that is never read.
// ClientIP falls back to the peer address when TrustedProxies is empty, so
// every client behind the ingress collapses into one rate-limit bucket, one
// lockout counter and one address in the audit log, while the operator's only
// evidence that per-client attribution works is the variable they set. This one
// warns instead of refusing, so the warning is the entire control: without it
// the misconfiguration has no symptom until an incident needs the audit log.
func TestValidateWarnsThatAProxyHeaderWithNoTrustedProxyIsNeverRead(t *testing.T) {
	tests := []struct {
		name string
		set  func(*Config)
		key  string
	}{
		{"client address header", func(c *Config) { c.RealIPHeader = "X-Forwarded-For" }, "REAL_IP_HEADER"},
		{"TLS fingerprint header", func(c *Config) { c.TLSFingerprintHeader = "X-JA3-Fingerprint" }, "VAULT_TLS_FINGERPRINT_HEADER"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := prodConfig()
			tt.set(c)

			var err error
			logged := cliconfigCaptureLog(t, func() { err = c.Validate() })

			if err != nil {
				t.Fatalf("a header with no trusted proxy must warn, not refuse; a running deployment would stop booting on upgrade: %v", err)
			}
			if !strings.Contains(logged, tt.key) {
				t.Errorf("nothing warned that %s is never read; log was:\n%s", tt.key, logged)
			}
			if !strings.Contains(logged, "TRUSTED_PROXIES") {
				t.Errorf("the warning does not name the setting that would fix it; log was:\n%s", logged)
			}
		})
	}

	// The negative control. A warning that fires on the working shape is one an
	// operator learns to scroll past, and this one has to be read.
	t.Run("a trusted proxy silences it", func(t *testing.T) {
		c := prodConfig()
		c.RealIPHeader = "X-Forwarded-For"
		c.TLSFingerprintHeader = "X-JA3-Fingerprint"
		c.TrustedProxies = []string{"10.0.0.0/8"}

		logged := cliconfigCaptureLog(t, func() {
			if err := c.Validate(); err != nil {
				t.Fatalf("a complete proxy configuration was rejected: %v", err)
			}
		})

		if strings.Contains(logged, "REAL_IP_HEADER") || strings.Contains(logged, "VAULT_TLS_FINGERPRINT_HEADER") {
			t.Errorf("a correctly configured proxy still warned; log was:\n%s", logged)
		}
	})
}

// An entry that net.ParseCIDR cannot read is dropped by the middleware with a
// warning that scrolls past during startup. For IP_BLOCKLIST that means the
// range the operator banned is not banned; for TRUSTED_PROXIES it means the
// ingress is not trusted, X-Forwarded-For is ignored, and every client shares
// one rate-limit bucket and one address in the audit log.
func TestLoadRefusesAnAccessListEntryThatIsNotAnAddressOrRange(t *testing.T) {
	tests := []struct {
		key   string
		value string
	}{
		{"IP_BLOCKLIST", "203.0.113.0-203.0.113.255"},
		{"IP_ALLOWLIST", "10.0.0.0/33"},
		{"TRUSTED_PROXIES", "ingress.internal"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "dev")
			t.Setenv(tt.key, tt.value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted %s=%q; the middleware drops it and the control silently covers less than it says", tt.key, tt.value)
			}
			if !strings.Contains(err.Error(), tt.key) {
				t.Fatalf("error %q does not name %s", err, tt.key)
			}
		})
	}
}

// The negative control for the same lists: bare addresses and CIDR ranges, IPv4
// and IPv6, are what real deployments set and must keep loading.
func TestTheAccessListsAcceptBareAddressesAndRanges(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.5, fc00::/7, ::1")
	t.Setenv("IP_ALLOWLIST", "203.0.113.7")
	t.Setenv("IP_BLOCKLIST", "198.51.100.0/24")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load rejected a valid access list: %v", err)
	}
	if len(c.TrustedProxies) != 4 {
		t.Fatalf("TrustedProxies = %v, want 4 entries", c.TrustedProxies)
	}
}
