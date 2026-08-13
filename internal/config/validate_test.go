package config

import "testing"

// prodConfig returns a non-dev Config that satisfies all fail-closed checks.
func prodConfig() *Config {
	return &Config{
		Profile:            ProfileProduction,
		HMACSecret:         []byte("0123456789abcdef0123456789abcdef"), // 32 bytes
		Pepper:             "0123456789abcdef0123456789abcdef",         // 32 bytes
		MasterKey:          []byte("0123456789abcdef0123456789abcdef"), // 32 bytes
		Origin:             "https://vault.test",
		TLSEnabled:         true,
		TLSCertFile:        "/tls/cert.pem",
		TLSKeyFile:         "/tls/key.pem",
		ForceSecureCookies: false,
		RateLimitEnabled:   true,
	}
}

func TestValidate(t *testing.T) {
	t.Run("valid production passes", func(t *testing.T) {
		if err := prodConfig().Validate(); err != nil {
			t.Fatalf("valid production config should pass: %v", err)
		}
	})

	t.Run("dev profile skips all checks", func(t *testing.T) {
		if err := (&Config{Profile: ProfileDev}).Validate(); err != nil {
			t.Fatalf("dev profile should always validate: %v", err)
		}
	})

	t.Run("missing HMAC secret (M6)", func(t *testing.T) {
		c := prodConfig()
		c.HMACSecret = nil
		if err := c.Validate(); err == nil {
			t.Fatal("missing HMAC secret must fail")
		}
	})

	t.Run("short HMAC secret (M6)", func(t *testing.T) {
		c := prodConfig()
		c.HMACSecret = []byte("too-short")
		if err := c.Validate(); err == nil {
			t.Fatal("sub-32-byte HMAC secret must fail")
		}
	})

	t.Run("missing pepper (M6)", func(t *testing.T) {
		c := prodConfig()
		c.Pepper = ""
		if err := c.Validate(); err == nil {
			t.Fatal("missing pepper must fail")
		}
	})

	t.Run("short pepper must fail", func(t *testing.T) {
		c := prodConfig()
		c.Pepper = "tooshort"
		if err := c.Validate(); err == nil {
			t.Fatal("sub-32-byte pepper must fail")
		}
	})

	t.Run("rate limiting disabled in prod fails", func(t *testing.T) {
		c := prodConfig()
		c.RateLimitEnabled = false
		if err := c.Validate(); err == nil {
			t.Fatal("disabled rate limiting must fail in production without override")
		}
	})

	t.Run("missing origin (L3)", func(t *testing.T) {
		c := prodConfig()
		c.Origin = ""
		if err := c.Validate(); err == nil {
			t.Fatal("missing origin must fail")
		}
	})

	t.Run("TLS disabled without override (M5)", func(t *testing.T) {
		c := prodConfig()
		c.TLSEnabled = false
		if err := c.Validate(); err == nil {
			t.Fatal("disabling TLS without override must fail")
		}
	})

	t.Run("TLS disabled with ForceSecureCookies escape hatch (M5)", func(t *testing.T) {
		c := prodConfig()
		c.TLSEnabled = false
		c.ForceSecureCookies = true
		if err := c.Validate(); err != nil {
			t.Fatalf("ForceSecureCookies should allow plaintext (proxy termination): %v", err)
		}
	})

	t.Run("TLS enabled without cert (M4)", func(t *testing.T) {
		c := prodConfig()
		c.TLSCertFile = ""
		if err := c.Validate(); err == nil {
			t.Fatal("TLS enabled without cert must fail")
		}
	})

	t.Run("missing master key in production", func(t *testing.T) {
		c := prodConfig()
		c.MasterKey = nil
		err := c.Validate()
		if err == nil {
			t.Fatal("production must refuse to start without MASTER_KEY_FILE")
		}
		if want := "MASTER_KEY_FILE required"; !contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	})

	t.Run("short master key in production", func(t *testing.T) {
		c := prodConfig()
		c.MasterKey = []byte("too-short")
		if err := c.Validate(); err == nil {
			t.Fatal("production must refuse a master key that is not 32 bytes")
		}
	})

	t.Run("oversized master key in production", func(t *testing.T) {
		c := prodConfig()
		c.MasterKey = make([]byte, 33)
		if err := c.Validate(); err == nil {
			t.Fatal("production must refuse a master key that is not 32 bytes")
		}
	})
}

// TestValidateMasterKeyIsProductionOnly pins that the master-key boot check
// is the production profile's, not a non-dev check. Embedded, honeypot and
// dev still start without one (TOTP / identity / blobs then fail at request
// time). Production must not: it is the one secret HMAC and pepper already
// refused at startup.
func TestValidateMasterKeyIsProductionOnly(t *testing.T) {
	base := func(p Profile) *Config {
		c := prodConfig()
		c.Profile = p
		c.MasterKey = nil
		return c
	}

	if err := base(ProfileProduction).Validate(); err == nil {
		t.Fatal("production accepted an empty master key")
	}

	for _, p := range []Profile{ProfileDev, ProfileEmbedded, ProfileHoneypot} {
		if err := base(p).Validate(); err != nil {
			t.Errorf("%s profile refused an empty master key: %v", p, err)
		}
	}
}
