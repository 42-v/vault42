package config

import "testing"

// prodConfig returns a non-dev Config that satisfies all fail-closed checks.
func prodConfig() *Config {
	return &Config{
		Profile:            ProfileProduction,
		HMACSecret:         []byte("0123456789abcdef0123456789abcdef"), // 32 bytes
		Pepper:             "pepper",
		Origin:             "https://vault.test",
		TLSEnabled:         true,
		TLSCertFile:        "/tls/cert.pem",
		TLSKeyFile:         "/tls/key.pem",
		ForceSecureCookies: false,
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
}
