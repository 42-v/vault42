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

// Load reaches applyProfileDefaults only after parseProfile has refused every
// name outside the four, so this branch answers the other caller: a Config
// assembled in code, where Profile is an ordinary exported string field nothing
// re-checks. Falling through with no defaults would leave the whole security
// baseline at its zero value, which is a plaintext listener with rate limiting
// off on /auth/login and CORS open to every origin. The fallback has to be the
// strict profile and has to say so in Profile, because every profile-keyed
// control downstream compares that field against an exact string.
func TestApplyProfileDefaultsFallsBackToTheProductionBaselineForAnUnknownProfile(t *testing.T) {
	c := &Config{Profile: Profile("staging")}
	applyProfileDefaults(c)

	if c.Profile != ProfileProduction {
		t.Errorf("Profile = %q, want %q; the profile-keyed controls downstream read this field", c.Profile, ProfileProduction)
	}
	if !c.TLSEnabled {
		t.Error("an unknown profile left TLS disabled")
	}
	if !c.RateLimitEnabled {
		t.Error("an unknown profile left rate limiting off on the auth endpoints")
	}
	if c.CORSAllowAll {
		t.Error("an unknown profile left CORS open to every origin")
	}
	if c.AutoMigrate {
		t.Error("an unknown profile enabled auto-migration against the live database")
	}
	if c.CacheBackend != "redis" {
		t.Errorf("CacheBackend = %q, want redis; a per-process cache divides every shared-state control by the replica count", c.CacheBackend)
	}
}
