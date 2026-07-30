package config

import "testing"

// The dev profile starts from the production baseline, and the production
// baseline resolves booleans with strconv.ParseBool while every other env var
// in this package uses envBool ("true"/"1"/"yes"). Without the explicit
// re-application, a dev operator writing VAULT_RATE_LIMIT_ENABLED=no would get
// the ParseBool fallback (rate limiting on) from one code path and the envBool
// answer (off) from Validate, and the two would disagree about whether the
// deployment is running unprotected.
func TestApplyProfileDefaults_DevHonoursExplicitRateLimitOverride(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want bool
	}{
		{"canonical false", "false", false},
		{"canonical true", "true", true},
		{"numeric off", "0", false},
		{"colloquial off", "no", false},
		{"colloquial on", "yes", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("VAULT_RATE_LIMIT_ENABLED", tt.env)
			c := &Config{Profile: ProfileDev, RateLimitEnabled: !tt.want}
			applyProfileDefaults(c)
			if c.RateLimitEnabled != tt.want {
				t.Fatalf("RateLimitEnabled = %v, want %v for VAULT_RATE_LIMIT_ENABLED=%q",
					c.RateLimitEnabled, tt.want, tt.env)
			}
			if c.RateLimitEnabled != envBool("VAULT_RATE_LIMIT_ENABLED") {
				t.Fatalf("dev profile disagrees with envBool for %q", tt.env)
			}
		})
	}
}

// An unset override must leave the production default (on) in place: the dev
// profile is allowed to relax logging and TTLs, never rate limiting.
func TestApplyProfileDefaults_DevKeepsRateLimitWithoutOverride(t *testing.T) {
	c := &Config{Profile: ProfileDev}
	applyProfileDefaults(c)
	if !c.RateLimitEnabled {
		t.Fatal("dev profile disabled rate limiting without an explicit override")
	}
}
