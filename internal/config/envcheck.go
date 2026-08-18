package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// This file is the gate between what an operator wrote and what this service
// believes. Every value the package reads is checked here before Load builds a
// Config. The alternative shape, parsing leniently and then comparing the
// result against one exact string somewhere downstream, is how CACHE_BACKEND=Redis
// became a per-process cache on four replicas with no error, no log line and a
// healthy /readyz.
//
// Two rules hold everywhere below:
//
//   - An unset or empty value means "the profile decides". Helm renders an
//     omitted value as "", so treating empty as a parse failure would turn every
//     chart with an unset optional setting into a boot loop.
//   - A value that is set but cannot be honored refuses to start. Silently
//     substituting a default there is indistinguishable, from outside the
//     process, from the operator having configured nothing at all.
//
// Values reach log.Fatalf through the returned error, so every one of them is
// quoted (CWE-117).

// boolEnvVars is every environment variable this package reads as a boolean.
// checkEnvValues walks it so an unrecognized spelling refuses to start; the
// helpers that read these variables (envBool, envBoolDefault, setDefaultBool)
// all resolve them through parseBoolEnv, so no two code paths can disagree
// about what a given spelling means.
//
// VAULT_SECRET_FILE_CONSUME is deliberately absent: consumeSecretFile keeps its
// exact-match test because the cost of guessing that one wrong is a destroyed
// keyfile rather than a missing control.
//
// TestEveryBooleanEnvironmentVariableIsRegistered parses this package and fails
// if a call site names a variable that is missing here.
var boolEnvVars = []string{
	"CORS_ALLOW_ALL",
	"VAULT_ALLOW_PLAINTEXT",
	"VAULT_ALLOW_RATE_LIMIT_DISABLED",
	"VAULT_AUTO_MIGRATE",
	"VAULT_DPOP_ENABLED",
	"VAULT_EMBEDDED_TRUSTED_UPSTREAM",
	"VAULT_FORCE_SECURE_COOKIES",
	"VAULT_HIBP_CHECK",
	"VAULT_KEY_ROTATION_DB",
	"VAULT_METRICS_ENABLED",
	"VAULT_MFA_REQUIRED",
	"VAULT_MINT_ENABLED",
	"VAULT_RATE_LIMIT_ENABLED",
	"VAULT_REGISTRATION_ENABLED",
	"VAULT_SERVE_FRONTEND",
	"VAULT_SMTP_ALLOW_PLAINTEXT",
	"VAULT_STRICT_SESSION_LIMIT",
	"VAULT_SVCDOC_ENABLED",
	"VAULT_SVCDOC_SHARED_ENABLED",
	"VAULT_TLS_ENABLED",
}

// durationEnvVars is every duration this package reads, with the lower bound
// each one's consumer can survive. A duration that is set but negative is never
// what an operator meant, and every consumer here reads a negative as "already
// in the past": a negative token TTL signs tokens that are expired on issue.
var durationEnvVars = map[string]time.Duration{
	"VAULT_ACCESS_TOKEN_TTL":     0,
	"VAULT_AUDIT_FLUSH_INTERVAL": 0,
	"VAULT_KEY_RETENTION_PERIOD": 0,
	"VAULT_MAX_SESSION_LIFETIME": 0,
	"VAULT_MINT_MAX_TTL":         0,
	"VAULT_MINT_TOKEN_TTL":       0,
	"VAULT_REFRESH_TOKEN_TTL":    0,
	"VAULT_REMEMBER_ME_TTL":      0,
	"VAULT_SHUTDOWN_TIMEOUT":     0,

	// keystore.StartRefreshLoop hands this to time.NewTicker, which panics on a
	// non-positive interval, in a goroutine started after the listener is up.
	"VAULT_KEY_REFRESH_INTERVAL": time.Nanosecond,
}

// intEnvVars is every integer this package reads, with its lower bound. Zero is
// a documented "use the profile default" or "no limit" for all of them; a
// negative is a typo that either disables a control or reaches a consumer that
// clamps it back to a default the operator never chose.
var intEnvVars = map[string]int{
	"DB_MAX_CONNS":                  0,
	"VAULT_AUDIT_BUFFER_SIZE":       0,
	"VAULT_AUDIT_RETENTION_DAYS":    0,
	"VAULT_BLOB_MAX_PER_USER":       0,
	"VAULT_BLOB_MAX_SIZE":           0,
	"VAULT_BLOB_MIN_SIZE":           0,
	"VAULT_BLOB_QUOTA_BYTES":        0,
	"VAULT_MAX_EMAIL_TEMPLATE_SIZE": 0,
	"VAULT_MAX_SESSIONS_PER_USER":   0,
	"VAULT_PASSWORD_MIN_LENGTH":     1,
	"VAULT_RECOVERY_RETENTION_DAYS": 0,
	"VAULT_SVCDOC_MAX_PER_SUBJECT":  0,
	"VAULT_SVCDOC_MAX_SIZE":         0,
	"VAULT_SVCDOC_QUOTA_BYTES":      0,
}

// enumEnvVars is every setting with a closed set of legal values, mapped to
// that set. Each of these is compared against an exact string somewhere
// downstream: cache.NewCache switches on the backend name, cmd/vault switches
// on the email provider, pgconn switches on the SSL mode. A near-miss spelling
// silently selects the default branch of somebody's switch.
var enumEnvVars = map[string][]string{
	"CACHE_BACKEND":        {"redis", "memory", "postgres"},
	"DB_SSLMODE":           {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"},
	"VAULT_EMAIL_PROVIDER": {"smtp", "sendgrid"},
}

// encryptedSSLModes are the DB_SSLMODE values that guarantee the connection is
// encrypted. "prefer" is absent on purpose: it asks for TLS and falls back to
// plaintext without an error when the server does not offer it.
var encryptedSSLModes = []string{"require", "verify-ca", "verify-full"}

// cidrEnvVars is every comma-separated list of addresses or ranges.
// middleware.SetTrustedProxies and parseCIDRList drop an entry they cannot
// parse and carry on, so a malformed entry means the list covers less than the
// operator wrote: a range that is not blocked, or an ingress that is not
// trusted and therefore an X-Forwarded-For that is ignored.
var cidrEnvVars = []string{"TRUSTED_PROXIES", "IP_ALLOWLIST", "IP_BLOCKLIST"}

// countryEnvVars is every list of ISO 3166-1 alpha-2 codes. The middleware
// compares them against the header value verbatim, so anything that is not two
// letters can never match: GEO_BLOCKLIST=UK blocks nothing, because the code
// for the United Kingdom is GB.
var countryEnvVars = []string{"GEO_ALLOWLIST", "GEO_BLOCKLIST"}

// checkEnvValues reports every environment variable that is set to something
// this service cannot honor. All of them are reported together: an operator
// fixing a manifest should not need one restart per typo.
func checkEnvValues() error {
	var errs []error

	for _, key := range boolEnvVars {
		if _, _, err := parseBoolEnv(key); err != nil {
			errs = append(errs, err)
		}
	}

	for key, lowest := range durationEnvVars {
		raw, ok := lookupEnvValue(key)
		if !ok {
			continue
		}
		d, err := time.ParseDuration(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s must be a duration such as 15m or 720h (got %q)", key, raw))
			continue
		}
		if d < lowest {
			errs = append(errs, fmt.Errorf("%s must be at least %s (got %q)", key, lowest, raw))
		}
	}

	for key, lowest := range intEnvVars {
		raw, ok := lookupEnvValue(key)
		if !ok {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s must be a whole number (got %q)", key, raw))
			continue
		}
		if n < lowest {
			errs = append(errs, fmt.Errorf("%s must be at least %d (got %q)", key, lowest, raw))
		}
	}

	for key, allowed := range enumEnvVars {
		raw, ok := lookupEnvValue(key)
		if !ok {
			continue
		}
		if !slices.Contains(allowed, raw) {
			errs = append(errs, fmt.Errorf("%s must be one of %s (got %q)", key, strings.Join(allowed, ", "), raw))
		}
	}

	for _, key := range cidrEnvVars {
		for _, entry := range splitList(os.Getenv(key)) {
			if !isAddressOrRange(entry) {
				errs = append(errs, fmt.Errorf("%s entry %q is not an IP address or CIDR range", key, entry))
			}
		}
	}

	for _, key := range countryEnvVars {
		for _, entry := range splitList(os.Getenv(key)) {
			if !isCountryCode(entry) {
				errs = append(errs, fmt.Errorf("%s entry %q is not an ISO 3166-1 alpha-2 country code", key, entry))
			}
		}
	}

	return errors.Join(errs...)
}

// lookupEnvValue returns the trimmed value of key and whether it carries one.
// An unset variable and one set to whitespace are the same thing: the profile
// default applies.
func lookupEnvValue(key string) (string, bool) {
	v := strings.TrimSpace(os.Getenv(key))
	return v, v != ""
}

// parseBoolEnv resolves a boolean environment variable. It is the only place
// this package decides what a boolean value means.
//
// The two parsers it replaces accepted different sets. One took "true", "1"
// and "yes"; the other took strconv.ParseBool's "true", "t", "TRUE", "1". Each
// answered false, or "use the default", for everything outside its own set. VAULT_MFA_REQUIRED=True was therefore an MFA requirement that did not
// exist, and VAULT_AUTO_MIGRATE=no on the embedded profile was a migration the
// operator had refused.
func parseBoolEnv(key string) (value, set bool, err error) {
	raw, ok := lookupEnvValue(key)
	if !ok {
		return false, false, nil
	}
	switch strings.ToLower(raw) {
	case "true", "t", "yes", "y", "on", "1":
		return true, true, nil
	case "false", "f", "no", "n", "off", "0":
		return false, true, nil
	}
	return false, false, fmt.Errorf("%s must be true/false, yes/no, on/off or 1/0 (got %q)", key, raw)
}

// parseProfile resolves VAULT_PROFILE.
//
// An unrecognized value used to become the production profile silently. That is
// the strict profile, so most of the damage was a confusing boot failure, with
// one exception that mattered: every profile-keyed control compares against an
// exact string, so VAULT_PROFILE=Honeypot produced a deployment where
// server.go never mounted the honeypot alerter and the trap accounts sat there
// notifying nobody.
//
// Case and surrounding space are normalized rather than refused, because a
// correct name in the wrong case is the operator's intent, and a deployment
// that has been running on it must not turn into a boot loop on upgrade.
func parseProfile(raw string) (Profile, error) {
	switch p := Profile(strings.ToLower(strings.TrimSpace(raw))); p {
	case "":
		return ProfileProduction, nil
	case ProfileProduction, ProfileEmbedded, ProfileDev, ProfileHoneypot:
		return p, nil
	default:
		return "", fmt.Errorf("VAULT_PROFILE must be one of %s, %s, %s, %s (got %q)",
			ProfileProduction, ProfileEmbedded, ProfileDev, ProfileHoneypot, raw)
	}
}

// splitList splits a comma-separated setting into trimmed, non-empty entries.
func splitList(s string) []string {
	var out []string
	for _, raw := range strings.Split(s, ",") {
		if v := strings.TrimSpace(raw); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// isAddressOrRange accepts what middleware.SetTrustedProxies and parseCIDRList
// accept: a CIDR range, or a bare address they normalize to a /32 or /128.
func isAddressOrRange(entry string) bool {
	if strings.Contains(entry, "/") {
		_, _, err := net.ParseCIDR(entry)
		return err == nil
	}
	return net.ParseIP(entry) != nil
}

// isCountryCode reports whether entry is two ASCII letters.
func isCountryCode(entry string) bool {
	if len(entry) != 2 {
		return false
	}
	for _, c := range entry {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}
