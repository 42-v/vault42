package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all bridge configuration. Every field is sourced from a BRIDGE_*
// environment variable named in its doc; see docs/bridge.md for the
// operator-facing reference.
type Config struct {
	// ListenAddr is the bind address for proxied traffic, the decoy pages and
	// the /bridge/* admin and probe endpoints, which all share one listener
	// (BRIDGE_LISTEN_ADDR). Default: ":8080".
	ListenAddr string
	// RealUpstream is the base URL of the real vault, where unflagged traffic
	// goes (BRIDGE_REAL_UPSTREAM). Required.
	RealUpstream string
	// HoneypotUpstream is the base URL of the honeypot vault, where flagged
	// traffic goes (BRIDGE_HONEYPOT_UPSTREAM). Required.
	HoneypotUpstream string
	// RateThreshold is the request count within RateWindow above which an IP
	// takes a scoring penalty (BRIDGE_RATE_THRESHOLD). Default: 60.
	RateThreshold int
	// RateWindow is the sliding window over which requests are counted
	// (BRIDGE_RATE_WINDOW). Default: 1m.
	RateWindow time.Duration
	// LoginFailThreshold is the number of 401s from POST /auth/login within
	// LoginFailWindow before the failures start scoring
	// (BRIDGE_LOGIN_FAIL_THRESHOLD). Default: 5.
	LoginFailThreshold int
	// LoginFailWindow is the sliding window over which login failures are
	// counted (BRIDGE_LOGIN_FAIL_WINDOW). Default: 15m.
	LoginFailWindow time.Duration
	// FlagTTL is how long a flag lasts before an IP is served the real vault
	// again (BRIDGE_FLAG_TTL). Default: 24h. Lowering it shortens the blast
	// radius of a false positive; raising it keeps an attacker in the honeypot
	// across longer campaigns.
	FlagTTL time.Duration
	// FlagThreshold is the accumulated score at which an IP is flagged
	// (BRIDGE_FLAG_THRESHOLD). Default: 100. Scores accumulate without decay,
	// so this is a lifetime budget per IP, not a rate.
	FlagThreshold int
	// WebhookURL receives a JSON notification on each auto-flag and decoy hit
	// (BRIDGE_WEBHOOK_URL). Empty disables notifications.
	WebhookURL string
	// AdminToken is the bearer token guarding /bridge/flag and /bridge/flags,
	// read from the file named by BRIDGE_ADMIN_TOKEN_FILE. LoadConfig
	// overwrites that file with zeros after reading it, so the secret does not
	// outlive startup on disk. Empty fails closed: the admin API rejects every
	// request rather than running unauthenticated.
	AdminToken string
	// RedisAddr enables shared, restart-surviving flag storage
	// (BRIDGE_REDIS_ADDR). Empty keeps flags in this process's memory only,
	// which means a restart clears them and each replica decides alone.
	RedisAddr string
	// TrustedProxies is the set of CIDRs whose RealIPHeader value is believed,
	// parsed from the comma-separated BRIDGE_TRUSTED_PROXIES. Empty means no
	// proxy is trusted and the peer address is always used. Listing a range
	// that is not actually a proxy in front of this bridge lets a client set
	// its own apparent IP, which both evades its own flag and lets it flag
	// someone else's.
	TrustedProxies []*net.IPNet
	// RealIPHeader is the header carrying the client IP when the request
	// arrives from a trusted proxy (BRIDGE_REAL_IP_HEADER). Empty disables
	// header-based client IP entirely.
	RealIPHeader string
	// LogLevel controls log verbosity (BRIDGE_LOG_LEVEL). Default: "info".
	// "debug" additionally logs every routing decision for a flagged IP.
	LogLevel string
	// MaxBodyBytes caps a proxied request body (BRIDGE_MAX_BODY_BYTES).
	//
	// The proxy used to stream whatever the client sent, for as long as
	// ReadTimeout allowed, into an upstream connection it opened concurrently.
	// The default is above the vault's own 10 MiB blob ceiling so this cap
	// never becomes the thing that rejects a legitimate upload; the vault
	// re-applies its own, smaller, limit per route.
	MaxBodyBytes int64
	// MaxInflight caps concurrently proxied requests
	// (BRIDGE_MAX_INFLIGHT). One goroutine and one upstream socket per request
	// with nothing counting them is how a slow upstream turns a request flood
	// into an unbounded connection table. Zero disables the cap.
	MaxInflight int
	// StripHeaders are additional request headers deleted before the request
	// reaches an upstream (BRIDGE_STRIP_HEADERS, comma separated).
	//
	// The bridge is the gateway the vault's trust model assumes: several
	// upstream controls believe a header purely because the peer that sent it
	// is a trusted proxy — the tenant slug, the TLS fingerprint that binds a
	// bearer token to a device, the real-IP header and the geo header. The
	// bridge forwarded all of them verbatim, so a client could supply the
	// values those controls were checking. defaultStrippedHeaders covers the
	// names the vault ships with; this list is for operators who renamed one
	// via VAULT_TLS_FINGERPRINT_HEADER, REAL_IP_HEADER or GEOIP_HEADER.
	StripHeaders []string
}

// LoadConfig reads configuration from environment variables.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		ListenAddr:         envOr("BRIDGE_LISTEN_ADDR", ":8080"),
		RealUpstream:       os.Getenv("BRIDGE_REAL_UPSTREAM"),
		HoneypotUpstream:   os.Getenv("BRIDGE_HONEYPOT_UPSTREAM"),
		RateThreshold:      envInt("BRIDGE_RATE_THRESHOLD", 60),
		RateWindow:         envDuration("BRIDGE_RATE_WINDOW", time.Minute),
		LoginFailThreshold: envInt("BRIDGE_LOGIN_FAIL_THRESHOLD", 5),
		LoginFailWindow:    envDuration("BRIDGE_LOGIN_FAIL_WINDOW", 15*time.Minute),
		FlagTTL:            envDuration("BRIDGE_FLAG_TTL", 24*time.Hour),
		FlagThreshold:      envInt("BRIDGE_FLAG_THRESHOLD", 100),
		WebhookURL:         os.Getenv("BRIDGE_WEBHOOK_URL"),
		RedisAddr:          os.Getenv("BRIDGE_REDIS_ADDR"),
		RealIPHeader:       os.Getenv("BRIDGE_REAL_IP_HEADER"),
		LogLevel:           envOr("BRIDGE_LOG_LEVEL", "info"),
		MaxBodyBytes:       int64(envInt("BRIDGE_MAX_BODY_BYTES", 16<<20)),
		MaxInflight:        envInt("BRIDGE_MAX_INFLIGHT", 512),
	}

	for _, h := range strings.Split(os.Getenv("BRIDGE_STRIP_HEADERS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.StripHeaders = append(cfg.StripHeaders, h)
		}
	}

	if cfg.RealUpstream == "" {
		return nil, fmt.Errorf("BRIDGE_REAL_UPSTREAM is required")
	}
	if cfg.HoneypotUpstream == "" {
		return nil, fmt.Errorf("BRIDGE_HONEYPOT_UPSTREAM is required")
	}

	// Every one of these caps is applied behind a `> 0` guard at the point of
	// use, so a negative value does not lower a limit, it removes it.
	// BRIDGE_MAX_INFLIGHT=-1 leaves nothing counting goroutines or upstream
	// sockets, and BRIDGE_MAX_BODY_BYTES=-1 leaves the proxy streaming whatever a
	// client sends for as long as ReadTimeout allows. An operator typing a
	// negative number is asking for a smaller limit and would get no limit at
	// all, silently, on the process whose whole job is to stand in front of the
	// vault. Zero stays accepted for the concurrency cap alone: that is the
	// documented way to turn it off on purpose.
	if err := cfg.validateBounds(); err != nil {
		return nil, err
	}

	// Load admin token from file (_FILE convention)
	tokenFile := os.Getenv("BRIDGE_ADMIN_TOKEN_FILE")
	if tokenFile != "" {
		data, err := os.ReadFile(tokenFile) // #nosec G304,G703 -- operator-configured path via env var, not user input
		if err != nil {
			return nil, fmt.Errorf("reading admin token file: %w", err)
		}
		cfg.AdminToken = strings.TrimSpace(string(data))
		// Zero the file contents
		_ = os.WriteFile(tokenFile, make([]byte, len(data)), 0o600) // #nosec G703 -- best-effort zeroing
	}

	// Parse trusted proxies
	proxies := os.Getenv("BRIDGE_TRUSTED_PROXIES")
	if proxies != "" {
		for _, cidr := range strings.Split(proxies, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", cidr, err)
			}
			cfg.TrustedProxies = append(cfg.TrustedProxies, network)
		}
	}

	return cfg, nil
}

// validateBounds refuses a configuration whose numbers are outside the range the
// code that reads them assumes.
//
// Every cap in this file is applied by a `> 0` guard — the inflight semaphore at
// proxy.go, the body limit at proxy.go, the scoring thresholds. A negative value
// passes strconv.Atoi, survives LoadConfig, and then turns that guard off:
// BRIDGE_MAX_INFLIGHT=-1 leaves the bridge with no bound on concurrent upstream
// sockets, and BRIDGE_MAX_BODY_BYTES=-1 removes the request-body cap, both while
// the operator is reading a configuration that says the opposite. A typed minus
// sign is not a request to disable a DoS control, and the two ways to ask for
// that deliberately — 0 for the inflight cap, per its own doc — stay available.
//
// Refusing at startup is the only place this can be said. After LoadConfig
// returns there is nothing left to distinguish "the cap is off because the
// operator asked" from "the cap is off because a value was mistyped".
func (c *Config) validateBounds() error {
	for _, f := range []struct {
		env      string
		value    int64
		minimum  int64
		zeroMean string
	}{
		{"BRIDGE_RATE_THRESHOLD", int64(c.RateThreshold), 1, ""},
		{"BRIDGE_LOGIN_FAIL_THRESHOLD", int64(c.LoginFailThreshold), 1, ""},
		{"BRIDGE_FLAG_THRESHOLD", int64(c.FlagThreshold), 1, ""},
		{"BRIDGE_MAX_BODY_BYTES", c.MaxBodyBytes, 1, ""},
		{"BRIDGE_MAX_INFLIGHT", int64(c.MaxInflight), 0, "0 disables the cap"},
	} {
		if f.value >= f.minimum {
			continue
		}
		hint := ""
		if f.zeroMean != "" {
			hint = " (" + f.zeroMean + ")"
		}
		return fmt.Errorf("%s is %d, which is below the minimum of %d%s: the code that reads it "+
			"guards on a positive value, so this silently disables the limit rather than lowering it",
			f.env, f.value, f.minimum, hint)
	}

	for _, f := range []struct {
		env   string
		value time.Duration
	}{
		{"BRIDGE_RATE_WINDOW", c.RateWindow},
		{"BRIDGE_LOGIN_FAIL_WINDOW", c.LoginFailWindow},
		{"BRIDGE_FLAG_TTL", c.FlagTTL},
	} {
		if f.value > 0 {
			continue
		}
		return fmt.Errorf("%s is %v; a window that is not positive makes the counter it bounds "+
			"either always empty or never expiring", f.env, f.value)
	}

	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envInt reads an integer, falling back to the default when the value does not
// parse — and saying so.
//
// The fallback itself is deliberate: a bridge that refuses to start because one
// threshold is mistyped takes the whole edge down. The silence was not. An
// operator who writes BRIDGE_FLAG_THRESHOLD=1O0 with a letter O gets 100 and no
// indication anywhere that the value they set is not the value in force, which
// is how a configuration and a running process come to disagree for months.
func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Printf("WARNING: %s=%q is not an integer; falling back to %d. The value you set is "+
			"not the value in force.", key, v, fallback) // #nosec G706 -- the key is a fixed literal and the value is quoted
		return fallback
	}
	return n
}

// envDuration reads a duration, falling back with the same warning as envInt.
// A value with no unit is the common case: BRIDGE_RATE_WINDOW=60 does not parse,
// and the operator who wrote it meant sixty seconds.
func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("WARNING: %s=%q is not a duration; falling back to %v. A duration needs a unit, "+
			"so 60 is not a minute, 60s is.", key, v, fallback) // #nosec G706 -- the key is a fixed literal and the value is quoted
		return fallback
	}
	return d
}
