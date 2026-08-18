package main

import (
	"fmt"
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

	// Both caps are applied behind a `> 0` guard at the point of use, so a
	// negative value does not lower them, it removes them. BRIDGE_MAX_INFLIGHT=-1
	// leaves nothing counting goroutines or upstream sockets, and
	// BRIDGE_MAX_BODY_BYTES=-1 leaves the proxy streaming whatever a client sends
	// for as long as ReadTimeout allows. An operator typing a negative number is
	// asking for a smaller limit and would get no limit at all, silently, on the
	// process whose whole job is to stand in front of the vault. Zero stays
	// accepted: it is the documented way to turn the concurrency cap off on
	// purpose.
	if cfg.MaxBodyBytes < 0 {
		return nil, fmt.Errorf("BRIDGE_MAX_BODY_BYTES is %d: a negative value disables the request "+
			"body cap rather than lowering it", cfg.MaxBodyBytes)
	}
	if cfg.MaxInflight < 0 {
		return nil, fmt.Errorf("BRIDGE_MAX_INFLIGHT is %d: a negative value disables the concurrency "+
			"cap rather than lowering it; use 0 to disable it deliberately", cfg.MaxInflight)
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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
