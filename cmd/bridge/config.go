package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all bridge configuration.
type Config struct {
	ListenAddr         string
	RealUpstream       string
	HoneypotUpstream   string
	RateThreshold      int
	RateWindow         time.Duration
	LoginFailThreshold int
	LoginFailWindow    time.Duration
	FlagTTL            time.Duration
	FlagThreshold      int
	WebhookURL         string
	AdminToken         string
	RedisAddr          string
	TrustedProxies     []*net.IPNet
	RealIPHeader       string
	LogLevel           string
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
	}

	if cfg.RealUpstream == "" {
		return nil, fmt.Errorf("BRIDGE_REAL_UPSTREAM is required")
	}
	if cfg.HoneypotUpstream == "" {
		return nil, fmt.Errorf("BRIDGE_HONEYPOT_UPSTREAM is required")
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
