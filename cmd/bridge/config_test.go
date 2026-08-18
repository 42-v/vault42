package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// bridgeEnvKeys is every environment variable LoadConfig reads. Tests clear the
// whole set before setting the ones they care about, so a BRIDGE_* variable that
// happens to be exported in the developer's shell or in CI cannot change what a
// test measures.
var bridgeEnvKeys = []string{
	"BRIDGE_LISTEN_ADDR",
	"BRIDGE_REAL_UPSTREAM",
	"BRIDGE_HONEYPOT_UPSTREAM",
	"BRIDGE_RATE_THRESHOLD",
	"BRIDGE_RATE_WINDOW",
	"BRIDGE_LOGIN_FAIL_THRESHOLD",
	"BRIDGE_LOGIN_FAIL_WINDOW",
	"BRIDGE_FLAG_TTL",
	"BRIDGE_FLAG_THRESHOLD",
	"BRIDGE_WEBHOOK_URL",
	"BRIDGE_ADMIN_TOKEN_FILE",
	"BRIDGE_REDIS_ADDR",
	"BRIDGE_TRUSTED_PROXIES",
	"BRIDGE_REAL_IP_HEADER",
	"BRIDGE_LOG_LEVEL",
	"BRIDGE_STRIP_HEADERS",
}

// clearBridgeEnv blanks every BRIDGE_* variable for the duration of the test.
// LoadConfig treats the empty string as unset everywhere, so blanking is
// equivalent to unsetting and t.Setenv restores the original values afterwards.
func clearBridgeEnv(t *testing.T) {
	t.Helper()
	for _, k := range bridgeEnvKeys {
		t.Setenv(k, "")
	}
}

// setRequiredUpstreams satisfies the two variables LoadConfig refuses to start
// without, so a test can focus on one optional setting at a time.
func setRequiredUpstreams(t *testing.T) {
	t.Helper()
	t.Setenv("BRIDGE_REAL_UPSTREAM", "http://real.internal:8080")
	t.Setenv("BRIDGE_HONEYPOT_UPSTREAM", "http://honeypot.internal:8080")
}

// TestLoadConfigDefaults pins every default in one place. These numbers are the
// deployed behavior of any bridge whose Helm values leave the tuning knobs
// alone, and they are published in docs/bridge.md, so a change to one of them is
// a change to a documented contract and should have to be made deliberately.
func TestLoadConfigDefaults(t *testing.T) {
	clearBridgeEnv(t)
	setRequiredUpstreams(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8080")
	}
	if cfg.RateThreshold != 60 {
		t.Errorf("RateThreshold = %d, want 60", cfg.RateThreshold)
	}
	if cfg.RateWindow != time.Minute {
		t.Errorf("RateWindow = %v, want 1m", cfg.RateWindow)
	}
	if cfg.LoginFailThreshold != 5 {
		t.Errorf("LoginFailThreshold = %d, want 5", cfg.LoginFailThreshold)
	}
	if cfg.LoginFailWindow != 15*time.Minute {
		t.Errorf("LoginFailWindow = %v, want 15m", cfg.LoginFailWindow)
	}
	if cfg.FlagTTL != 24*time.Hour {
		t.Errorf("FlagTTL = %v, want 24h", cfg.FlagTTL)
	}
	if cfg.FlagThreshold != 100 {
		t.Errorf("FlagThreshold = %d, want 100", cfg.FlagThreshold)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}

	// The optional integrations must stay off unless asked for. An admin token
	// that defaulted to anything but empty would be a default credential, and a
	// trusted proxy list that defaulted to non-empty would let clients choose
	// their own apparent IP.
	if cfg.AdminToken != "" {
		t.Errorf("AdminToken = %q, want empty", cfg.AdminToken)
	}
	if cfg.WebhookURL != "" {
		t.Errorf("WebhookURL = %q, want empty", cfg.WebhookURL)
	}
	if cfg.RedisAddr != "" {
		t.Errorf("RedisAddr = %q, want empty", cfg.RedisAddr)
	}
	if cfg.RealIPHeader != "" {
		t.Errorf("RealIPHeader = %q, want empty", cfg.RealIPHeader)
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Errorf("TrustedProxies = %v, want empty", cfg.TrustedProxies)
	}
}

// TestLoadConfigRequiresBothUpstreams keeps the bridge from starting half
// configured. A bridge missing the honeypot upstream would still parse, still
// listen, and then fail every flagged request, which is the one case where
// failing loudly at startup beats failing quietly in production.
func TestLoadConfigRequiresBothUpstreams(t *testing.T) {
	tests := []struct {
		name     string
		real     string
		honeypot string
		wantErr  string
	}{
		{"neither", "", "", "BRIDGE_REAL_UPSTREAM is required"},
		{"only honeypot", "", "http://h:8080", "BRIDGE_REAL_UPSTREAM is required"},
		{"only real", "http://r:8080", "", "BRIDGE_HONEYPOT_UPSTREAM is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearBridgeEnv(t)
			t.Setenv("BRIDGE_REAL_UPSTREAM", tt.real)
			t.Setenv("BRIDGE_HONEYPOT_UPSTREAM", tt.honeypot)

			cfg, err := LoadConfig()
			if err == nil {
				t.Fatalf("LoadConfig = %+v, want error %q", cfg, tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Errorf("error = %q, want %q", err.Error(), tt.wantErr)
			}
			if cfg != nil {
				t.Errorf("LoadConfig returned %+v alongside an error, want nil", cfg)
			}
		})
	}
}

// TestLoadConfigReadsEveryOverride walks the full environment surface in one
// pass, so a newly added variable that is parsed but never wired into Config
// fails here rather than in a deployment.
func TestLoadConfigReadsEveryOverride(t *testing.T) {
	clearBridgeEnv(t)

	t.Setenv("BRIDGE_LISTEN_ADDR", "127.0.0.1:9999")
	t.Setenv("BRIDGE_REAL_UPSTREAM", "http://real:1234")
	t.Setenv("BRIDGE_HONEYPOT_UPSTREAM", "http://honeypot:5678")
	t.Setenv("BRIDGE_RATE_THRESHOLD", "7")
	t.Setenv("BRIDGE_RATE_WINDOW", "45s")
	t.Setenv("BRIDGE_LOGIN_FAIL_THRESHOLD", "3")
	t.Setenv("BRIDGE_LOGIN_FAIL_WINDOW", "2h")
	t.Setenv("BRIDGE_FLAG_TTL", "30m")
	t.Setenv("BRIDGE_FLAG_THRESHOLD", "55")
	t.Setenv("BRIDGE_WEBHOOK_URL", "https://hooks.example.com/bridge")
	t.Setenv("BRIDGE_REDIS_ADDR", "redis.internal:6379")
	t.Setenv("BRIDGE_REAL_IP_HEADER", "CF-Connecting-IP")
	t.Setenv("BRIDGE_LOG_LEVEL", "debug")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"ListenAddr", cfg.ListenAddr, "127.0.0.1:9999"},
		{"RealUpstream", cfg.RealUpstream, "http://real:1234"},
		{"HoneypotUpstream", cfg.HoneypotUpstream, "http://honeypot:5678"},
		{"RateThreshold", cfg.RateThreshold, 7},
		{"RateWindow", cfg.RateWindow, 45 * time.Second},
		{"LoginFailThreshold", cfg.LoginFailThreshold, 3},
		{"LoginFailWindow", cfg.LoginFailWindow, 2 * time.Hour},
		{"FlagTTL", cfg.FlagTTL, 30 * time.Minute},
		{"FlagThreshold", cfg.FlagThreshold, 55},
		{"WebhookURL", cfg.WebhookURL, "https://hooks.example.com/bridge"},
		{"RedisAddr", cfg.RedisAddr, "redis.internal:6379"},
		{"RealIPHeader", cfg.RealIPHeader, "CF-Connecting-IP"},
		{"LogLevel", cfg.LogLevel, "debug"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// TestLoadConfigIgnoresUnparseableNumbers pins a genuinely dangerous behavior
// so that it is at least a known one: a malformed threshold or window is not an
// error, it silently reverts to the default. An operator who writes
// BRIDGE_FLAG_THRESHOLD=1O0 with a letter O gets 100, and an operator who writes
// BRIDGE_RATE_WINDOW=60 without a unit gets one minute by luck rather than by
// parsing. Nothing in the logs says so.
func TestLoadConfigIgnoresUnparseableNumbers(t *testing.T) {
	clearBridgeEnv(t)
	setRequiredUpstreams(t)

	t.Setenv("BRIDGE_RATE_THRESHOLD", "not-a-number")
	t.Setenv("BRIDGE_FLAG_THRESHOLD", "1O0")
	t.Setenv("BRIDGE_RATE_WINDOW", "60")
	t.Setenv("BRIDGE_FLAG_TTL", "one day")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.RateThreshold != 60 {
		t.Errorf("RateThreshold = %d, want the default 60", cfg.RateThreshold)
	}
	if cfg.FlagThreshold != 100 {
		t.Errorf("FlagThreshold = %d, want the default 100", cfg.FlagThreshold)
	}
	if cfg.RateWindow != time.Minute {
		t.Errorf("RateWindow = %v, want the default 1m", cfg.RateWindow)
	}
	if cfg.FlagTTL != 24*time.Hour {
		t.Errorf("FlagTTL = %v, want the default 24h", cfg.FlagTTL)
	}
}

// TestLoadConfigAdminTokenFile covers the _FILE convention and the zeroing that
// follows it. The zeroing is the interesting half: the token is a bearer
// credential for an API that can route arbitrary IPs into the honeypot, and
// leaving it readable in a mounted secret for the life of the pod would hand it
// to anything that can read the container filesystem.
func TestLoadConfigAdminTokenFile(t *testing.T) {
	clearBridgeEnv(t)
	setRequiredUpstreams(t)

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "admin-token")
	const token = "s3cr3t-admin-token"
	// Trailing whitespace is what a here-doc or an editor leaves behind, and it
	// must not become part of the compared secret.
	if err := os.WriteFile(tokenFile, []byte("  "+token+"\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	original, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}

	t.Setenv("BRIDGE_ADMIN_TOKEN_FILE", tokenFile)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.AdminToken != token {
		t.Errorf("AdminToken = %q, want %q", cfg.AdminToken, token)
	}

	after, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("re-read token file: %v", err)
	}
	if len(after) != len(original) {
		t.Errorf("zeroed file is %d bytes, want %d", len(after), len(original))
	}
	for i, b := range after {
		if b != 0 {
			t.Fatalf("byte %d of the zeroed file is %#x, want 0x00; contents %q", i, b, after)
		}
	}
	if strings.Contains(string(after), token) {
		t.Error("the token is still readable on disk after LoadConfig")
	}
}

// TestLoadConfigAdminTokenFileMissing makes an unreadable secret a startup
// failure. Continuing with an empty token would leave the admin API permanently
// rejecting every request, which looks identical to a token mismatch and would
// send an operator hunting the wrong problem.
func TestLoadConfigAdminTokenFileMissing(t *testing.T) {
	clearBridgeEnv(t)
	setRequiredUpstreams(t)
	t.Setenv("BRIDGE_ADMIN_TOKEN_FILE", filepath.Join(t.TempDir(), "does-not-exist"))

	cfg, err := LoadConfig()
	if err == nil {
		t.Fatalf("LoadConfig = %+v, want an error", cfg)
	}
	if !strings.Contains(err.Error(), "reading admin token file") {
		t.Errorf("error = %v, want it to mention reading the admin token file", err)
	}
}

// TestLoadConfigTrustedProxies is the parsing half of the most
// security-sensitive setting in the file. A CIDR that silently failed to parse
// would leave the list shorter than the operator intended, which fails closed,
// while a CIDR accepted too eagerly would let a client choose its own apparent
// IP. LoadConfig therefore has to reject a bad CIDR rather than skip it.
func TestLoadConfigTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []string
		wantErr string
	}{
		{
			name:  "single range",
			value: "10.0.0.0/8",
			want:  []string{"10.0.0.0/8"},
		},
		{
			name:  "several ranges with surrounding whitespace",
			value: " 10.0.0.0/8 , 172.16.0.0/12,192.168.0.0/16 ",
			want:  []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},
		{
			name:  "empty entries are skipped",
			value: "10.0.0.0/8,,  ,127.0.0.0/8",
			want:  []string{"10.0.0.0/8", "127.0.0.0/8"},
		},
		{
			name:  "IPv6",
			value: "2001:db8::/32",
			want:  []string{"2001:db8::/32"},
		},
		{
			name:  "host bits are masked off",
			value: "10.1.2.3/8",
			want:  []string{"10.0.0.0/8"},
		},
		{
			name:    "a bare address is not a CIDR",
			value:   "10.0.0.1",
			wantErr: `invalid trusted proxy CIDR "10.0.0.1"`,
		},
		{
			name:    "nonsense",
			value:   "not-a-cidr",
			wantErr: `invalid trusted proxy CIDR "not-a-cidr"`,
		},
		{
			name:    "one bad entry rejects the whole list",
			value:   "10.0.0.0/8,999.0.0.0/8",
			wantErr: `invalid trusted proxy CIDR "999.0.0.0/8"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearBridgeEnv(t)
			setRequiredUpstreams(t)
			t.Setenv("BRIDGE_TRUSTED_PROXIES", tt.value)

			cfg, err := LoadConfig()

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("LoadConfig = %+v, want error containing %q", cfg, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			var got []string
			for _, n := range cfg.TrustedProxies {
				got = append(got, n.String())
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("TrustedProxies = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEnvOr checks that an exported but empty variable is treated as unset. A
// Kubernetes container that maps an absent ConfigMap key produces exactly that
// shape, and the fallback is what keeps the listener on its documented port.
func TestEnvOr(t *testing.T) {
	t.Setenv("BRIDGE_TEST_ENV_OR", "")
	if got := envOr("BRIDGE_TEST_ENV_OR", "fallback"); got != "fallback" {
		t.Errorf("envOr with an empty value = %q, want %q", got, "fallback")
	}

	t.Setenv("BRIDGE_TEST_ENV_OR", "set")
	if got := envOr("BRIDGE_TEST_ENV_OR", "fallback"); got != "set" {
		t.Errorf("envOr = %q, want %q", got, "set")
	}

	if got := envOr("BRIDGE_TEST_ENV_OR_ABSENT", "fallback"); got != "fallback" {
		t.Errorf("envOr for an absent key = %q, want %q", got, "fallback")
	}
}

func TestEnvInt(t *testing.T) {
	tests := []struct {
		name  string
		value string
		set   bool
		want  int
	}{
		{"absent", "", false, 42},
		{"empty", "", true, 42},
		{"valid", "7", true, 7},
		{"zero is honored, not treated as unset", "0", true, 0},
		{"negative", "-5", true, -5},
		{"trailing space is not a number", "7 ", true, 42},
		{"float", "7.5", true, 42},
		{"nonsense", "many", true, 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const key = "BRIDGE_TEST_ENV_INT"
			if tt.set {
				t.Setenv(key, tt.value)
			} else {
				t.Setenv(key, "")
			}
			if got := envInt(key, 42); got != tt.want {
				t.Errorf("envInt(%q) = %d, want %d", tt.value, got, tt.want)
			}
		})
	}
}

func TestEnvDuration(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{"empty", "", 90 * time.Second},
		{"seconds", "30s", 30 * time.Second},
		{"minutes", "15m", 15 * time.Minute},
		{"hours", "24h", 24 * time.Hour},
		{"compound", "1h30m", 90 * time.Minute},
		{"zero is honored, not treated as unset", "0s", 0},
		{"a bare number has no unit", "60", 90 * time.Second},
		{"nonsense", "a while", 90 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const key = "BRIDGE_TEST_ENV_DURATION"
			t.Setenv(key, tt.value)
			if got := envDuration(key, 90*time.Second); got != tt.want {
				t.Errorf("envDuration(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// BRIDGE_STRIP_HEADERS is the operator's half of the F-18 fix: the bridge
// deletes a fixed list of headers the upstream trusts by peer, and this variable
// names the ones a particular deployment has renamed. It is written by hand into
// a Helm values file or a systemd unit, so it arrives with human spacing —
// entries separated by ", ", a trailing comma, an empty slot left behind after
// an edit.
//
// Every one of those has to be reduced to the bare header name, because
// http.Header.Del canonicalises what it is given and " X-Custom-Fingerprint "
// canonicalises to nothing that matches. An untrimmed entry is not a noisy
// config, it is a header the operator believes is stripped and that arrives at
// the upstream carrying whatever the client put in it.
func TestLoadConfigTrimsStripHeadersAndDropsEmptyEntries(t *testing.T) {
	clearBridgeEnv(t)
	setRequiredUpstreams(t)
	t.Setenv("BRIDGE_STRIP_HEADERS", " X-Custom-Fingerprint ,, X-Edge-Trust,\t,")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	want := []string{"X-Custom-Fingerprint", "X-Edge-Trust"}
	if len(cfg.StripHeaders) != len(want) {
		t.Fatalf("StripHeaders = %q, want %q; empty entries between commas are not header names", cfg.StripHeaders, want)
	}
	for i := range want {
		if cfg.StripHeaders[i] != want[i] {
			t.Fatalf("StripHeaders = %q, want %q", cfg.StripHeaders, want)
		}
	}

	// The parse is only worth anything if the parsed name reaches Header.Del, so
	// the list LoadConfig produced is handed to a real bridge and the forged
	// header has to be gone from what the upstream sees. With the entry
	// untrimmed this assertion is what fails.
	b, headers := testBridge(t, func(c *Config) { c.StripHeaders = cfg.StripHeaders })
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("X-Custom-Fingerprint", "forged-by-the-client")
	req.Header.Set("X-Edge-Trust", "forged-by-the-client")
	b.ServeHTTP(httptest.NewRecorder(), req)

	got := headers()
	if got == nil {
		t.Fatal("the upstream never saw the request")
	}
	for _, h := range want {
		if v := got.Get(h); v != "" {
			t.Errorf("the upstream received %s: %q; an operator-renamed header the client forged reached it", h, v)
		}
	}
}

// An unset BRIDGE_STRIP_HEADERS must leave the list empty rather than holding
// one empty string. A "" in the list is a Del("") on every proxied request, and
// it is also what makes the list look configured to anything that only checks
// its length.
func TestLoadConfigLeavesStripHeadersEmptyWhenUnset(t *testing.T) {
	clearBridgeEnv(t)
	setRequiredUpstreams(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.StripHeaders) != 0 {
		t.Fatalf("StripHeaders = %q with the variable unset, want none", cfg.StripHeaders)
	}
}
