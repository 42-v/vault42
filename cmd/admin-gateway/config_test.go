package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// gatewayEnvVars is every environment variable LoadConfig reads. Tests blank
// the whole list before setting the handful they care about, so a variable that
// happens to be exported in the developer's shell cannot change the result. The
// list is also the reason a new configuration knob cannot be added silently: an
// unlisted variable leaks between test cases and the failure points here.
var gatewayEnvVars = []string{
	"ADMIN_GW_LISTEN_ADDR",
	"ADMIN_GW_TLS_CERT_FILE",
	"ADMIN_GW_TLS_KEY_FILE",
	"ADMIN_GW_CLIENT_CA_FILE",
	"ADMIN_GW_SESSION_TTL",
	"ADMIN_GW_MAX_FAILED_LOGINS",
	"ADMIN_GW_LOCKOUT_DURATION",
	"ADMIN_GW_AUTO_MIGRATE",
	"ADMIN_GW_SHUTDOWN_TIMEOUT",
	"ADMIN_GW_DEV_MODE",
	"ADMIN_GW_KILLSWITCH",
	"DB_HOST",
	"DB_PORT",
	"DB_NAME",
	"DB_SSLMODE",
	"DB_MAX_CONNS",
	"VAULT_SEED_FILE",
	"MASTER_KEY_FILE",
	"DB_ADMIN_PASSWORD_FILE",
	"VAULT_PEPPER_FILE",
	"HMAC_SECRET_FILE",
	"VAULT_RECOVERY_PUBLIC_KEY_FILE",
}

// minimalEnv blanks the gateway environment and then sets the four values
// LoadConfig refuses to start without, leaving every other setting on its
// default. t.Setenv restores the previous values when the test ends.
func minimalEnv(t *testing.T) {
	t.Helper()
	for _, k := range gatewayEnvVars {
		t.Setenv(k, "")
	}
	t.Setenv("ADMIN_GW_TLS_CERT_FILE", "/tls/server.crt")
	t.Setenv("ADMIN_GW_TLS_KEY_FILE", "/tls/server.key")
	t.Setenv("ADMIN_GW_CLIENT_CA_FILE", "/tls/client-ca.crt")
	t.Setenv("MASTER_KEY_FILE", writeSecret(t, "master-key", []byte(testMasterKey)))
}

// TestLoadConfigDefaults pins the values an operator gets when they set nothing
// beyond the mandatory TLS paths and master key.
//
// These defaults are the gateway's security posture in the absence of
// configuration: loopback-only binding, mTLS, a killswitch that is on unless
// dev mode turns it off, and a connection pool small enough that the admin
// plane cannot starve the user-facing server of database connections. Changing
// any of them is a deployment-visible decision, so each is asserted by value
// rather than by "not empty".
func TestLoadConfigDefaults(t *testing.T) {
	minimalEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"ListenAddr", cfg.ListenAddr, "127.0.0.1:9443"},
		{"SessionTTL", cfg.SessionTTL, time.Hour},
		{"MaxFailed", cfg.MaxFailed, 5},
		{"LockoutDur", cfg.LockoutDur, 30 * time.Minute},
		{"DBHost", cfg.DBHost, "localhost"},
		{"DBPort", cfg.DBPort, "5432"},
		{"DBName", cfg.DBName, "vault"},
		{"DBSSLMode", cfg.DBSSLMode, "require"},
		{"DBMaxConns", cfg.DBMaxConns, 5},
		{"AutoMigrate", cfg.AutoMigrate, false},
		{"ShutdownTimeout", cfg.ShutdownTimeout, 15 * time.Second},
		{"SeedFile", cfg.SeedFile, ""},
		{"DevMode", cfg.DevMode, false},
		{"Killswitch", cfg.Killswitch, true},
		{"Pepper", cfg.Pepper, ""},
		{"DBPassword", cfg.DBPassword, ""},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	if string(cfg.MasterKey) != testMasterKey {
		t.Errorf("MasterKey = %q, want %q", cfg.MasterKey, testMasterKey)
	}
	if len(cfg.HMACSecret) != 0 {
		t.Errorf("HMACSecret = %q, want empty", cfg.HMACSecret)
	}
	if len(cfg.RecoveryPublicKeyPEM) != 0 {
		t.Errorf("RecoveryPublicKeyPEM = %q, want empty", cfg.RecoveryPublicKeyPEM)
	}
}

// TestLoadConfigOverrides checks that every tunable is actually read from its
// documented variable.
//
// The risk this covers is a copy-paste in the struct literal: two fields
// reading the same variable, or a field reading a variable that no longer
// matches docs/config.md. Values are chosen to be distinct from both the
// defaults and from each other so a crossed wire cannot pass.
func TestLoadConfigOverrides(t *testing.T) {
	minimalEnv(t)

	seed := writeSecret(t, "seed.json", []byte(`{"admins":[]}`))
	t.Setenv("ADMIN_GW_LISTEN_ADDR", "[::1]:19443")
	t.Setenv("ADMIN_GW_SESSION_TTL", "7m")
	t.Setenv("ADMIN_GW_MAX_FAILED_LOGINS", "11")
	t.Setenv("ADMIN_GW_LOCKOUT_DURATION", "13m")
	t.Setenv("ADMIN_GW_AUTO_MIGRATE", "yes")
	t.Setenv("ADMIN_GW_SHUTDOWN_TIMEOUT", "3s")
	t.Setenv("DB_HOST", "db.internal")
	t.Setenv("DB_PORT", "6543")
	t.Setenv("DB_NAME", "vaultdb")
	t.Setenv("DB_SSLMODE", "verify-full")
	t.Setenv("DB_MAX_CONNS", "17")
	t.Setenv("VAULT_SEED_FILE", seed)
	t.Setenv("DB_ADMIN_PASSWORD_FILE", writeSecret(t, "db-admin", []byte("s3cret")))
	t.Setenv("VAULT_PEPPER_FILE", writeSecret(t, "pepper", []byte("peppercorn")))
	t.Setenv("HMAC_SECRET_FILE", writeSecret(t, "hmac", []byte("hmackey")))
	t.Setenv("VAULT_RECOVERY_PUBLIC_KEY_FILE", writeSecret(t, "recovery.pem", []byte("-----BEGIN PUBLIC KEY-----")))

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"ListenAddr", cfg.ListenAddr, "[::1]:19443"},
		{"SessionTTL", cfg.SessionTTL, 7 * time.Minute},
		{"MaxFailed", cfg.MaxFailed, 11},
		{"LockoutDur", cfg.LockoutDur, 13 * time.Minute},
		{"AutoMigrate", cfg.AutoMigrate, true},
		{"ShutdownTimeout", cfg.ShutdownTimeout, 3 * time.Second},
		{"DBHost", cfg.DBHost, "db.internal"},
		{"DBPort", cfg.DBPort, "6543"},
		{"DBName", cfg.DBName, "vaultdb"},
		{"DBSSLMode", cfg.DBSSLMode, "verify-full"},
		{"DBMaxConns", cfg.DBMaxConns, 17},
		{"SeedFile", cfg.SeedFile, seed},
		{"DBPassword", cfg.DBPassword, "s3cret"},
		{"Pepper", cfg.Pepper, "peppercorn"},
		{"HMACSecret", string(cfg.HMACSecret), "hmackey"},
		{"RecoveryPublicKeyPEM", string(cfg.RecoveryPublicKeyPEM), "-----BEGIN PUBLIC KEY-----"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// TestLoadConfigRequiredSettings covers the refusals that keep a
// misconfigured gateway from ever reaching the network.
//
// Each of these is a fail-closed check. Dropping one would not break any happy
// path: the process would start and only then discover it has no server
// certificate, no client CA to verify operators against, or no key to encrypt
// admin TOTP secrets with. The listen-address case is the load-bearing one.
// The gateway holds the vault_admin role, so a build that let it bind a
// non-loopback interface would put the admin plane on the network with nothing
// but mTLS in front of it.
func TestLoadConfigRequiredSettings(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T)
		wantErr string
	}{
		{
			name:    "server certificate path is mandatory",
			mutate:  func(t *testing.T) { t.Setenv("ADMIN_GW_TLS_CERT_FILE", "") },
			wantErr: "ADMIN_GW_TLS_CERT_FILE is required",
		},
		{
			name:    "server key path is mandatory",
			mutate:  func(t *testing.T) { t.Setenv("ADMIN_GW_TLS_KEY_FILE", "") },
			wantErr: "ADMIN_GW_TLS_KEY_FILE is required",
		},
		{
			name:    "client CA path is mandatory",
			mutate:  func(t *testing.T) { t.Setenv("ADMIN_GW_CLIENT_CA_FILE", "") },
			wantErr: "ADMIN_GW_CLIENT_CA_FILE is required",
		},
		{
			name:    "master key file must be set",
			mutate:  func(t *testing.T) { t.Setenv("MASTER_KEY_FILE", "") },
			wantErr: "MASTER_KEY_FILE is required",
		},
		{
			name: "master key file must exist",
			mutate: func(t *testing.T) {
				t.Setenv("MASTER_KEY_FILE", filepath.Join(t.TempDir(), "absent"))
			},
			wantErr: "MASTER_KEY_FILE is required",
		},
		{
			name: "master key must be 32 bytes",
			mutate: func(t *testing.T) {
				t.Setenv("MASTER_KEY_FILE", writeSecret(t, "short", []byte("too-short")))
			},
			wantErr: "32 bytes for AES-256",
		},
		{
			name:    "wildcard bind is rejected",
			mutate:  func(t *testing.T) { t.Setenv("ADMIN_GW_LISTEN_ADDR", "0.0.0.0:9443") },
			wantErr: `must bind to loopback (127.0.0.1 or [::1]), got "0.0.0.0:9443"`,
		},
		{
			name:    "bare port bind is rejected",
			mutate:  func(t *testing.T) { t.Setenv("ADMIN_GW_LISTEN_ADDR", ":9443") },
			wantErr: "must bind to loopback",
		},
		{
			name:    "routable address is rejected",
			mutate:  func(t *testing.T) { t.Setenv("ADMIN_GW_LISTEN_ADDR", "10.0.0.5:9443") },
			wantErr: "must bind to loopback",
		},
		{
			name:    "host that merely starts with 127 is rejected",
			mutate:  func(t *testing.T) { t.Setenv("ADMIN_GW_LISTEN_ADDR", "127.0.0.1.evil.example:9443") },
			wantErr: "must bind to loopback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			minimalEnv(t)
			tt.mutate(t)

			cfg, err := LoadConfig()
			if err == nil {
				t.Fatalf("LoadConfig succeeded, want error containing %q (cfg=%+v)", tt.wantErr, cfg)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("LoadConfig error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestLoadConfigAcceptsLoopbackForms records which spellings of "loopback" get
// past the bind check.
//
// The check is a prefix match on three strings, so it is narrower than the set
// of addresses the kernel treats as loopback: 127.0.0.2 is a loopback address
// the gateway will not bind. That is a safe direction to be wrong in, and it is
// pinned here so a future rewrite to a net.IP.IsLoopback test is a deliberate
// widening rather than an accident.
func TestLoadConfigAcceptsLoopbackForms(t *testing.T) {
	tests := []struct {
		addr   string
		accept bool
	}{
		{"127.0.0.1:9443", true},
		{"[::1]:9443", true},
		{"localhost:9443", true},
		{"127.0.0.2:9443", false},
		{"[::]:9443", false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			minimalEnv(t)
			t.Setenv("ADMIN_GW_LISTEN_ADDR", tt.addr)

			cfg, err := LoadConfig()
			switch {
			case tt.accept && err != nil:
				t.Fatalf("LoadConfig(%q) = %v, want success", tt.addr, err)
			case tt.accept && cfg.ListenAddr != tt.addr:
				t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, tt.addr)
			case !tt.accept && err == nil:
				t.Fatalf("LoadConfig(%q) succeeded, want the loopback check to reject it", tt.addr)
			}
		})
	}
}

// TestLoadConfigDevModeRelaxesBindCheck covers the one escape hatch from the
// loopback rule.
//
// Dev mode exists so the gateway can be reached through a Kubernetes ingress
// during development, which means it disables the single control that keeps the
// admin plane off the network. It therefore also turns the killswitch default
// off, since a pod behind an ingress sees non-loopback peers by design and
// would otherwise crash-loop. Both halves are asserted together because
// enabling one without the other is what makes a dev cluster unusable or a
// production cluster unsafe.
func TestLoadConfigDevModeRelaxesBindCheck(t *testing.T) {
	minimalEnv(t)
	t.Setenv("ADMIN_GW_DEV_MODE", "true")
	t.Setenv("ADMIN_GW_LISTEN_ADDR", "0.0.0.0:9443")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig in dev mode: %v", err)
	}
	if !cfg.DevMode {
		t.Error("DevMode = false, want true")
	}
	if cfg.ListenAddr != "0.0.0.0:9443" {
		t.Errorf("ListenAddr = %q, want the non-loopback address to be accepted", cfg.ListenAddr)
	}
	if cfg.Killswitch {
		t.Error("Killswitch = true in dev mode, want it defaulted off")
	}
}

// TestLoadConfigDevModeOnlyAcceptsTrue records that the dev-mode switch is
// stricter than every other boolean the gateway reads.
//
// envBool accepts "true", "1" and "yes", but the dev-mode test is a literal
// comparison against "true". An operator who writes ADMIN_GW_DEV_MODE=1 by
// analogy with ADMIN_GW_AUTO_MIGRATE=1 gets production behavior: the loopback
// check stays on and so does the killswitch. Failing closed is the right
// default for a control that disables a network restriction, so this pins the
// asymmetry rather than calling it a bug.
func TestLoadConfigDevModeOnlyAcceptsTrue(t *testing.T) {
	for _, value := range []string{"1", "yes", "TRUE", "True", "on"} {
		t.Run(value, func(t *testing.T) {
			minimalEnv(t)
			t.Setenv("ADMIN_GW_DEV_MODE", value)
			t.Setenv("ADMIN_GW_LISTEN_ADDR", "0.0.0.0:9443")

			if _, err := LoadConfig(); err == nil {
				t.Fatalf("ADMIN_GW_DEV_MODE=%q enabled dev mode, want only the exact string \"true\" to do so", value)
			}
		})
	}
}

// TestLoadConfigKillswitch covers the parse of the control that turns a
// non-loopback request into a process crash.
//
// The killswitch is the gateway's tripwire: rather than answering 403 to a
// request that arrived from off-box, it panics so the breach attempt surfaces
// as a CrashLoopBackOff instead of a line in a log nobody reads. The default
// therefore has to be on. The subtlety worth pinning is that an explicitly set
// but unrecognized value turns the tripwire OFF, so ADMIN_GW_KILLSWITCH=True,
// ADMIN_GW_KILLSWITCH=on and a typo all silently disable it. See
// TestLoadConfigKillswitchFailsOpenOnUnrecognizedValue.
func TestLoadConfigKillswitch(t *testing.T) {
	tests := []struct {
		name    string
		devMode bool
		value   string
		set     bool
		want    bool
	}{
		{name: "on by default", want: true},
		{name: "off by default in dev mode", devMode: true, want: false},
		{name: "true", value: "true", set: true, want: true},
		{name: "1", value: "1", set: true, want: true},
		{name: "yes", value: "yes", set: true, want: true},
		{name: "false", value: "false", set: true, want: false},
		{name: "explicit value overrides dev mode", devMode: true, value: "true", set: true, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			minimalEnv(t)
			if tt.devMode {
				t.Setenv("ADMIN_GW_DEV_MODE", "true")
			}
			if tt.set {
				t.Setenv("ADMIN_GW_KILLSWITCH", tt.value)
			}

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if cfg.Killswitch != tt.want {
				t.Errorf("Killswitch = %v, want %v", cfg.Killswitch, tt.want)
			}
		})
	}
}

// TestLoadConfigKillswitchFailsOpenOnUnrecognizedValue documents a real
// footgun in the killswitch parse.
//
// Setting the variable to anything outside {true, 1, yes} disables the
// killswitch, including capitalizations that every other tool in the stack
// accepts. The unset default is "on", so an operator who tries to be explicit
// about wanting the killswitch and writes ADMIN_GW_KILLSWITCH=True ends up
// weaker than one who left the variable alone. The behavior is asserted here
// so that a fix, or a decision that this is intended, is a visible change to
// this test rather than an unnoticed change in posture.
func TestLoadConfigKillswitchFailsOpenOnUnrecognizedValue(t *testing.T) {
	for _, value := range []string{"True", "TRUE", "YES", "on", "enabled", "tru"} {
		t.Run(value, func(t *testing.T) {
			minimalEnv(t)
			t.Setenv("ADMIN_GW_KILLSWITCH", value)

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if cfg.Killswitch {
				t.Fatalf("ADMIN_GW_KILLSWITCH=%q kept the killswitch on; update this test if the parse was widened", value)
			}
		})
	}
}

// TestLoadConfigAcceptsGeneratedMasterKeyEndingInWhitespaceByte is the inverted
// form of a regression test that used to pin the defect.
//
// scripts/generate-secrets.sh writes the master key as 32 raw bytes from
// `openssl rand 32`, and loadSecret runs strings.TrimSpace over whatever it
// reads. Six of the 256 possible byte values are ASCII whitespace, so roughly
// one generated key in twenty-two began or ended with a byte the trim ate. The
// key on disk was correct and exactly 32 bytes, and the gateway reported
// "MASTER_KEY_FILE is required (32 bytes for AES-256)" and refused to start,
// which reads as a missing file rather than a corrupted read.
//
// The master key now loads through config.LoadSecretBinary, which does not trim
// and treats the length as the contract. The key is asserted byte for byte
// rather than just accepted, because a loader that quietly substituted a
// different 32 bytes would pass a mere non-error check.
func TestLoadConfigAcceptsGeneratedMasterKeyEndingInWhitespaceByte(t *testing.T) {
	for _, b := range []byte{'\t', '\n', '\v', '\f', '\r', ' '} {
		t.Run(string([]byte{b}), func(t *testing.T) {
			key := make([]byte, 32)
			for i := range key {
				key[i] = 'k'
			}
			key[31] = b

			minimalEnv(t)
			t.Setenv("MASTER_KEY_FILE", writeSecret(t, "master-key", key))

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig rejected a valid 32-byte master key ending in %q: %v", b, err)
			}
			if !bytes.Equal(cfg.MasterKey, key) {
				t.Fatalf("master key came back altered:\n got %x\nwant %x", cfg.MasterKey, key)
			}
		})
	}
}

// TestDatabaseURL pins the connection string the gateway builds.
//
// The role name is the point. The gateway is a separate binary precisely
// because it connects as vault_admin, a more privileged role than the vault_app
// role the user-facing server uses, so a change that silently swapped the role
// would either break the admin plane or hand the public server admin rights.
func TestDatabaseURL(t *testing.T) {
	cfg := &Config{
		DBPassword: "hunter2",
		DBHost:     "db.internal",
		DBPort:     "6543",
		DBName:     "vaultdb",
		DBSSLMode:  "verify-full",
	}

	got := cfg.DatabaseURL()
	want := "postgres://vault_admin:hunter2@db.internal:6543/vaultdb?sslmode=verify-full"
	if got != want {
		t.Fatalf("DatabaseURL() = %q, want %q", got, want)
	}
}

// TestDatabaseURLDoesNotEscapePassword documents a second real defect.
//
// The connection string is assembled with fmt.Sprintf, so a password is spliced
// into a URL without being percent-encoded and any character that is structural
// in a URL changes the meaning of the string rather than being carried as data.
// The test drives the result through pgxpool.ParseConfig, which is the parser
// postgres.New hands it to, so the assertions are about what the gateway will
// actually do rather than about string shapes.
//
// Two failure classes fall out. Characters that terminate the authority, "/",
// "?", "#" and a space, make the string unparseable, so the gateway dies with
// "invalid port" or "invalid userinfo" and points the operator at a host and
// port that are both correct. A percent sign is worse: it is silently
// percent-decoded, so the gateway authenticates with a password that is not the
// one on disk and the operator sees an authentication failure against a
// credential they can see is right.
//
// The shipped generator emits hex passwords, which is why this has not bitten
// in production, but docs/config.md invites operators to supply their own
// password file and nothing warns them off punctuation. main.go builds the
// migration role's URL the same way, so DB_MIG_PASSWORD has the same problem.
// The fix is url.UserPassword rather than Sprintf.
func TestDatabaseURLDoesNotEscapePassword(t *testing.T) {
	newConfig := func(password string) *Config {
		return &Config{
			DBPassword: password,
			DBHost:     "db.internal",
			DBPort:     "6543",
			DBName:     "vaultdb",
			DBSSLMode:  "disable",
		}
	}

	t.Run("hex password from the shipped generator round-trips", func(t *testing.T) {
		const password = "9f2c4ab7d1e08356"
		cfg, err := pgxpool.ParseConfig(newConfig(password).DatabaseURL())
		if err != nil {
			t.Fatalf("ParseConfig: %v", err)
		}
		if cfg.ConnConfig.Password != password {
			t.Errorf("password = %q, want %q", cfg.ConnConfig.Password, password)
		}
		if cfg.ConnConfig.Host != "db.internal" || cfg.ConnConfig.Port != 6543 {
			t.Errorf("host = %s:%d, want db.internal:6543", cfg.ConnConfig.Host, cfg.ConnConfig.Port)
		}
	})

	t.Run("structural characters make the string unparseable", func(t *testing.T) {
		for _, password := range []string{"ab/cd", "ab?cd", "ab#cd", "ab cd"} {
			t.Run(password, func(t *testing.T) {
				if _, err := pgxpool.ParseConfig(newConfig(password).DatabaseURL()); err == nil {
					t.Fatalf("password %q no longer breaks the connection string; it is being escaped now, invert this test", password)
				}
			})
		}
	})

	t.Run("percent sign silently changes the password", func(t *testing.T) {
		const password = "ab%cdef"
		cfg, err := pgxpool.ParseConfig(newConfig(password).DatabaseURL())
		if err != nil {
			t.Fatalf("ParseConfig: %v", err)
		}
		if cfg.ConnConfig.Password == password {
			t.Fatal("the percent sign now survives; the password is being escaped, invert this test")
		}
		if cfg.ConnConfig.Password != "ab\xcdef" {
			t.Fatalf("password decoded to %q, want the percent-decoded %q", cfg.ConnConfig.Password, "ab\xcdef")
		}
	})
}

// TestEnvOr covers the string fallback helper. An empty variable is treated as
// absent, which is what lets the child-process harness blank a variable with
// t.Setenv rather than unsetting it.
func TestEnvOr(t *testing.T) {
	const key = "VAULT42_TEST_ENV_OR"

	tests := []struct {
		name     string
		set      bool
		value    string
		fallback string
		want     string
	}{
		{name: "unset yields fallback", fallback: "fallback", want: "fallback"},
		{name: "empty yields fallback", set: true, value: "", fallback: "fallback", want: "fallback"},
		{name: "set wins", set: true, value: "actual", fallback: "fallback", want: "actual"},
		{name: "whitespace is a value", set: true, value: " ", fallback: "fallback", want: " "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(key)
			if tt.set {
				t.Setenv(key, tt.value)
			}
			if got := envOr(key, tt.fallback); got != tt.want {
				t.Errorf("envOr(%q, %q) = %q, want %q", key, tt.fallback, got, tt.want)
			}
		})
	}
}

// TestEnvBool covers the boolean helper that gates auto-migration.
//
// The accepted set is exactly {true, 1, yes}. Anything else is false, including
// the capitalizations an operator is most likely to reach for.
func TestEnvBool(t *testing.T) {
	const key = "VAULT42_TEST_ENV_BOOL"

	tests := []struct {
		value string
		set   bool
		want  bool
	}{
		{value: "true", set: true, want: true},
		{value: "1", set: true, want: true},
		{value: "yes", set: true, want: true},
		{value: "false", set: true, want: false},
		{value: "0", set: true, want: false},
		{value: "TRUE", set: true, want: false},
		{value: "Yes", set: true, want: false},
		{value: "", set: true, want: false},
		{want: false},
	}

	for _, tt := range tests {
		name := tt.value
		if !tt.set {
			name = "unset"
		}
		t.Run(name, func(t *testing.T) {
			os.Unsetenv(key)
			if tt.set {
				t.Setenv(key, tt.value)
			}
			if got := envBool(key); got != tt.want {
				t.Errorf("envBool(%q=%q) = %v, want %v", key, tt.value, got, tt.want)
			}
		})
	}
}

// TestEnvInt covers the integer helper behind DB_MAX_CONNS,
// ADMIN_GW_MAX_FAILED_LOGINS and VAULT_MAX_EMAIL_TEMPLATE_SIZE.
//
// It parses with fmt.Sscanf, which stops at the first non-digit and reports no
// error, so "64k" is read as 64 and "5 connections" as 5. That is a quiet
// misconfiguration rather than a startup failure, and it is pinned here because
// the failure mode of a silently truncated limit is a size cap or a pool size
// an order of magnitude below what the operator wrote.
func TestEnvInt(t *testing.T) {
	const key = "VAULT42_TEST_ENV_INT"

	tests := []struct {
		name  string
		value string
		set   bool
		def   int
		want  int
	}{
		{name: "unset yields default", def: 5, want: 5},
		{name: "empty yields default", value: "", set: true, def: 5, want: 5},
		{name: "plain integer", value: "17", set: true, def: 5, want: 17},
		{name: "negative integer", value: "-3", set: true, def: 5, want: -3},
		{name: "zero", value: "0", set: true, def: 5, want: 0},
		{name: "non-numeric yields default", value: "many", set: true, def: 5, want: 5},
		{name: "trailing garbage is silently dropped", value: "64k", set: true, def: 5, want: 64},
		{name: "leading whitespace is skipped", value: "  7", set: true, def: 5, want: 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(key)
			if tt.set {
				t.Setenv(key, tt.value)
			}
			if got := envInt(key, tt.def); got != tt.want {
				t.Errorf("envInt(%q=%q, %d) = %d, want %d", key, tt.value, tt.def, got, tt.want)
			}
		})
	}
}

// TestEnvDuration covers the duration helper behind the session TTL, the
// lockout window and the shutdown budget.
//
// An unparseable value falls back to the default rather than failing startup.
// That matters most for ADMIN_GW_SESSION_TTL: a typo does not extend admin
// sessions, it quietly restores the one-hour default.
func TestEnvDuration(t *testing.T) {
	const key = "VAULT42_TEST_ENV_DURATION"

	tests := []struct {
		name  string
		value string
		set   bool
		def   time.Duration
		want  time.Duration
	}{
		{name: "unset yields default", def: time.Hour, want: time.Hour},
		{name: "empty yields default", value: "", set: true, def: time.Hour, want: time.Hour},
		{name: "minutes", value: "90m", set: true, def: time.Hour, want: 90 * time.Minute},
		{name: "compound", value: "1h30m", set: true, def: time.Hour, want: 90 * time.Minute},
		{name: "sub-second", value: "250ms", set: true, def: time.Hour, want: 250 * time.Millisecond},
		{name: "zero is honored", value: "0s", set: true, def: time.Hour, want: 0},
		{name: "missing unit yields default", value: "90", set: true, def: time.Hour, want: time.Hour},
		{name: "garbage yields default", value: "soon", set: true, def: time.Hour, want: time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(key)
			if tt.set {
				t.Setenv(key, tt.value)
			}
			if got := envDuration(key, tt.def); got != tt.want {
				t.Errorf("envDuration(%q=%q, %v) = %v, want %v", key, tt.value, tt.def, got, tt.want)
			}
		})
	}
}

// TestLoadSecret covers the _FILE convention every secret arrives through.
//
// Secrets are never passed as environment values, only as paths, so that they
// cannot be read out of /proc/<pid>/environ or a container inspect. The helper
// therefore has to distinguish three cases that look alike at the call site: no
// variable set, a variable pointing at nothing readable, and a real file. Only
// the third may return a value, and the two failures must be distinguishable in
// the error text because one is a deployment omission and the other is a broken
// mount.
func TestLoadSecret(t *testing.T) {
	const key = "VAULT42_TEST_SECRET"

	t.Run("unset variable", func(t *testing.T) {
		os.Unsetenv(key + "_FILE")
		got, err := loadSecret(key)
		if err == nil {
			t.Fatalf("loadSecret returned %q, want an error", got)
		}
		if !strings.Contains(err.Error(), key+"_FILE not set") {
			t.Errorf("error = %q, want it to name the unset variable", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Setenv(key+"_FILE", filepath.Join(t.TempDir(), "absent"))
		got, err := loadSecret(key)
		if err == nil {
			t.Fatalf("loadSecret returned %q, want an error", got)
		}
		if !strings.Contains(err.Error(), "read "+key+"_FILE") {
			t.Errorf("error = %q, want it to report a failed read", err)
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root, permission bits do not deny reads")
		}
		path := writeSecret(t, "locked", []byte("value"))
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Setenv(key+"_FILE", path)

		if got, err := loadSecret(key); err == nil {
			t.Fatalf("loadSecret returned %q for a mode 000 file, want an error", got)
		}
	})

	t.Run("directory instead of file", func(t *testing.T) {
		t.Setenv(key+"_FILE", t.TempDir())
		if got, err := loadSecret(key); err == nil {
			t.Fatalf("loadSecret returned %q for a directory, want an error", got)
		}
	})

	t.Run("value is trimmed", func(t *testing.T) {
		t.Setenv(key+"_FILE", writeSecret(t, "secret", []byte("  padded-secret\n\n")))
		got, err := loadSecret(key)
		if err != nil {
			t.Fatalf("loadSecret: %v", err)
		}
		if got != "padded-secret" {
			t.Errorf("loadSecret = %q, want %q", got, "padded-secret")
		}
	})

	t.Run("interior whitespace survives", func(t *testing.T) {
		t.Setenv(key+"_FILE", writeSecret(t, "secret", []byte("two words")))
		got, err := loadSecret(key)
		if err != nil {
			t.Fatalf("loadSecret: %v", err)
		}
		if got != "two words" {
			t.Errorf("loadSecret = %q, want %q", got, "two words")
		}
	})

	t.Run("path is cleaned before reading", func(t *testing.T) {
		dir := t.TempDir()
		path := writeFile(t, filepath.Join(dir, "secret"), []byte("value"))
		t.Setenv(key+"_FILE", filepath.Join(dir, "..", filepath.Base(dir), ".", "secret"))

		got, err := loadSecret(key)
		if err != nil {
			t.Fatalf("loadSecret(%s): %v", path, err)
		}
		if got != "value" {
			t.Errorf("loadSecret = %q, want %q", got, "value")
		}
	})
}
