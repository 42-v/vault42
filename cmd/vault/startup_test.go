package main

// Startup contract.
//
// vault42 is a fail-fast binary: nearly every configuration mistake is meant to
// stop the process before it listens, with a message an operator can act on.
// That behavior has no other test. The 1.0.0 coverage claim is measured over
// ./internal/..., so the file that decides whether a misconfigured deployment
// refuses to start or starts anyway was outside it entirely.
//
// These tests pin both halves of the contract for each startup stage: the exit
// status a deployment script branches on, and the stderr line a human reads.
// Where a stage handles key material they also pin what must NOT appear in the
// output, because a startup path that fails open or logs a credential is worse
// than one that is untested.

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// adminTokenRule reports the admin token as already provisioned. Without it
// every boot pays for an Argon2id hash (46 MiB, by design) to mint a first-boot
// token that no test reads.
func adminTokenRule(value string) pgRule {
	return pgRule{
		match: "SELECT value FROM auth.admin_config",
		cols:  textColumns("value"),
		rows:  [][][]byte{textRow(value)},
	}
}

// bootedStub is the database a healthy startup sees: reachable, with the admin
// token already set, and every other statement answering empty.
func bootedStub(t *testing.T) *pgStub {
	t.Helper()
	return startPGStub(t, adminTokenRule("$argon2id$already-provisioned"))
}

// ---------------------------------------------------------------------------
// The server path
// ---------------------------------------------------------------------------

// TestServerBootsServesAndShutsDownGracefully is the backbone test: it drives
// main() from the first line to the last against a scripted database, proves the
// process actually serves HTTP, and proves that SIGTERM and SIGINT both end it
// with a zero exit status rather than by killing an in-flight request.
//
// A binary that exits non-zero on SIGTERM makes every Kubernetes rollout look
// like a crash loop, so the exit status here is the operational contract and not
// a detail.
func TestServerBootsServesAndShutsDownGracefully(t *testing.T) {
	for _, tc := range []struct {
		name string
		sig  syscall.Signal
	}{
		{"SIGTERM", syscall.SIGTERM},
		{"SIGINT", syscall.SIGINT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := bootedStub(t)
			addr := freeAddr(t)
			env := bootEnv(t, stub, addr)

			res := bootAndShutdown(t, vaultRun{env: env}, addr, tc.sig, func(t *testing.T) {
				if code, _ := get(t, addr, "/healthz"); code != 200 {
					t.Fatalf("GET /healthz = %d, want 200", code)
				}
				// /readyz runs the PingDB closure main() builds, so it is the
				// only assertion that the readiness probe is wired to the pool
				// rather than reporting ready unconditionally.
				if code, body := get(t, addr, "/readyz"); code != 200 {
					t.Fatalf("GET /readyz = %d, want 200 (body %q)", code, body)
				}
				code, body := get(t, addr, "/.well-known/jwks.json")
				if code != 200 {
					t.Fatalf("GET /.well-known/jwks.json = %d, want 200", code)
				}
				if !strings.Contains(body, `"kty"`) {
					t.Fatalf("JWKS has no keys: %s", body)
				}
			})

			requireExit(t, res, 0, "Shutting down...")
			if !strings.Contains(res.stderr, "The Vault listening on "+addr) {
				t.Fatalf("startup never logged the listen address %q\nstderr:\n%s", addr, res.stderr)
			}
			if dialable(addr) {
				t.Fatalf("%s still accepts connections after the process exited", addr)
			}
			requireNoSecretLeak(t, res, dbPassword, strings.Repeat("h", 32), strings.Repeat("p", 32), strings.Repeat("m", 32))
		})
	}
}

// TestGracefulShutdownDrainsConcurrentRequests fires traffic at the server from
// several goroutines and signals it mid-flight. It exists for two regressions:
// a shutdown that kills live connections instead of draining them, which shows
// up as a request error here, and a data race in the startup wiring, which shows
// up as a race-detector report in the child because the child is this same
// -race-instrumented binary.
func TestGracefulShutdownDrainsConcurrentRequests(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)

	p := startVault(t, vaultRun{env: bootEnv(t, stub, addr)})
	awaitServing(t, p, addr, 60*time.Second)

	const workers = 8
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan string, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// A request that is refused because the listener has already
				// closed is the expected end state; a request that is accepted
				// and then answered with a server error is not.
				code, _, err := tryGet(addr, "/healthz")
				if err != nil {
					return
				}
				if code >= 500 {
					errs <- "healthz answered " + strconv.Itoa(code) + " during shutdown"
					return
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	p.signal(t, syscall.SIGTERM)
	res := p.wait(t, 60*time.Second)
	close(stop)
	wg.Wait()
	close(errs)

	for msg := range errs {
		t.Error(msg)
	}
	requireExit(t, res, 0, "Shutting down...")
}

// TestServerExitsNonZeroWhenTheListenAddressIsTaken covers the last error branch
// in main(). A port collision is the ordinary way a second replica lands on a
// host that already runs one, and it must be a startup failure, not a process
// that stays up doing nothing.
func TestServerExitsNonZeroWhenTheListenAddressIsTaken(t *testing.T) {
	stub := bootedStub(t)
	addr := occupiedAddr(t)

	res := runVault(t, vaultRun{env: bootEnv(t, stub, addr)})
	requireExit(t, res, 1, "Server error")
	if !strings.Contains(res.stderr, "address already in use") {
		t.Fatalf("stderr does not name the bind failure\nstderr:\n%s", res.stderr)
	}
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

// TestProfilesBootWithTheirOwnDefaults walks every deployment profile through a
// full startup. Each profile changes what main() wires up, and the honeypot
// profile changes it the most: it is the only one that installs the trap-user
// alerter and rewrites the fake JWT issuer, so a regression that dropped that
// wiring would leave a honeypot silently indistinguishable from a plain server.
func TestProfilesBootWithTheirOwnDefaults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile profileName
		env     map[string]string
		wantLog []string
	}{
		{
			name:    "production",
			profile: profileProduction,
			wantLog: []string{"profile=production"},
		},
		{
			name:    "embedded",
			profile: profileEmbedded,
			// The embedded profile turns auto-migration on by default, and this
			// suite has no schema to migrate against.
			env:     map[string]string{"VAULT_AUTO_MIGRATE": "false"},
			wantLog: []string{"profile=embedded"},
		},
		{
			name:    "honeypot",
			profile: profileHoneypot,
			env: map[string]string{
				"VAULT_AUTO_MIGRATE":        "false",
				"VAULT_HONEYPOT_TRAP_USERS": "root@example.com, Admin@Example.com",
			},
			wantLog: []string{"profile=honeypot", "Honeypot mode active: 2 trap users configured"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := bootedStub(t)
			addr := freeAddr(t)
			env := bootEnv(t, stub, addr)
			env["VAULT_PROFILE"] = string(tc.profile)
			for k, v := range tc.env {
				env[k] = v
			}

			res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)
			requireExit(t, res, 0, "Shutting down...")
			for _, want := range tc.wantLog {
				if !strings.Contains(res.stderr, want) {
					t.Fatalf("stderr does not contain %q\nstderr:\n%s", want, res.stderr)
				}
			}
		})
	}
}

// TestDevProfileRunsMigrationsBeforeServing pins the one profile that cannot opt
// out of auto-migration: applyProfileDefaults sets AutoMigrate unconditionally
// for dev, ignoring VAULT_AUTO_MIGRATE. The stub reports every migration file as
// already applied, so the runner has nothing to do and the test observes the
// path rather than the schema.
func TestDevProfileRunsMigrationsBeforeServing(t *testing.T) {
	applied := make([][][]byte, 0)
	for _, name := range migrationNames(t) {
		applied = append(applied, textRow(name))
	}

	stub := startPGStub(t,
		adminTokenRule("$argon2id$already-provisioned"),
		pgRule{
			match: "SELECT version FROM public.schema_migrations",
			cols:  textColumns("version"),
			rows:  applied,
		},
	)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	env["VAULT_PROFILE"] = string(profileDev)

	// The migration runner reads the migrations/ directory relative to the
	// working directory, which for the real binary is the image root.
	res := bootAndShutdown(t, vaultRun{env: env, dir: repoRoot(t)}, addr, syscall.SIGTERM, nil)

	requireExit(t, res, 0, "Migrations complete")
	if !strings.Contains(res.stderr, "profile=dev") {
		t.Fatalf("dev profile not reported in the config summary\nstderr:\n%s", res.stderr)
	}
	if !stub.sawQuery("CREATE TABLE IF NOT EXISTS public.schema_migrations") {
		t.Fatalf("migration runner never created its tracking table; queries seen: %v", stub.queries())
	}
}

// TestMigrationFailureStopsStartup asserts that a broken migration is fatal. A
// server that starts against a half-migrated schema answers requests with
// column-does-not-exist errors instead of refusing to start, which is a much
// harder failure to diagnose.
func TestMigrationFailureStopsStartup(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	env["VAULT_AUTO_MIGRATE"] = "true"

	// The package directory has no migrations/ subdirectory, so the runner
	// fails while reading it.
	res := runVault(t, vaultRun{env: env})
	requireExit(t, res, 1, "Migration failed")
	if dialable(addr) {
		t.Fatal("the server bound its port despite the migration failure")
	}
}

// TestMigrationConnectFailureIsFatalAndRedacted covers the other migration
// branch, and the redaction that goes with it: the migration connection string
// carries the vault_mig password, and pgx puts the whole connection string into
// its dial errors.
func TestMigrationConnectFailureIsFatalAndRedacted(t *testing.T) {
	stub := bootedStub(t)
	env := bootEnv(t, stub, freeAddr(t))
	env["VAULT_AUTO_MIGRATE"] = "true"
	env["DB_HOST"] = "127.0.0.1"
	env["DB_PORT"] = deadPort(t)

	res := runVault(t, vaultRun{env: env})
	requireExit(t, res, 1, "Failed to connect for migrations")
	requireNoSecretLeak(t, res, dbPassword)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// TestConfigLoadFailuresAreFatal covers the branches where config.Load itself
// refuses. Each row is a setting that fails closed by design, and the point of
// the table is that main() surfaces the reason rather than starting with a
// substituted default.
func TestConfigLoadFailuresAreFatal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, env map[string]string)
		wantMsg string
	}{
		{
			name: "invalid primary color",
			mutate: func(_ *testing.T, env map[string]string) {
				env["VAULT_PRIMARY_COLOR"] = "red; background:url(x)"
			},
			wantMsg: "invalid VAULT_PRIMARY_COLOR",
		},
		{
			name: "hmac secret shorter than 32 bytes outside dev",
			mutate: func(t *testing.T, env map[string]string) {
				env["HMAC_SECRET_FILE"] = secretFile(t, t.TempDir(), "short-hmac", "too-short")
			},
			wantMsg: "HMAC secret must be at least 32 bytes",
		},
		{
			name: "embedded trust shortcut outside the embedded profile",
			mutate: func(_ *testing.T, env map[string]string) {
				env["VAULT_EMBEDDED_TRUSTED_UPSTREAM"] = "true"
			},
			wantMsg: "only valid in the embedded profile",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := bootedStub(t)
			addr := freeAddr(t)
			env := bootEnv(t, stub, addr)
			tc.mutate(t, env)

			res := runVault(t, vaultRun{env: env})
			requireExit(t, res, 1, "Failed to load config")
			if !strings.Contains(res.stderr, tc.wantMsg) {
				t.Fatalf("stderr does not explain the failure (%q)\nstderr:\n%s", tc.wantMsg, res.stderr)
			}
			if dialable(addr) {
				t.Fatal("the server bound its port despite the configuration failure")
			}
		})
	}
}

// TestConfigValidationFailuresAreFatal covers Config.Validate as main() sees it.
// Every row here is a fail-closed invariant from the security audit: a non-dev
// deployment missing an HMAC key, a pepper, an origin, rate limiting, or TLS
// must refuse to start. A regression that turned any of these into a warning
// would leave the deployment running and quietly weaker, which is exactly the
// failure mode this asserts against.
func TestConfigValidationFailuresAreFatal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, env map[string]string)
		wantMsg string
	}{
		{
			name: "missing hmac secret",
			mutate: func(_ *testing.T, env map[string]string) {
				delete(env, "HMAC_SECRET_FILE")
			},
			wantMsg: "HMAC_SECRET_FILE required",
		},
		{
			name: "missing pepper",
			mutate: func(_ *testing.T, env map[string]string) {
				delete(env, "VAULT_PEPPER_FILE")
			},
			wantMsg: "VAULT_PEPPER_FILE required",
		},
		{
			name: "missing origin",
			mutate: func(_ *testing.T, env map[string]string) {
				delete(env, "VAULT_ORIGIN")
			},
			wantMsg: "VAULT_ORIGIN required",
		},
		{
			name: "rate limiting disabled without the override",
			mutate: func(_ *testing.T, env map[string]string) {
				env["VAULT_RATE_LIMIT_ENABLED"] = "false"
			},
			wantMsg: "refusing to disable rate limiting",
		},
		{
			name: "plaintext without the override",
			mutate: func(_ *testing.T, env map[string]string) {
				delete(env, "VAULT_ALLOW_PLAINTEXT")
			},
			wantMsg: "refusing to disable TLS",
		},
		{
			name: "tls enabled with no certificate",
			mutate: func(_ *testing.T, env map[string]string) {
				env["VAULT_TLS_ENABLED"] = "true"
			},
			wantMsg: "VAULT_TLS_CERT_FILE and VAULT_TLS_KEY_FILE required",
		},
		{
			name: "mint enabled without an audience",
			mutate: func(_ *testing.T, env map[string]string) {
				env["VAULT_MINT_ENABLED"] = "true"
			},
			wantMsg: "VAULT_MINT_AUDIENCE required",
		},
		{
			name: "mint audience equal to the issuer",
			mutate: func(_ *testing.T, env map[string]string) {
				env["VAULT_MINT_ENABLED"] = "true"
				env["VAULT_MINT_AUDIENCE"] = env["VAULT_ORIGIN"]
			},
			wantMsg: "must differ from VAULT_ORIGIN",
		},
		{
			name: "missing master key",
			mutate: func(_ *testing.T, env map[string]string) {
				delete(env, "MASTER_KEY_FILE")
			},
			wantMsg: "MASTER_KEY_FILE required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := bootedStub(t)
			addr := freeAddr(t)
			env := bootEnv(t, stub, addr)
			tc.mutate(t, env)

			res := runVault(t, vaultRun{env: env})
			requireExit(t, res, 1, "Invalid configuration")
			if !strings.Contains(res.stderr, tc.wantMsg) {
				t.Fatalf("stderr does not explain the failure (%q)\nstderr:\n%s", tc.wantMsg, res.stderr)
			}
			if dialable(addr) {
				t.Fatal("the server bound its port despite invalid configuration")
			}
		})
	}
}

// TestDatabaseConnectFailureIsFatalAndRedacted is the security half of the
// connect path. pgx embeds the whole connection string, password included, in
// its dial errors; sanitizeDBError exists to strip it, and this asserts the
// stripping actually happens on the path an operator will hit first.
func TestDatabaseConnectFailureIsFatalAndRedacted(t *testing.T) {
	stub := bootedStub(t)
	env := bootEnv(t, stub, freeAddr(t))
	env["DB_HOST"] = "127.0.0.1"
	env["DB_PORT"] = deadPort(t)

	res := runVault(t, vaultRun{env: env})
	requireExit(t, res, 1, "Failed to connect to database")
	requireNoSecretLeak(t, res, dbPassword)
}

// ---------------------------------------------------------------------------
// Secret files
// ---------------------------------------------------------------------------

// TestSecretFileConsumeDestroysTheFileAfterReading pins VAULT_SECRET_FILE_CONSUME,
// the defense-in-depth wipe. It is opt-in precisely because it destroys the
// operator's keyfile, so both directions are asserted: with it on the file is
// gone after startup, and with it off the file survives byte-for-byte. A
// regression in either direction is severe. Silently keeping the file defeats
// the feature; silently consuming it destroys a master key on a writable mount.
func TestSecretFileConsumeDestroysTheFileAfterReading(t *testing.T) {
	const master = "0123456789abcdef0123456789abcdef" // 32 bytes

	for _, tc := range []struct {
		name       string
		consume    string
		wantExists bool
	}{
		{name: "consume enabled", consume: "true", wantExists: false},
		{name: "consume disabled", consume: "", wantExists: true},
		{name: "consume set to something other than true", consume: "1", wantExists: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := bootedStub(t)
			addr := freeAddr(t)
			env := bootEnv(t, stub, addr)

			keyfile := secretFile(t, t.TempDir(), "master.key", master)
			env["MASTER_KEY_FILE"] = keyfile
			env["VAULT_SECRET_FILE_CONSUME"] = tc.consume

			res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)
			requireExit(t, res, 0, "Shutting down...")
			requireNoSecretLeak(t, res, master)

			data, err := os.ReadFile(keyfile) //nolint:gosec // fixture path from t.TempDir
			switch {
			case tc.wantExists && err != nil:
				t.Fatalf("secret file was destroyed with consume=%q: %v", tc.consume, err)
			case tc.wantExists && string(data) != master:
				t.Fatalf("secret file was modified with consume=%q: %q", tc.consume, data)
			case !tc.wantExists && err == nil:
				t.Fatalf("secret file survived VAULT_SECRET_FILE_CONSUME=true (content %q)", data)
			case !tc.wantExists && !os.IsNotExist(err):
				t.Fatalf("unexpected error reading the consumed secret file: %v", err)
			}
		})
	}
}

// TestSecretFileTrailingNewlineIsTrimmed guards the convention every Kubernetes
// secret mount depends on. A 32-byte master key written by `echo` is 33 bytes on
// disk, and a startup that did not trim would reject it as the wrong length.
func TestSecretFileTrailingNewlineIsTrimmed(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	env["MASTER_KEY_FILE"] = secretFile(t, t.TempDir(), "master.key", "0123456789abcdef0123456789abcdef\n")
	// The DB-backed keystore is the consumer that rejects a master key of the
	// wrong length, so it is what makes the trimming observable.
	env["VAULT_KEY_ROTATION_DB"] = "true"

	// The scripted database cannot satisfy the keystore, so startup still fails.
	// Where it fails is the assertion: past the length gate, not at it.
	res := runVault(t, vaultRun{env: env})
	if strings.Contains(res.stderr, "requires MASTER_KEY_FILE (32 bytes)") {
		t.Fatalf("a trailing newline made a 32-byte key look like the wrong length\nstderr:\n%s", res.stderr)
	}
	requireExit(t, res, 1, "Failed to initialize keystore")
}

// TestKeystoreInitFailureIsFatal covers the DB-backed keystore branch. The
// keystore owns the JWT signing keys, so a server that carried on past a
// keystore it could not initialize would either sign with nothing or sign with a
// key no other replica knows about.
func TestKeystoreInitFailureIsFatal(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	env["VAULT_KEY_ROTATION_DB"] = "true"
	env["MASTER_KEY_FILE"] = secretFile(t, t.TempDir(), "master.key", "0123456789abcdef0123456789abcdef")

	res := runVault(t, vaultRun{env: env})
	requireExit(t, res, 1, "Failed to initialize keystore")
	if dialable(addr) {
		t.Fatal("the server bound its port without a usable keystore")
	}
}

// ---------------------------------------------------------------------------
// Signing keys
// ---------------------------------------------------------------------------

// TestSigningKeyFromFileIsUsedForJWKS asserts the file-based signing key is the
// key the server actually publishes. Loading a key and then serving a different
// one would break every relying party that pins the kid, and only an end-to-end
// check of the JWKS output can tell the difference.
func TestSigningKeyFromFileIsUsedForJWKS(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)

	keyPEM, kid := signingKeyPEM(t)
	env["SIGNING_KEY_FILE"] = secretFile(t, t.TempDir(), "signing.pem", keyPEM)

	var jwks string
	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, func(t *testing.T) {
		_, jwks = get(t, addr, "/.well-known/jwks.json")
	})

	requireExit(t, res, 0, "Signing key loaded from file")
	if !strings.Contains(res.stderr, "kid="+kid) {
		t.Fatalf("startup did not report the key id from the file (want %q)\nstderr:\n%s", kid, res.stderr)
	}
	if !strings.Contains(jwks, kid) {
		t.Fatalf("JWKS does not publish the loaded key id %q: %s", kid, jwks)
	}
	requireNoSecretLeak(t, res, keyPEM)
}

// TestEphemeralSigningKeyIsAnnounced covers the no-key-file default. The key is
// generated per process, which silently breaks any multi-replica deployment, so
// the warning is the only thing standing between an operator and intermittent
// signature failures across pods.
func TestEphemeralSigningKeyIsAnnounced(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)

	res := bootAndShutdown(t, vaultRun{env: bootEnv(t, stub, addr)}, addr, syscall.SIGTERM, nil)
	requireExit(t, res, 0, "WARNING: No SIGNING_KEY_FILE")
	if !strings.Contains(res.stderr, "multi-pod will fail") {
		t.Fatalf("the ephemeral-key warning does not say what breaks\nstderr:\n%s", res.stderr)
	}
}

// TestSigningKeyGenerationFailureIsFatal covers the two entropy draws on the
// no-key-file path. Neither is a configuration mistake an operator can make, so
// the child runs over a starved CSPRNG (see starvedReader) to produce them.
//
// Both guard a failure that would otherwise be silent or misattributed. A
// generation failure that was only logged leaves signingKey nil and the process
// dies a few lines down, on the nil dereference that builds the JWKS map,
// reporting a stack trace where it should report a cause. A key-id failure that
// was only logged is worse: the server starts, publishes a JWKS whose single
// entry has an empty kid, and signs every token with that empty kid, which
// nothing downstream can pin and no probe can see from the outside.
func TestSigningKeyGenerationFailureIsFatal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		godebug string
		want    string
	}{
		// rsa.GenerateKey ignores a replaced crypto/rand.Reader unless
		// cryptocustomrand=1, so with the default the key is generated from the
		// crypto module's own DRBG and the starved reader is felt one statement
		// later, where RandomUUID reads crypto/rand.Reader directly. The value is
		// stated rather than left out so an inherited GODEBUG cannot decide which
		// of the two failures this row gets.
		{name: "key id", godebug: "cryptocustomrand=0", want: "Failed to generate key ID"},
		// With the setting on, the same reader is felt in rsa.GenerateKey itself
		// and startup fails before a key exists at all.
		{name: "signing key", godebug: "cryptocustomrand=1", want: "Failed to generate signing key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := bootedStub(t)
			addr := freeAddr(t)
			env := bootEnv(t, stub, addr)
			env[vaultChildStarveEntropy] = "1"
			env["GODEBUG"] = tc.godebug

			res := runVault(t, vaultRun{env: env})
			requireExit(t, res, 1, tc.want)
			if dialable(addr) {
				t.Fatal("the server bound its port without a signing key")
			}
		})
	}
}

// TestMalformedSigningKeyIsFatal asserts a corrupt key file stops startup. The
// alternative, falling back to a generated key, would silently rotate every
// issued token out of validity.
func TestMalformedSigningKeyIsFatal(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rotationDB string
		want       string
	}{
		{name: "file based", rotationDB: "", want: "Failed to load signing key:"},
		{name: "keystore import", rotationDB: "true", want: "Failed to load signing key for import"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := bootedStub(t)
			addr := freeAddr(t)
			env := bootEnv(t, stub, addr)
			env["SIGNING_KEY_FILE"] = secretFile(t, t.TempDir(), "signing.pem", "-----BEGIN RSA PRIVATE KEY-----\nnot-a-key\n-----END RSA PRIVATE KEY-----")
			env["VAULT_KEY_ROTATION_DB"] = tc.rotationDB
			if tc.rotationDB == "true" {
				env["MASTER_KEY_FILE"] = secretFile(t, t.TempDir(), "master.key", "0123456789abcdef0123456789abcdef")
			}

			res := runVault(t, vaultRun{env: env})
			requireExit(t, res, 1, tc.want)
			if dialable(addr) {
				t.Fatal("the server bound its port despite an unusable signing key")
			}
		})
	}
}

// TestKeyRotationDBRequiresA32ByteMasterKey pins the guard in front of the
// DB-backed keystore. The keystore encrypts every signing key at rest with this
// master key, so accepting a short or absent one would mean writing private keys
// to the database under a key that is not a key.
func TestKeyRotationDBRequiresA32ByteMasterKey(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "absent", value: ""},
		{name: "too short", value: "short"},
		{name: "too long", value: strings.Repeat("k", 33)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := bootedStub(t)
			addr := freeAddr(t)
			env := bootEnv(t, stub, addr)
			// Production Validate now refuses a missing master key first.
			// This test is the remaining guard in main() for every other
			// profile that can enable the DB-backed keystore.
			env["VAULT_PROFILE"] = string(profileEmbedded)
			env["VAULT_AUTO_MIGRATE"] = "false"
			env["VAULT_KEY_ROTATION_DB"] = "true"
			if tc.value == "" {
				delete(env, "MASTER_KEY_FILE")
			} else {
				env["MASTER_KEY_FILE"] = secretFile(t, t.TempDir(), "master.key", tc.value)
			}

			res := runVault(t, vaultRun{env: env})
			requireExit(t, res, 1, "VAULT_KEY_ROTATION_DB=true requires MASTER_KEY_FILE (32 bytes)")
			if dialable(addr) {
				t.Fatal("the server bound its port with an unusable keystore master key")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Optional subsystems
// ---------------------------------------------------------------------------

// TestKMSRootKeyGatesTheUnwrapOracle covers both directions of the KMS branch.
// POST /kms/unwrap is a decryption oracle, so it must be mounted only when a
// root key was actually provisioned, and a root key too short to be safe must
// stop the process instead of being padded or ignored.
func TestKMSRootKeyGatesTheUnwrapOracle(t *testing.T) {
	t.Run("valid root enables the oracle", func(t *testing.T) {
		stub := bootedStub(t)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		root := strings.Repeat("r", 32)
		env["KMS_ROOT_KEY_FILE"] = secretFile(t, t.TempDir(), "kms.key", root)

		var status int
		res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, func(t *testing.T) {
			status, _ = get(t, addr, "/kms/unwrap")
		})
		requireExit(t, res, 0, "KMS unwrap oracle enabled at POST /kms/unwrap")
		if status == 404 {
			t.Fatal("/kms/unwrap is not routed even though a root key was provisioned")
		}
		requireNoSecretLeak(t, res, root)
	})

	t.Run("short root is fatal", func(t *testing.T) {
		stub := bootedStub(t)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		env["KMS_ROOT_KEY_FILE"] = secretFile(t, t.TempDir(), "kms.key", "too-short-for-a-root-key")

		res := runVault(t, vaultRun{env: env})
		requireExit(t, res, 1, "KMS_ROOT_KEY invalid")
		if dialable(addr) {
			t.Fatal("the server bound its port with an invalid KMS root key")
		}
	})

	t.Run("no root leaves the oracle unmounted", func(t *testing.T) {
		stub := bootedStub(t)
		addr := freeAddr(t)

		var status int
		res := bootAndShutdown(t, vaultRun{env: bootEnv(t, stub, addr)}, addr, syscall.SIGTERM, func(t *testing.T) {
			status, _ = get(t, addr, "/kms/unwrap")
		})
		requireExit(t, res, 0, "Shutting down...")
		if strings.Contains(res.stderr, "KMS unwrap oracle enabled") {
			t.Fatalf("the oracle announced itself without a root key\nstderr:\n%s", res.stderr)
		}
		if status != 404 {
			t.Fatalf("GET /kms/unwrap = %d without a root key, want 404", status)
		}
	})
}

// TestRecoveryPublicKeyGatesEscrow covers the account-erasure escrow branch. A
// malformed key must stop startup rather than disable escrow silently: erasure
// still works without it, so a silent fallback would make every deletion
// unrecoverable while the deployment looked healthy.
func TestRecoveryPublicKeyGatesEscrow(t *testing.T) {
	t.Run("valid key enables escrow", func(t *testing.T) {
		stub := bootedStub(t)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		env["VAULT_RECOVERY_PUBLIC_KEY_FILE"] = secretFile(t, t.TempDir(), "recovery.pem", recoveryPublicKeyPEM(t))

		res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)
		requireExit(t, res, 0, "Account-recovery escrow enabled")
	})

	t.Run("malformed key is fatal", func(t *testing.T) {
		stub := bootedStub(t)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		env["VAULT_RECOVERY_PUBLIC_KEY_FILE"] = secretFile(t, t.TempDir(), "recovery.pem", "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----")

		res := runVault(t, vaultRun{env: env})
		requireExit(t, res, 1, "Failed to load recovery public key")
		if dialable(addr) {
			t.Fatal("the server bound its port with an unusable recovery key")
		}
	})

	t.Run("absent key warns but starts", func(t *testing.T) {
		stub := bootedStub(t)
		addr := freeAddr(t)

		res := bootAndShutdown(t, vaultRun{env: bootEnv(t, stub, addr)}, addr, syscall.SIGTERM, nil)
		requireExit(t, res, 0, "SECURITY WARNING: VAULT_RECOVERY_PUBLIC_KEY_FILE not set")
	})
}

// TestMintPolicyIsEnforcedAtStartup covers the mint branch. NewMintService is
// called from main() rather than from route setup specifically so that an unsafe
// policy can abort the process, and this is the test that keeps that property:
// an allow-list naming an admin-tier role must be a startup failure, not a
// signing oracle that hands out admin tokens.
func TestMintPolicyIsEnforcedAtStartup(t *testing.T) {
	t.Run("admin role in the allow-list is fatal", func(t *testing.T) {
		stub := bootedStub(t)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		env["VAULT_MINT_ENABLED"] = "true"
		env["VAULT_MINT_AUDIENCE"] = "https://beon3.test"
		env["VAULT_MINT_ROLES"] = "admin"

		res := runVault(t, vaultRun{env: env})
		requireExit(t, res, 1, "Failed to initialize mint service")
		if dialable(addr) {
			t.Fatal("the server bound its port with an admin-tier mint policy")
		}
	})

	t.Run("safe policy starts and announces the audience", func(t *testing.T) {
		stub := bootedStub(t)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		env["VAULT_MINT_ENABLED"] = "true"
		env["VAULT_MINT_AUDIENCE"] = "https://beon3.test"
		env["VAULT_MINT_ROLES"] = "service"
		env["VAULT_MINT_SCOPES"] = "read"

		res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)
		requireExit(t, res, 0, `Mint enabled: signing for audience "https://beon3.test"`)
	})
}

// TestMetricsEndpointFollowsTheFlag asserts the collector is wired only when
// asked, and that it never appears on the public listener. /metrics exposes
// password-hashing concurrency and process-global document rates, so a build
// that mounted it on the port the Ingress publishes would widen the
// unauthenticated surface of every deployment — which is what it used to do,
// under a comment recommending a NetworkPolicy that cannot select on a path.
func TestMetricsEndpointFollowsTheFlag(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled string
		want    int
	}{
		{name: "enabled", enabled: "true", want: 200},
		{name: "disabled", enabled: "", want: 0}, // 0 = nothing listening at all
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := bootedStub(t)
			addr := freeAddr(t)
			scrapeAddr := freeAddr(t)
			env := bootEnv(t, stub, addr)
			env["VAULT_METRICS_ENABLED"] = tc.enabled
			env["VAULT_METRICS_ADDR"] = scrapeAddr

			var status, publicStatus int
			var body string
			res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, func(t *testing.T) {
				publicStatus, _ = get(t, addr, "/metrics")
				status, body = scrape(t, scrapeAddr)
			})
			requireExit(t, res, 0, "Shutting down...")

			if publicStatus != http.StatusNotFound {
				t.Fatalf("GET /metrics on the public listener = %d, want 404: the scrape endpoint "+
					"shares the port the Ingress publishes", publicStatus)
			}
			if status != tc.want {
				t.Fatalf("GET /metrics on the metrics listener = %d, want %d (body %q)",
					status, tc.want, body)
			}
			if tc.enabled == "true" && !strings.Contains(res.stderr, "Prometheus metrics enabled") {
				t.Fatalf("metrics were served without being announced\nstderr:\n%s", res.stderr)
			}
		})
	}
}

// scrape requests /metrics from the dedicated metrics listener. It returns 0
// when nothing is listening, which is what "metrics are off" now looks like:
// the endpoint is absent rather than answering 404 on a shared port.
func scrape(t *testing.T, addr string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/metrics")
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close() //nolint:errcheck // response body of a finished request
	var b bytes.Buffer
	if _, err := b.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	return resp.StatusCode, b.String()
}

// TestEmailProviderSelection walks the provider switch in startup order. The
// third row is the one worth having: with VAULT_EMAIL_PROVIDER left at its "smtp"
// default and no SMTP host, a SendGrid key alone still has to produce a working
// sender, otherwise the deployment starts with password-reset mail silently
// disabled.
func TestEmailProviderSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "explicit sendgrid",
			env:  map[string]string{"VAULT_EMAIL_PROVIDER": "sendgrid", "SENDGRID_API_KEY_FILE": "fixture"},
			want: "Email: SendGrid provider configured",
		},
		{
			name: "smtp host set",
			env:  map[string]string{"SMTP_HOST": "smtp.example.test"},
			want: "Email: SMTP provider configured",
		},
		{
			name: "sendgrid fallback when smtp is unconfigured",
			env:  map[string]string{"SENDGRID_API_KEY_FILE": "fixture"},
			want: "Email: SendGrid provider configured (fallback, SMTP_HOST empty)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := bootedStub(t)
			addr := freeAddr(t)
			env := bootEnv(t, stub, addr)
			apiKey := "SG.test-key-not-a-real-credential"
			for k, v := range tc.env {
				if v == "fixture" {
					v = secretFile(t, t.TempDir(), "sendgrid", apiKey)
				}
				env[k] = v
			}

			res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)
			requireExit(t, res, 0, tc.want)
			requireNoSecretLeak(t, res, apiKey)
		})
	}
}

// TestOIDCProviderRegistration covers the generic OpenID Connect loop. Provider
// names come from configuration, so the log line naming each registered provider
// is the only startup-time evidence an operator has that a typo in
// VAULT_OIDC_PROVIDERS did not silently drop their identity provider.
func TestOIDCProviderRegistration(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	secret := "oidc-client-secret-fixture"
	env["VAULT_OIDC_PROVIDERS"] = "okta,incomplete"
	env["VAULT_OIDC_OKTA_ISSUER"] = "https://okta.example.test"
	env["VAULT_OIDC_OKTA_CLIENT_ID"] = "okta-client"
	env["VAULT_OIDC_OKTA_CLIENT_SECRET_FILE"] = secretFile(t, t.TempDir(), "okta", secret)
	// "incomplete" has no issuer and must be skipped rather than registered half-built.
	env["VAULT_OIDC_INCOMPLETE_CLIENT_ID"] = "orphan"

	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)
	requireExit(t, res, 0, `oauth: registered OIDC provider "okta" (issuer=https://okta.example.test)`)
	if strings.Contains(res.stderr, `provider "incomplete"`) {
		t.Fatalf("a provider with no issuer was registered\nstderr:\n%s", res.stderr)
	}
	requireNoSecretLeak(t, res, secret)
}

// TestRetentionSweepersStartOnlyForTheServer pins where the two GDPR retention
// sweepers are started. Both sweep immediately on start, and both are started
// after the CLI check on purpose: starting them earlier would make every
// unrelated `vault ...` subcommand purge the audit log and the recovery escrow
// as a side effect.
func TestRetentionSweepersStartOnlyForTheServer(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	env["VAULT_AUDIT_RETENTION_DAYS"] = "30"
	env["VAULT_RECOVERY_RETENTION_DAYS"] = "7"

	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)
	requireExit(t, res, 0, "audit retention: purging entries older than 720h0m0s")
	if !strings.Contains(res.stderr, "recovery retention: purging escrow records older than 168h0m0s") {
		t.Fatalf("recovery retention did not start\nstderr:\n%s", res.stderr)
	}
}

// TestCacheBackendFallback covers the cache branch. A Redis outage at boot must
// degrade to the in-memory cache with a warning rather than take the process
// down, because the cache holds rate-limit counters and session hints, not
// durable state.
func TestCacheBackendFallback(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	env["CACHE_BACKEND"] = "redis"
	env["REDIS_ADDR"] = "127.0.0.1:" + deadPort(t)

	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)
	requireExit(t, res, 0, "cache init failed, falling back to per-process memory")

	// The line has to say what was lost, not only that something was. The
	// fallback silently turns every cross-replica control into a per-pod one:
	// the login and password-reset limiters multiply by the replica count, and
	// OAuth state written on one pod cannot be read on another. An operator
	// reading "falling back to memory" has no reason to treat that as urgent.
	for _, want := range []string{"WARNING", "rate limiting", "readyz reports cache=degraded"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("the fallback warning does not mention %q, so nothing tells the operator "+
				"what degraded:\n%s", want, res.stderr)
		}
	}
}

// TestSeedFileFailuresAreFatal covers declarative seeding on the server path.
// Seeding runs after the CLI check (see TestCLIDoesNotApplySeedFile) and
// before the server listens, so a seed file that cannot be read or applied
// must stop the process: continuing would bring up a deployment missing the
// very accounts the operator declared.
func TestSeedFileFailuresAreFatal(t *testing.T) {
	t.Run("unreadable seed file", func(t *testing.T) {
		stub := bootedStub(t)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		env["VAULT_SEED_FILE"] = filepath.Join(t.TempDir(), "absent.json")

		res := runVault(t, vaultRun{env: env})
		requireExit(t, res, 1, "Failed to load seed file")
		if dialable(addr) {
			t.Fatal("the server bound its port despite an unusable seed file")
		}
	})

	t.Run("seeding error", func(t *testing.T) {
		stub := startPGStub(t,
			adminTokenRule("$argon2id$already-provisioned"),
			pgRule{match: "INSERT INTO auth.clients", errCode: "42501", errMsg: "permission denied for table clients"},
		)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		env["VAULT_SEED_FILE"] = secretFile(t, t.TempDir(), "seed.json",
			`{"clients":[{"name":"beon3","role":"service","scopes":["read"]}]}`)

		res := runVault(t, vaultRun{env: env})
		requireExit(t, res, 1, "Seeding failed")
	})

	t.Run("empty seed file applies cleanly", func(t *testing.T) {
		stub := bootedStub(t)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		env["VAULT_SEED_FILE"] = secretFile(t, t.TempDir(), "seed.json", `{}`)

		res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)
		requireExit(t, res, 0, "Shutting down...")
	})
}

// TestEmailTemplateOverrideRejectionIsFatal covers the template renderer branch.
// Overrides are operator-supplied HTML rendered into outgoing mail, and the
// renderer refuses anything carrying script or style content. Refusing at
// startup rather than at send time is the point: the alternative is discovering
// the rejection when a password-reset mail fails to render for a user.
func TestEmailTemplateOverrideRejectionIsFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "verification.html"),
		[]byte(`<p>hi</p><script>fetch("//evil.test")</script>`), 0o600); err != nil {
		t.Fatalf("write override template: %v", err)
	}

	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	env["VAULT_EMAIL_TEMPLATES_DIR"] = dir

	res := runVault(t, vaultRun{env: env})
	requireExit(t, res, 1, "Failed to initialize email templates")
	if dialable(addr) {
		t.Fatal("the server bound its port with a rejected email template")
	}
}

// TestAdminTokenInitFailureIsNotFatal is the counterweight to the tests above.
// The admin token is provisioned on first boot, and a database that refuses the
// write must be logged and survived: the token is an administrative convenience,
// and refusing to serve authentication traffic because of it would turn a
// degraded admin path into a full outage.
func TestAdminTokenInitFailureIsNotFatal(t *testing.T) {
	stub := startPGStub(t,
		pgRule{match: "INSERT INTO auth.admin_config", errCode: "42501", errMsg: "permission denied for table admin_config"},
	)
	addr := freeAddr(t)

	res := bootAndShutdown(t, vaultRun{env: bootEnv(t, stub, addr)}, addr, syscall.SIGTERM, nil)
	requireExit(t, res, 0, "Admin token init error")
	if !strings.Contains(res.stderr, "Shutting down...") {
		t.Fatalf("the server did not reach a normal shutdown\nstderr:\n%s", res.stderr)
	}
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// signingKeyPEM returns a PKCS#8 RSA private key in PEM form and the key id
// vault42 will derive from it, so a test can assert that the published JWKS
// names that exact key.
func signingKeyPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal signing key: %v", err)
	}
	encoded := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	_, kid, err := vaultcrypto.LoadSigningKeyPEM([]byte(encoded))
	if err != nil {
		t.Fatalf("derive key id: %v", err)
	}
	return encoded, kid
}

// recoveryPublicKeyPEM returns a PEM-encoded RSA public key for the escrow path.
func recoveryPublicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate recovery key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal recovery key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// deadPort returns a loopback port with nothing listening on it.
func deadPort(t *testing.T) string {
	t.Helper()
	_, port, err := net.SplitHostPort(freeAddr(t))
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	return port
}

// occupiedAddr returns an address held open for the lifetime of the test.
func occupiedAddr(t *testing.T) string {
	t.Helper()
	addr := freeAddr(t)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("hold %s open: %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return addr
}

// TestBuiltInOAuthProvidersAreRegisteredFromCredentials covers the three
// hardcoded social providers. Each is registered only when both its client id
// and its client secret are present, and each is handed a redirect URI built
// from VAULT_ORIGIN. A wrong or missing redirect URI is rejected by the provider
// at the far end of a browser redirect, which is the least debuggable place for
// a configuration mistake to surface, so it is asserted here at startup instead.
func TestBuiltInOAuthProvidersAreRegisteredFromCredentials(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	origin := env["VAULT_ORIGIN"]

	for _, p := range []struct{ envID, id string }{
		{"VAULT_OAUTH_GOOGLE_CLIENT_ID", "google-client-id"},
		{"VAULT_OAUTH_GITHUB_CLIENT_ID", "github-client-id"},
		{"VAULT_OAUTH_FACEBOOK_CLIENT_ID", "facebook-client-id"},
	} {
		env[p.envID] = p.id
	}
	secret := "oauth-client-secret-fixture"
	for _, name := range []string{"GOOGLE", "GITHUB", "FACEBOOK"} {
		env["VAULT_OAUTH_"+name+"_CLIENT_SECRET_FILE"] = secretFile(t, t.TempDir(), name, secret)
	}

	locations := map[string]string{}
	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, func(t *testing.T) {
		for _, name := range []string{"google", "github", "facebook"} {
			code, loc := getNoRedirect(t, addr, "/auth/oauth2/authorize?provider="+name)
			if code != http.StatusFound {
				t.Fatalf("authorize for %s = %d, want 302", name, code)
			}
			locations[name] = loc
		}
	})
	requireExit(t, res, 0, "Shutting down...")

	for name, wantHost := range map[string]string{
		"google":   "accounts.google.com",
		"github":   "github.com",
		"facebook": "facebook.com",
	} {
		loc := locations[name]
		u, err := url.Parse(loc)
		if err != nil {
			t.Fatalf("%s redirect is not a URL: %v", name, err)
		}
		if !strings.HasSuffix(u.Host, wantHost) {
			t.Fatalf("%s redirect went to %q, want a %s host", name, u.Host, wantHost)
		}
		if got := u.Query().Get("client_id"); got != name+"-client-id" {
			t.Fatalf("%s redirect carries client_id %q, want %q", name, got, name+"-client-id")
		}
		if got, want := u.Query().Get("redirect_uri"), origin+"/auth/oauth2/callback/"+name; got != want {
			t.Fatalf("%s redirect_uri = %q, want %q", name, got, want)
		}
	}
	requireNoSecretLeak(t, res, secret)
}

// TestOAuthRoutesAreAbsentWithoutProviders is the other half: with no provider
// credentials the OAuth routes are never registered at all. A deployment that
// exposed an authorize endpoint answering "unknown_provider" would advertise a
// social login it cannot perform.
func TestOAuthRoutesAreAbsentWithoutProviders(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)

	var code int
	res := bootAndShutdown(t, vaultRun{env: bootEnv(t, stub, addr)}, addr, syscall.SIGTERM, func(t *testing.T) {
		code, _ = getNoRedirect(t, addr, "/auth/oauth2/authorize?provider=google")
	})
	requireExit(t, res, 0, "Shutting down...")
	if code != http.StatusNotFound {
		t.Fatalf("authorize without providers = %d, want 404", code)
	}
}

// TestMintReportsToTheMetricsCollector covers the one line that only runs when
// minting and metrics are both on. A nil *metrics.Collector passed as a typed
// nil would be non-nil at the interface and panic on the first mint, so the
// collector is assigned through an interface variable that stays nil when
// metrics are off; this is the configuration where it must not stay nil.
func TestMintReportsToTheMetricsCollector(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	env["VAULT_MINT_ENABLED"] = "true"
	env["VAULT_MINT_AUDIENCE"] = "https://beon3.test"
	env["VAULT_MINT_ROLES"] = "service"
	env["VAULT_METRICS_ENABLED"] = "true"
	scrapeAddr := freeAddr(t)
	env["VAULT_METRICS_ADDR"] = scrapeAddr

	var mintStatus, metricsStatus int
	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, func(t *testing.T) {
		metricsStatus, _ = scrape(t, scrapeAddr)
		mintStatus, _ = getNoRedirect(t, addr, "/mint")
	})

	requireExit(t, res, 0, "Mint enabled: signing for audience")
	if metricsStatus != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", metricsStatus)
	}
	if mintStatus == http.StatusNotFound {
		t.Fatal("/mint is not routed even though minting is enabled")
	}
	if !strings.Contains(res.stderr, "Prometheus metrics enabled") {
		t.Fatalf("metrics were not announced\nstderr:\n%s", res.stderr)
	}
}

// TestMintSignsWithTheBootSigningKey is the end-to-end proof that the signer
// main() hands the mint service is the key the server publishes. The bearer
// token is minted in the test with the same file key the server loads, which is
// the only way to reach POST /mint without a client credential from the
// database, and the returned assertion is then verified against that key with
// the issuer and audience the configuration set.
//
// Without this, a mint service wired to the wrong key would still start, still
// log "Mint enabled", and still answer 200; the tokens would simply fail
// verification at whichever service consumed them.
func TestMintSignsWithTheBootSigningKey(t *testing.T) {
	keyPEM, kid := signingKeyPEM(t)
	key, _, err := vaultcrypto.LoadSigningKeyPEM([]byte(keyPEM))
	if err != nil {
		t.Fatalf("load fixture signing key: %v", err)
	}

	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	origin := env["VAULT_ORIGIN"]
	const mintAudience = "https://beon3.test"
	env["SIGNING_KEY_FILE"] = secretFile(t, t.TempDir(), "signing.pem", keyPEM)
	env["VAULT_MINT_ENABLED"] = "true"
	env["VAULT_MINT_AUDIENCE"] = mintAudience
	env["VAULT_MINT_ROLES"] = "service"
	env["VAULT_MINT_SCOPES"] = "beon3:read"

	var status int
	var body string
	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, func(t *testing.T) {
		caller := vaultcrypto.VaultClaims{
			RegisteredClaims: vjwt.RegisteredClaims{
				Issuer:    origin,
				Subject:   "beon3-service",
				Audience:  vjwt.ClaimStrings{origin},
				ExpiresAt: vjwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				IssuedAt:  vjwt.NewNumericDate(time.Now()),
			},
			ClientID:  "beon3-client",
			Scopes:    []string{handler.MintScope},
			TokenType: "Bearer",
		}
		bearer, err := vaultcrypto.SignToken(caller, key, kid)
		if err != nil {
			t.Fatalf("sign the caller token: %v", err)
		}
		status, body = postJSON(t, addr, "/mint", bearer,
			`{"subject":"user-42","roles":["service"],"scopes":["beon3:read"]}`)
	})
	requireExit(t, res, 0, "Mint enabled: signing for audience")

	if status != http.StatusOK {
		t.Fatalf("POST /mint = %d, want 200 (body %s)", status, body)
	}
	var minted struct {
		AccessToken string `json:"access_token"`
		KID         string `json:"kid"`
		Audience    string `json:"audience"`
	}
	if err := json.Unmarshal([]byte(body), &minted); err != nil {
		t.Fatalf("mint response is not JSON: %v (body %s)", err, body)
	}
	if minted.KID != kid {
		t.Fatalf("minted token reports kid %q, want the boot signing key %q", minted.KID, kid)
	}
	if minted.Audience != mintAudience {
		t.Fatalf("minted audience = %q, want %q", minted.Audience, mintAudience)
	}

	claims, err := vaultcrypto.ParseAndValidate(minted.AccessToken,
		func(*vjwt.Token) (any, error) { return &key.PublicKey, nil }, origin, mintAudience)
	if err != nil {
		t.Fatalf("the minted token does not verify against the boot signing key: %v", err)
	}
	if claims.Subject != "user-42" {
		t.Fatalf("minted subject = %q, want %q", claims.Subject, "user-42")
	}
}

// TestAnIncompleteDeferredEmailDrainIsReportedAtShutdown is the last thing the
// process does and the only report anyone gets that it did not finish.
//
// Signup verification, password reset, the import-claim link, the account-locked
// notice, the email OTP fallback and the new-country notices are all sent off the
// request path on a bounded pool. Shutdown drains that pool before the cache and
// the database pool are closed, because a send that is still running writes its
// token to the cache and then mails the link — closing the cache first hands the
// user a verification link that can never work.
//
// The drain is bounded by VAULT_SHUTDOWN_TIMEOUT so a wedged relay cannot hold
// the process open past its termination grace period. When that bound is what
// ends the drain, some number of users have a mail nobody sent and a token
// nobody can redeem, and this line is the only place that is recorded: the
// process still exits 0, because refusing to exit is the failure mode the
// deadline exists to prevent.
//
// The control matters as much as the warning. An ordinary shutdown, with the
// same binary and the same short deadline, must not print it — a drain warning
// on every rollout is one an operator stops reading.
func TestAnIncompleteDeferredEmailDrainIsReportedAtShutdown(t *testing.T) {
	const warning = "WARNING: deferred email drain incomplete"

	boot := func(t *testing.T, stall bool) vaultResult {
		t.Helper()
		stub := startPGStub(t, adminTokenRule("$argon2id$already-provisioned"))
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		// Short enough that the test does not wait out a production grace
		// period, long enough that an idle server drains its listener well
		// inside it.
		env["VAULT_SHUTDOWN_TIMEOUT"] = "250ms"
		if stall {
			env[vaultChildStallDeferwork] = "1"
		}
		return bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)
	}

	t.Run("a send still running at the deadline is reported", func(t *testing.T) {
		res := boot(t, true)
		requireExit(t, res, 0, warning)
		// The process still has to come down. A drain that waited for the
		// wedged relay would be killed by the orchestrator instead, taking
		// every other live connection with it.
		if !strings.Contains(res.stderr, "deferwork: drain deadline expired") {
			t.Errorf("the pool did not report the expired deadline\nstderr:\n%s", res.stderr)
		}
	})

	t.Run("an ordinary shutdown reports nothing", func(t *testing.T) {
		res := boot(t, false)
		requireExit(t, res, 0, "")
		if strings.Contains(res.stderr, warning) {
			t.Errorf("a shutdown with nothing deferred warned about an incomplete drain; the warning "+
				"is only useful if it means something\nstderr:\n%s", res.stderr)
		}
	})
}
