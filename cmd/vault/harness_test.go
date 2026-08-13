package main

// Child-process harness.
//
// main() is not a function this package can call and then make assertions
// about. It ends in log.Fatalf on every startup failure, and log.Fatalf calls
// os.Exit, which takes the test binary down with it; on the success path it
// blocks in ListenAndServe until a signal arrives. Both of those are the
// contract, not an obstacle to it: an operator judges this binary by its exit
// status and by what it writes to stderr, and a test that cannot observe those
// two things is not testing the entry point.
//
// So the tests run vault42 the way an operator does, as a process. TestMain
// re-executes this same test binary with vaultChildEnv set, and the child hands
// control straight to main() with an argv the parent chose. Because the child is
// the coverage-instrumented test binary and Go flushes coverage counters on
// os.Exit, the statements a child executes (including the ones behind
// log.Fatalf) are credited to this package's profile.
//
// Nothing here starts a container. The database is the scripted wire stub in
// pgstub_test.go and the listening socket is a loopback port the parent picked.

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	// vaultChildEnv switches this binary from "run the tests" to "be vault42".
	vaultChildEnv = "VAULT42_TEST_CHILD"
	// vaultChildArgs carries argv[1:] for the child, unit-separated so that an
	// argument may contain spaces or be empty.
	vaultChildArgs = "VAULT42_TEST_CHILD_ARGS"
	vaultArgsSep   = "\x1f"
	// vaultChildStarveEntropy runs the child over a CSPRNG that has stopped
	// answering. See starvedReader.
	vaultChildStarveEntropy = "VAULT42_TEST_STARVE_ENTROPY"
)

// starvedReader is a CSPRNG that has run out. Several checks in this package sit
// behind a crypto/rand.Reader read that a healthy Linux host never fails: the
// real reader does not report an error at all, it takes the process down.
// Installing this one is what makes those checks observable, both in the child
// (the ephemeral signing key and its key id) and in the parent (the nonce
// `vault kms wrap` draws for its AEAD seal).
type starvedReader struct{}

func (starvedReader) Read([]byte) (int, error) { return 0, errors.New("entropy exhausted") }

// TestMain is the fork point. Without the child branch the tests below would
// have no way to reach main() at all.
func TestMain(m *testing.M) {
	if os.Getenv(vaultChildEnv) == "1" {
		// Swapped here because main() takes no arguments and holds no seam: the
		// entropy source it uses is the process-wide one, so the only place to
		// starve it is before control is handed over.
		if os.Getenv(vaultChildStarveEntropy) == "1" {
			rand.Reader = starvedReader{}
		}
		os.Args = append([]string{"vault"}, childArgs()...)
		main()
		// Reached only when main() returns rather than exiting: --version, a
		// handled CLI subcommand, or a server that shut down gracefully. Exit 0
		// is what the real binary does there.
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func childArgs() []string {
	raw := os.Getenv(vaultChildArgs)
	if raw == "" {
		return nil
	}
	return strings.Split(raw, vaultArgsSep)
}

// ---------------------------------------------------------------------------
// Running the binary
// ---------------------------------------------------------------------------

// vaultRun describes one invocation of the vault42 binary.
type vaultRun struct {
	args  []string          // argv[1:]
	env   map[string]string // environment overrides; a "" value unsets the variable
	dir   string            // working directory; defaults to the package directory
	stdin string
}

// vaultResult is what an operator sees: an exit status and two streams.
type vaultResult struct {
	code   int
	stdout string
	stderr string
}

// vaultProc is a running child.
type vaultProc struct {
	cmd    *exec.Cmd
	stdout *syncBuffer
	stderr *syncBuffer
	done   chan error
	waited bool
	result vaultResult
}

// startVault launches the binary and returns without waiting for it. Use it for
// the server path, where the process only exits once it is signaled.
func startVault(t *testing.T, r vaultRun) *vaultProc {
	t.Helper()

	cmd := exec.Command(os.Args[0]) // #nosec G204 -- re-executes this test binary
	cmd.Env = childEnv(r.env, r.args)
	cmd.Dir = r.dir
	if cmd.Dir == "" {
		cmd.Dir = packageDir(t)
	}
	if r.stdin != "" {
		cmd.Stdin = strings.NewReader(r.stdin)
	}

	p := &vaultProc{cmd: cmd, stdout: &syncBuffer{}, stderr: &syncBuffer{}, done: make(chan error, 1)}
	cmd.Stdout = p.stdout
	cmd.Stderr = p.stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start vault child: %v", err)
	}
	go func() { p.done <- cmd.Wait() }()

	t.Cleanup(func() {
		if p.waited {
			return
		}
		// A test that failed before signaling would otherwise leave a server
		// holding a port for the rest of the run.
		_ = cmd.Process.Kill()
		<-p.done
	})
	return p
}

// runVault launches the binary and waits for it to exit on its own.
func runVault(t *testing.T, r vaultRun) vaultResult {
	t.Helper()
	return startVault(t, r).wait(t, 60*time.Second)
}

// signal delivers sig to the child.
func (p *vaultProc) signal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := p.cmd.Process.Signal(sig); err != nil {
		t.Fatalf("signal %v: %v", sig, err)
	}
}

// wait blocks until the child exits and returns its observable result. A race
// detector report is turned into a test failure here rather than left to be
// mistaken for an ordinary non-zero exit.
func (p *vaultProc) wait(t *testing.T, timeout time.Duration) vaultResult {
	t.Helper()
	if p.waited {
		return p.result
	}

	select {
	case err := <-p.done:
		p.waited = true
		code := 0
		var ee *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &ee):
			code = ee.ExitCode()
		default:
			t.Fatalf("wait for vault child: %v", err)
		}
		p.result = vaultResult{code: code, stdout: p.stdout.String(), stderr: p.stderr.String()}
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		<-p.done
		p.waited = true
		t.Fatalf("vault child did not exit within %s\nstdout:\n%s\nstderr:\n%s",
			timeout, p.stdout.String(), p.stderr.String())
	}

	if strings.Contains(p.result.stderr, "DATA RACE") {
		t.Fatalf("race detector fired inside the vault42 process:\n%s", p.result.stderr)
	}
	return p.result
}

// awaitStderr blocks until the child's stderr contains want. It is the signal
// that a startup stage completed, for stages that have no socket to poll.
func (p *vaultProc) awaitStderr(t *testing.T, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(p.stderr.String(), want) {
			return
		}
		select {
		case err := <-p.done:
			p.done <- err
			t.Fatalf("vault child exited before logging %q\nstdout:\n%s\nstderr:\n%s",
				want, p.stdout.String(), p.stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatalf("vault child never logged %q within %s\nstderr:\n%s", want, timeout, p.stderr.String())
}

// childEnv builds the environment for a child. The inherited environment is
// filtered first: a VAULT_* or DB_* variable left over from the developer's
// shell would otherwise silently reconfigure the process under test and make a
// green run mean nothing.
func childEnv(overrides map[string]string, args []string) []string {
	parent := os.Environ()
	env := make([]string, 0, len(parent)+len(overrides))
	for _, kv := range parent {
		name, _, _ := strings.Cut(kv, "=")
		if configEnvVar(name) {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, vaultChildEnv+"=1", vaultChildArgs+"="+strings.Join(args, vaultArgsSep))
	for k, v := range overrides {
		if v == "" {
			continue
		}
		env = append(env, k+"="+v)
	}
	return env
}

// configEnvPrefixes are the environment namespaces config.Load, pgx, and the
// secret-file convention read from.
var configEnvPrefixes = []string{
	"VAULT_", "VAULT42_", "DB_", "PG", "ADMIN_TOKEN", "MASTER_KEY", "HMAC_SECRET",
	"KMS_ROOT_KEY", "SIGNING_KEY", "SENDGRID_", "SMTP_", "REDIS_", "CACHE_BACKEND",
	"LISTEN_ADDR", "LOG_LEVEL", "CORS_", "TRUSTED_PROXIES", "REAL_IP_HEADER",
	"GEO_", "IP_ALLOWLIST", "IP_BLOCKLIST", "SEED",
}

func configEnvVar(name string) bool {
	for _, p := range configEnvPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// syncBuffer collects a child's output while the parent reads it concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ---------------------------------------------------------------------------
// Environment fixtures
// ---------------------------------------------------------------------------

// bootEnv is the smallest environment in which vault42 starts and serves: a
// production profile that passes Validate (including the 32-byte master key
// production now requires at boot), plaintext listening (the tests do not
// exercise TLS termination), the scripted database, and an in-memory cache.
//
// Every startup test builds on this and overrides only the variables it is about,
// so a failure names one cause instead of a configuration soup.
func bootEnv(t *testing.T, stub *pgStub, listen string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	return map[string]string{
		"VAULT_PROFILE":         string(profileProduction),
		"VAULT_ORIGIN":          "https://vault.test",
		"LISTEN_ADDR":           listen,
		"VAULT_TLS_ENABLED":     "false",
		"VAULT_ALLOW_PLAINTEXT": "true",
		"DB_HOST":               stub.host(),
		"DB_PORT":               stub.port(),
		"DB_SSLMODE":            "disable",
		"DB_APP_PASSWORD_FILE":  secretFile(t, dir, "db_app", dbPassword),
		"DB_MIG_PASSWORD_FILE":  secretFile(t, dir, "db_mig", dbPassword),
		"HMAC_SECRET_FILE":      secretFile(t, dir, "hmac", strings.Repeat("h", 32)),
		"VAULT_PEPPER_FILE":     secretFile(t, dir, "pepper", strings.Repeat("p", 32)),
		"MASTER_KEY_FILE":       secretFile(t, dir, "master", strings.Repeat("m", 32)),
		"CACHE_BACKEND":         "memory",
		"VAULT_HIBP_CHECK":      "false",
	}
}

// dbPassword is deliberately distinctive: several tests assert that it never
// reaches stderr, and a generic value would match by accident.
const dbPassword = "sup3r-s3cret-db-passw0rd"

// profileProduction mirrors config.ProfileProduction without importing the
// config package into every table row.
type profileName string

const (
	profileProduction profileName = "production"
	profileEmbedded   profileName = "embedded"
	profileDev        profileName = "dev"
	profileHoneypot   profileName = "honeypot"
)

// secretFile writes a secret to dir/name and returns its path.
func secretFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write secret file %s: %v", path, err)
	}
	return path
}

// freeAddr reserves a loopback port, releases it, and returns the address. The
// window between release and the child's bind is a theoretical race that no
// other listener in this suite competes for.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return addr
}

// awaitServing polls the child's HTTP listener until it answers. Waiting for a
// real response rather than for a log line is what makes "the server started" an
// observation instead of a claim.
func awaitServing(t *testing.T, p *vaultProc, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		select {
		case err := <-p.done:
			p.done <- err
			t.Fatalf("vault child exited before it served\nstdout:\n%s\nstderr:\n%s",
				p.stdout.String(), p.stderr.String())
		default:
		}
		resp, err := client.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("vault42 never served on %s within %s\nstderr:\n%s", addr, timeout, p.stderr.String())
}

// tryGet is get without the assertion, for probes that expect the listener to
// disappear underneath them.
func tryGet(addr, path string) (int, string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + path)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close() //nolint:errcheck // response body of a finished request
	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, body.String(), nil
}

// postJSON issues an authenticated JSON request against the running child.
func postJSON(t *testing.T, addr, path, bearer, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request for %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body of a finished request
	var out bytes.Buffer
	if _, err := out.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body of %s: %v", path, err)
	}
	return resp.StatusCode, out.String()
}

// getNoRedirect issues a request without following redirects, so a test can
// assert where the server pointed the browser rather than what the third party
// answered.
func getNoRedirect(t *testing.T, addr, path string) (int, string) {
	t.Helper()
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://" + addr + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body of a finished request
	return resp.StatusCode, resp.Header.Get("Location")
}

// get issues one request against the running child and returns status and body.
func get(t *testing.T, addr, path string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body of a finished request
	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body of %s: %v", path, err)
	}
	return resp.StatusCode, body.String()
}

// bootAndShutdown starts vault42, waits until it serves, runs probe, then sends
// sig and returns the result. It is the shape every full-startup test takes.
func bootAndShutdown(t *testing.T, r vaultRun, addr string, sig syscall.Signal, probe func(t *testing.T)) vaultResult {
	t.Helper()
	p := startVault(t, r)
	awaitServing(t, p, addr, 60*time.Second)
	if probe != nil {
		probe(t)
	}
	p.signal(t, sig)
	return p.wait(t, 60*time.Second)
}

// ---------------------------------------------------------------------------
// Locating the tree
// ---------------------------------------------------------------------------

// packageDir is the directory go test runs the binary from.
func packageDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return dir
}

// repoRoot walks up from the package directory to the module root, which is
// where the migrations/ directory the migration runner reads lives.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir := packageDir(t)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the package directory")
		}
		dir = parent
	}
}

// migrationNames lists the files the migration runner would apply, so a test can
// tell the stub to report them as already applied.
func migrationNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(repoRoot(t), "migrations"))
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("no .sql files in migrations/; the applied-migrations fixture would be vacuous")
	}
	return names
}

// requireExit fails the test unless the child exited with code and wrote want to
// stderr. Both halves matter: an operator scripting a deployment reads the exit
// status, and the human reading the logs afterwards reads the message.
func requireExit(t *testing.T, res vaultResult, code int, want string) {
	t.Helper()
	if res.code != code {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s",
			res.code, code, res.stdout, res.stderr)
	}
	if want != "" && !strings.Contains(res.stderr, want) {
		t.Fatalf("stderr does not contain %q\nstderr:\n%s", want, res.stderr)
	}
}

// requireNoSecretLeak asserts that none of the given secrets appear anywhere in
// the child's output. Startup logs a redacted configuration summary and several
// database errors carry the connection URL, so this is the assertion that keeps
// a diagnostic improvement from turning into a credential disclosure.
func requireNoSecretLeak(t *testing.T, res vaultResult, secrets ...string) {
	t.Helper()
	combined := res.stdout + res.stderr
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(combined, s) {
			t.Fatalf("secret %q leaked into the process output:\n%s", s, combined)
		}
	}
}

// dialable reports whether something is listening on addr.
func dialable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
