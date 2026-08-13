package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// childRoleRun runs main() with no command-line arguments.
const childRoleRun = "run"

// childRoleVersion runs main() with --version.
const childRoleVersion = "run --version"

// TestMain either runs the test suite or, when the process was launched as a
// gateway child, hands control to main() and never returns to the testing
// framework. See childRoleEnv for why the binary has to be able to do both.
func TestMain(m *testing.M) {
	if role := os.Getenv(childRoleEnv); role != "" {
		os.Args = append([]string{"admin-gateway"}, strings.Fields(role)[1:]...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fixture is everything a gateway child needs to boot: a certificate
// authority, a stub database, a reserved loopback port, a working directory and
// the secret files the _FILE convention points at.
type fixture struct {
	pki     *pki
	pg      *fakePostgres
	addr    string
	workDir string

	masterKeyFile  string
	dbPasswordFile string
}

// newFixture builds a bootable configuration. The stub database is started
// first so that its cleanup runs after the cleanup of any child launched later,
// which is what stops it from waiting on a session belonging to a process that
// has not been killed yet.
func newFixture(t *testing.T) *fixture {
	t.Helper()

	f := &fixture{
		pki:     newPKI(t),
		pg:      startFakePostgres(t),
		addr:    freeAddr(t),
		workDir: t.TempDir(),
	}
	f.masterKeyFile = writeSecret(t, "master-key", []byte(testMasterKey))
	f.dbPasswordFile = writeSecret(t, "db-admin-password", []byte("adminpw"))
	return f
}

// env returns the environment of a gateway that can reach the stub database,
// with extra appended last so a test can override or add to it.
func (f *fixture) env(extra ...string) []string {
	base := []string{
		"ADMIN_GW_LISTEN_ADDR=" + f.addr,
		"ADMIN_GW_TLS_CERT_FILE=" + f.pki.serverCertFile,
		"ADMIN_GW_TLS_KEY_FILE=" + f.pki.serverKeyFile,
		"ADMIN_GW_CLIENT_CA_FILE=" + f.pki.clientCAFile,
		"MASTER_KEY_FILE=" + f.masterKeyFile,
		"DB_ADMIN_PASSWORD_FILE=" + f.dbPasswordFile,
		"DB_HOST=" + f.pg.host(),
		"DB_PORT=" + f.pg.port(),
		"DB_NAME=vault",
		"DB_SSLMODE=disable",
	}
	return append(base, extra...)
}

// start launches a gateway that is expected to come up, and blocks until it is
// accepting connections.
func (f *fixture) start(t *testing.T, extra ...string) *child {
	t.Helper()

	c := launch(t, childRoleRun, f.workDir, f.env(extra...)...)
	c.waitForLog(t, "admin-gateway: listening on "+f.addr)
	c.waitForListener(t, f.addr)
	return c
}

// httpClient returns a client that presents the operator certificate and
// trusts the fixture's CA.
func (f *fixture) httpClient() *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: f.pki.tlsClientConfig()},
	}
}

// TestVersionFlagShortCircuitsBeforeConfiguration is the reason --version is
// the first thing main() looks at.
//
// An operator debugging a container that will not start needs to be able to ask
// the binary what it is without supplying a master key, a certificate or a
// database. This child is launched with no gateway configuration at all, so if
// the version check ever moves below LoadConfig the process exits 1 with a
// config error instead of printing anything.
//
// The stamps are also asserted by value. Version, GitCommit and BuildTime are
// set at link time with -ldflags, and their compiled-in defaults are what tells
// a reader that a binary did not come off the release pipeline. A build that
// reported a plausible-looking version by default would erase that signal.
func TestVersionFlagShortCircuitsBeforeConfiguration(t *testing.T) {
	c := launch(t, childRoleVersion, t.TempDir())

	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("--version exited %d, want 0\nstderr:\n%s", code, c.stderr.String())
	}

	want := fmt.Sprintf("vault-admin-gateway %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
	if got := c.stdout.String(); got != want {
		t.Errorf("--version stdout = %q, want %q", got, want)
	}
	if Version != "dev" || GitCommit != "unknown" || BuildTime != "unknown" {
		t.Errorf("unstamped build reports %s/%s/%s, want dev/unknown/unknown", Version, GitCommit, BuildTime)
	}
	if out := c.stderr.String(); out != "" {
		t.Errorf("--version wrote to stderr: %q", out)
	}
}

// TestConfigErrorIsFatalBeforeAnyDatabaseWork checks that a configuration
// failure stops the process at the first step.
//
// LoadConfig is the only place the gateway validates its own inputs. If its
// error were logged and swallowed, the process would carry on with an empty
// certificate path or a short master key and fail later, in the middle of
// setup, with a much less obvious message. The exit code matters as much as the
// text: a container that exits non-zero is restarted and reported, one that
// exits 0 looks like a clean shutdown.
func TestConfigErrorIsFatalBeforeAnyDatabaseWork(t *testing.T) {
	f := newFixture(t)

	tests := []struct {
		name    string
		env     []string
		wantLog string
	}{
		{
			name:    "no server certificate",
			env:     []string{"ADMIN_GW_TLS_CERT_FILE="},
			wantLog: "admin-gateway: config error: ADMIN_GW_TLS_CERT_FILE is required",
		},
		{
			name:    "no client CA",
			env:     []string{"ADMIN_GW_CLIENT_CA_FILE="},
			wantLog: "admin-gateway: config error: ADMIN_GW_CLIENT_CA_FILE is required",
		},
		{
			name:    "no master key",
			env:     []string{"MASTER_KEY_FILE="},
			wantLog: "admin-gateway: config error: MASTER_KEY_FILE is required",
		},
		{
			name:    "non-loopback bind",
			env:     []string{"ADMIN_GW_LISTEN_ADDR=0.0.0.0:9443"},
			wantLog: "admin-gateway: config error: ADMIN_GW_LISTEN_ADDR must bind to loopback",
		},
		{
			name:    "unparseable killswitch",
			env:     []string{"ADMIN_GW_KILLSWITCH=True"},
			wantLog: "admin-gateway: config error: ADMIN_GW_KILLSWITCH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := launch(t, childRoleRun, f.workDir, f.env(tt.env...)...)

			if code := c.waitForExit(t); code != 1 {
				t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, c.stderr.String())
			}
			if got := c.stderr.String(); !strings.Contains(got, tt.wantLog) {
				t.Errorf("stderr does not contain %q:\n%s", tt.wantLog, got)
			}
			if f.pg.sawAnyConnection() {
				t.Error("the gateway reached the database despite a configuration error")
			}
		})
	}
}

// TestUnreachableDatabaseIsFatalAndRedacted covers the connection failure an
// operator is most likely to hit, and the redaction that keeps it from being a
// secret disclosure.
//
// The gateway builds its connection string by interpolating the vault_admin
// password, so any error text that echoes that string is a credential in a log
// aggregator. sanitizeDBError exists for that, and this test asserts the
// property that matters rather than the shape of the current message: the
// password must not appear anywhere in the process output.
func TestUnreachableDatabaseIsFatalAndRedacted(t *testing.T) {
	f := newFixture(t)
	closed := freeAddr(t)
	host, port, err := net.SplitHostPort(closed)
	if err != nil {
		t.Fatalf("split %q: %v", closed, err)
	}

	c := launch(t, childRoleRun, f.workDir, f.env("DB_HOST="+host, "DB_PORT="+port)...)

	if code := c.waitForExit(t); code != 1 {
		t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, c.stderr.String())
	}

	out := c.stderr.String()
	if !strings.Contains(out, "admin-gateway: database error:") {
		t.Errorf("stderr does not report a database error:\n%s", out)
	}
	if strings.Contains(out, "adminpw") {
		t.Errorf("the vault_admin password leaked into the log:\n%s", out)
	}
}

// TestAutoMigrateRunsBeforeTheApplicationConnection covers the migration stage,
// which runs as a different, more privileged database role than the rest of the
// process.
//
// Migrations connect as vault_mig for DDL and are torn down before the
// vault_admin pool is opened. Every failure in that stage is fatal on purpose:
// a gateway that started with a half-applied schema would fail later in ways
// that look like data corruption rather than a failed deployment.
func TestAutoMigrateRunsBeforeTheApplicationConnection(t *testing.T) {
	t.Run("unreachable database is fatal", func(t *testing.T) {
		f := newFixture(t)
		closed := freeAddr(t)
		host, port, _ := net.SplitHostPort(closed)

		c := launch(t, childRoleRun, f.workDir,
			f.env("ADMIN_GW_AUTO_MIGRATE=true", "DB_HOST="+host, "DB_PORT="+port)...)

		if code := c.waitForExit(t); code != 1 {
			t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, c.stderr.String())
		}
		out := c.stderr.String()
		if !strings.Contains(out, "admin-gateway: migration connect error:") {
			t.Errorf("stderr does not report a migration connect error:\n%s", out)
		}
		if strings.Contains(out, "adminpw") {
			t.Errorf("a password leaked into the migration connect error:\n%s", out)
		}
	})

	t.Run("missing migrations directory is fatal", func(t *testing.T) {
		f := newFixture(t)

		c := launch(t, childRoleRun, f.workDir, f.env("ADMIN_GW_AUTO_MIGRATE=true")...)

		if code := c.waitForExit(t); code != 1 {
			t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, c.stderr.String())
		}
		if out := c.stderr.String(); !strings.Contains(out, "admin-gateway: migration error:") {
			t.Errorf("stderr does not report a migration error:\n%s", out)
		}
		if !f.pg.sawStatementContaining("schema_migrations") {
			t.Error("the migration runner never created its tracking table")
		}
	})

	t.Run("empty migrations directory completes and boots", func(t *testing.T) {
		f := newFixture(t)
		if err := os.Mkdir(filepath.Join(f.workDir, "migrations"), 0o755); err != nil {
			t.Fatalf("create migrations directory: %v", err)
		}

		c := f.start(t, "ADMIN_GW_AUTO_MIGRATE=true")
		c.waitForLog(t, "admin-gateway: migrations complete")

		if !f.pg.sawStatementContaining("FROM public.schema_migrations") {
			t.Error("the migration runner never read the applied-versions table")
		}

		c.signal(t, syscall.SIGTERM)
		if code := c.waitForExit(t); code != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
		}
	})
}

// TestMigrationsUseTheDedicatedDDLRole is the least-privilege test for the
// database side of the gateway.
//
// DDL runs as vault_mig and everything afterwards as vault_admin, from two
// separate secret files, and the migration connection is closed before the
// application pool opens. Collapsing the two, by reusing DatabaseURL for
// migrations or by pointing both at one password file, would leave a
// long-lived pool holding a role that can drop tables. Nothing else in the
// suite would notice, because both roles behave identically against a stub that
// answers every query the same way.
//
// The stub demands a cleartext password, so the assertion covers the secret as
// well as the role name: a swap of DB_MIG_PASSWORD_FILE and
// DB_ADMIN_PASSWORD_FILE fails here.
func TestMigrationsUseTheDedicatedDDLRole(t *testing.T) {
	f := newFixture(t)
	if err := os.Mkdir(filepath.Join(f.workDir, "migrations"), 0o755); err != nil {
		t.Fatalf("create migrations directory: %v", err)
	}

	c := f.start(t,
		"ADMIN_GW_AUTO_MIGRATE=true",
		"DB_MIG_PASSWORD_FILE="+writeSecret(t, "db-mig-password", []byte("migpw")),
	)
	c.waitForLog(t, "admin-gateway: migrations complete")
	c.waitForLog(t, "admin-gateway: first admin creation error:")

	if !f.pg.sawLogin(login{user: "vault_mig", database: "vault", password: "migpw"}) {
		t.Errorf("no vault_mig login carrying DB_MIG_PASSWORD_FILE; roles seen: %v", f.pg.loginRoles())
	}
	if !f.pg.sawLogin(login{user: "vault_admin", database: "vault", password: "adminpw"}) {
		t.Errorf("no vault_admin login carrying DB_ADMIN_PASSWORD_FILE; roles seen: %v", f.pg.loginRoles())
	}

	roles := f.pg.loginRoles()
	if len(roles) == 0 || roles[0] != "vault_mig" {
		t.Errorf("first login was %v, want migrations to run before the application pool opens", roles)
	}

	c.signal(t, syscall.SIGTERM)
	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
	}
}

// TestOperatorSuppliedDatabasePasswordSurvivesURLEncoding is the wire-level
// half of TestDatabaseURLEscapesPassword. The percent sign is the load-bearing
// case: it used to parse cleanly and authenticate as a different string, so
// the operator saw a wrong-password error against a file they could read.
// The slash is the parse-failure case: without encoding the child never
// completes the handshake. Both roles are asserted because main() builds the
// vault_mig URI independently of Config.DatabaseURL.
func TestOperatorSuppliedDatabasePasswordSurvivesURLEncoding(t *testing.T) {
	t.Run("percent sign in vault_admin password", func(t *testing.T) {
		const password = "ab%cdef"
		f := newFixture(t)
		c := f.start(t, "DB_ADMIN_PASSWORD_FILE="+writeSecret(t, "db-admin-pct", []byte(password)))

		if !f.pg.sawLogin(login{user: "vault_admin", database: "vault", password: password}) {
			t.Errorf("vault_admin did not authenticate as the password on disk; roles seen: %v", f.pg.loginRoles())
		}

		c.signal(t, syscall.SIGTERM)
		if code := c.waitForExit(t); code != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
		}
	})

	t.Run("slash in vault_admin password", func(t *testing.T) {
		const password = "ab/cd"
		f := newFixture(t)
		c := f.start(t, "DB_ADMIN_PASSWORD_FILE="+writeSecret(t, "db-admin-slash", []byte(password)))

		if !f.pg.sawLogin(login{user: "vault_admin", database: "vault", password: password}) {
			t.Errorf("vault_admin did not authenticate as the password on disk; roles seen: %v", f.pg.loginRoles())
		}

		c.signal(t, syscall.SIGTERM)
		if code := c.waitForExit(t); code != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
		}
	})

	t.Run("percent sign in vault_mig password", func(t *testing.T) {
		const password = "ab%cdef"
		f := newFixture(t)
		if err := os.Mkdir(filepath.Join(f.workDir, "migrations"), 0o755); err != nil {
			t.Fatalf("create migrations directory: %v", err)
		}

		c := f.start(t,
			"ADMIN_GW_AUTO_MIGRATE=true",
			"DB_MIG_PASSWORD_FILE="+writeSecret(t, "db-mig-pct", []byte(password)),
		)
		c.waitForLog(t, "admin-gateway: migrations complete")

		if !f.pg.sawLogin(login{user: "vault_mig", database: "vault", password: password}) {
			t.Errorf("vault_mig did not authenticate as the password on disk; roles seen: %v", f.pg.loginRoles())
		}

		c.signal(t, syscall.SIGTERM)
		if code := c.waitForExit(t); code != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
		}
	})
}

// TestMigrationsWithoutAPasswordFileStillUseTheDDLRole records what happens
// when DB_MIG_PASSWORD_FILE is not supplied.
//
// The read failure is swallowed and the migration connection is attempted with
// an empty password, so a deployment that forgot to mount the vault_mig secret
// does not fail with "secret missing" but with whatever the database says about
// an empty password. The role is still vault_mig, so the least-privilege split
// holds; only the diagnostic is poor.
func TestMigrationsWithoutAPasswordFileStillUseTheDDLRole(t *testing.T) {
	f := newFixture(t)
	if err := os.Mkdir(filepath.Join(f.workDir, "migrations"), 0o755); err != nil {
		t.Fatalf("create migrations directory: %v", err)
	}

	c := f.start(t, "ADMIN_GW_AUTO_MIGRATE=true")
	c.waitForLog(t, "admin-gateway: migrations complete")

	if !f.pg.sawLogin(login{user: "vault_mig", database: "vault", password: ""}) {
		t.Errorf("migration login was not vault_mig with an empty password; logins seen: %v", f.pg.loginRoles())
	}

	c.signal(t, syscall.SIGTERM)
	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
	}
}

// TestGatewayStartsAgainstUnmigratedDatabase is the wiring test for the whole
// second half of main().
//
// Every database-backed startup step after the connection is deliberately
// non-fatal: the first-admin bootstrap, seeding and the keystore all log and
// carry on. That is what lets an operator bring the gateway up against a
// database whose schema is not ready yet and then fix it, instead of watching a
// pod crash-loop with no way in. The stub database answers every query with
// "relation does not exist", so this test drives all three of those paths at
// once and asserts they logged and continued rather than exiting.
//
// The absence of the keystore-disabled warning is asserted too, but only
// as a runtime sanity check that the 32-byte key reached the keystore.
// Those init-error / ks==nil branches never ran (keystore.New errors only
// on length, and LoadConfig already refused any other), so a process-level
// test cannot see them. TestKeystoreInitHasNoDeadBranches is the check
// that fails if they are put back.
func TestGatewayStartsAgainstUnmigratedDatabase(t *testing.T) {
	f := newFixture(t)
	c := f.start(t)

	c.waitForLog(t, "admin-gateway: first admin creation error:")
	c.waitForLog(t, "admin-gateway: keystore ensure key error:")

	out := c.stderr.String()
	wantLines := []string{
		fmt.Sprintf("admin-gateway: listen=%s tls=mTLS db=%s:%s/vault", f.addr, f.pg.host(), f.pg.port()),
		"admin-gateway: HMAC_SECRET_FILE not set",
		"admin-gateway: listening on " + f.addr,
	}
	for _, want := range wantLines {
		if !strings.Contains(out, want) {
			t.Errorf("stderr does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "keystore not initialized") {
		t.Errorf("the keystore was disabled despite a valid 32-byte master key:\n%s", out)
	}
	if !f.pg.sawStatementContaining("FROM auth.admin_users") {
		t.Error("the first-admin bootstrap never queried the admin users table")
	}

	c.signal(t, syscall.SIGTERM)
	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
	}
}

// TestKeystoreInitHasNoDeadBranches is the failing-before test for the
// unreachable keystore.New handling that used to sit in main().
//
// keystore.New returns a non-nil error only when len(masterKey) != 32, and
// LoadConfig already refuses any other length, so the previous
//
//	ks, err := keystore.New(...)
//	if err != nil { log.Printf("... keystore init error ...") }
//	if ks != nil { EnsureKey; StartRefreshLoop } else { log "not initialized" }
//
// pair could not run. A child-process test with a valid 32-byte key takes
// the success path either way, which is why TestGatewayStartsAgainstUnmigratedDatabase
// stayed green with the dead branches still there. This reads the AST of
// main() and fails if either branch is restored: the error result of
// keystore.New must be discarded, ks must not be nil-checked, and the
// store must still be used so deleting the feature would not pass.
func TestKeystoreInitHasNoDeadBranches(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", srcPath, err)
	}

	var mainFn *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name.Name == "main" && fn.Recv == nil {
			mainFn = fn
			return false
		}
		return true
	})
	if mainFn == nil || mainFn.Body == nil {
		t.Fatal("no func main in main.go")
	}

	var newAssign *ast.AssignStmt
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "New" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "keystore" {
			return true
		}
		newAssign = as
		return false
	})
	if newAssign == nil {
		t.Fatal("main() no longer calls keystore.New; rewrite this test rather than treating that as the dead-branch fix")
	}

	if len(newAssign.Lhs) != 2 {
		t.Fatalf("keystore.New is assigned to %d result(s), want 2 (store, discarded error)", len(newAssign.Lhs))
	}
	errName := astIdentName(newAssign.Lhs[1])
	// The error is read rather than discarded. Discarding it satisfies coverage
	// without a single exclusion entry, and costs an errcheck suppression plus a
	// nil dereference on the line below the day keystore.New grows a second
	// error path. Reading it and dying loudly is one uncoverable line, which is
	// what the exclusion register exists for.
	//
	// What keeps that line honestly unreachable is not this call site but
	// keystore.New itself, so that is what gets pinned, below.
	if errName == "" {
		t.Fatalf("keystore.New error result at line %d is neither named nor discarded",
			fset.Position(newAssign.Pos()).Line)
	}

	ksName := astIdentName(newAssign.Lhs[0])
	if ksName == "" || ksName == "_" {
		t.Fatal("keystore.New store result is not a named identifier")
	}

	var nilGuards []int
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if astComparesToNil(ifs.Cond, ksName) {
			nilGuards = append(nilGuards, fset.Position(ifs.Pos()).Line)
		}
		return true
	})
	if len(nilGuards) > 0 {
		t.Fatalf("main() still nil-checks %s at line(s) %v; that branch is unreachable after LoadConfig", ksName, nilGuards)
	}

	var sawEnsure, sawRefresh bool
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok || recv.Name != ksName {
			return true
		}
		switch sel.Sel.Name {
		case "EnsureKey":
			sawEnsure = true
		case "StartRefreshLoop":
			sawRefresh = true
		}
		return true
	})
	if !sawEnsure || !sawRefresh {
		t.Fatalf("main() does not use the keystore (EnsureKey=%v StartRefreshLoop=%v); the dead branches must be deleted, not the feature", sawEnsure, sawRefresh)
	}
}

func astIdentName(e ast.Expr) string {
	id, ok := e.(*ast.Ident)
	if !ok {
		return fmt.Sprintf("%T", e)
	}
	return id.Name
}

func astComparesToNil(expr ast.Expr, name string) bool {
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return astComparesToNil(e.X, name)
	case *ast.UnaryExpr:
		return astComparesToNil(e.X, name)
	case *ast.BinaryExpr:
		if e.Op == token.LAND || e.Op == token.LOR {
			return astComparesToNil(e.X, name) || astComparesToNil(e.Y, name)
		}
		if e.Op != token.EQL && e.Op != token.NEQ {
			return false
		}
		x, y := astIdentName(e.X), astIdentName(e.Y)
		return (x == name && y == "nil") || (x == "nil" && y == name)
	default:
		return false
	}
}

// TestListenerEnforcesMutualTLS13 is the security test for the listener
// main() builds by hand.
//
// The gateway holds the vault_admin database role. Its only defenses are the
// loopback bind and this tls.Config, so each field is asserted through observed
// behavior rather than by reading the struct: a client with no certificate is
// refused, a client pinned below TLS 1.3 is refused, and a client holding a
// certificate from the configured CA gets through to the router. Downgrading
// ClientAuth to VerifyClientCertIfGiven or MinVersion to TLS 1.2 would leave
// every other test in this file passing.
func TestListenerEnforcesMutualTLS13(t *testing.T) {
	f := newFixture(t)
	c := f.start(t)
	url := "https://" + f.addr + "/admin/status"

	t.Run("client without a certificate is refused", func(t *testing.T) {
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs:    f.pki.roots,
				ServerName: "127.0.0.1",
				MinVersion: tls.VersionTLS13,
			}},
		}
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("request without a client certificate returned %s, want a handshake failure", resp.Status)
		}
	})

	t.Run("client pinned to TLS 1.2 is refused", func(t *testing.T) {
		cfg := f.pki.tlsClientConfig()
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = tls.VersionTLS12

		client := &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: cfg},
		}
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("TLS 1.2 request returned %s, want the handshake to be refused", resp.Status)
		}
	})

	t.Run("client with a certificate from the configured CA reaches the router", func(t *testing.T) {
		resp, err := f.httpClient().Get(url)
		if err != nil {
			t.Fatalf("mutually authenticated request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
			t.Errorf("negotiated TLS version = %#x, want TLS 1.3", resp.TLS.Version)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			t.Errorf("GET /admin/status = %s, want 401 from the session middleware (body: %s)", resp.Status, body)
		}
	})

	t.Run("client certificate from an untrusted CA is refused", func(t *testing.T) {
		other := newPKI(t)
		cfg := f.pki.tlsClientConfig()
		cfg.Certificates = []tls.Certificate{other.clientCert}

		client := &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: cfg},
		}
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("certificate from an unconfigured CA returned %s, want it to be refused", resp.Status)
		}
	})

	c.signal(t, syscall.SIGTERM)
	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
	}
}

// TestClientCAFailuresAreFatal covers the two ways the mTLS trust anchor can be
// wrong.
//
// Neither is caught by LoadConfig, which only checks that a path was supplied.
// Both must stop the process: a gateway that started with an empty client CA
// pool would present a certificate, demand one back, and then be unable to
// verify any operator, and a gateway that started with no verification at all
// would accept anyone who can reach the port.
func TestClientCAFailuresAreFatal(t *testing.T) {
	tests := []struct {
		name    string
		file    func(t *testing.T) string
		wantLog string
	}{
		{
			name:    "missing file",
			file:    func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.crt") },
			wantLog: "admin-gateway: failed to read client CA:",
		},
		{
			name:    "not a PEM certificate",
			file:    func(t *testing.T) string { return writeSecret(t, "client-ca.crt", []byte("not a certificate")) },
			wantLog: "admin-gateway: failed to parse client CA certificate",
		},
		{
			name: "PEM block that is not a certificate",
			file: func(t *testing.T) string {
				return writeSecret(t, "client-ca.crt", []byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"))
			},
			wantLog: "admin-gateway: failed to parse client CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			c := launch(t, childRoleRun, f.workDir, f.env("ADMIN_GW_CLIENT_CA_FILE="+tt.file(t))...)

			if code := c.waitForExit(t); code != 1 {
				t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, c.stderr.String())
			}
			if out := c.stderr.String(); !strings.Contains(out, tt.wantLog) {
				t.Errorf("stderr does not contain %q:\n%s", tt.wantLog, out)
			}
		})
	}
}

// TestErasureEndpointRequiresHMACSecret covers the wiring of the account
// erasure cascade behind DELETE /admin/users/{id}.
//
// Erasure derives its pseudonyms from the HMAC secret, so without that secret
// the endpoint cannot address the rows it is supposed to delete. Rather than
// deleting the wrong thing, the service is simply not constructed and the route
// answers 503. The escrow public key is separately optional: absent means
// erasure still happens but cannot be reversed. A malformed one is fatal,
// because silently continuing would produce irreversible deletions from an
// operator who asked for recoverable ones.
func TestErasureEndpointRequiresHMACSecret(t *testing.T) {
	t.Run("absent secret disables the endpoint", func(t *testing.T) {
		f := newFixture(t)
		c := f.start(t)

		if out := c.stderr.String(); !strings.Contains(out, "account erasure endpoint disabled") {
			t.Errorf("stderr does not report the endpoint as disabled:\n%s", out)
		}

		c.signal(t, syscall.SIGTERM)
		if code := c.waitForExit(t); code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
	})

	t.Run("secret alone enables it without escrow", func(t *testing.T) {
		f := newFixture(t)
		c := f.start(t, "HMAC_SECRET_FILE="+writeSecret(t, "hmac-secret", []byte("0123456789abcdef")))

		if out := c.stderr.String(); strings.Contains(out, "account erasure endpoint disabled") {
			t.Errorf("the endpoint stayed disabled despite HMAC_SECRET_FILE being set:\n%s", out)
		}

		c.signal(t, syscall.SIGTERM)
		if code := c.waitForExit(t); code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
	})

	t.Run("secret plus a valid escrow key", func(t *testing.T) {
		f := newFixture(t)
		c := f.start(t,
			"HMAC_SECRET_FILE="+writeSecret(t, "hmac-secret", []byte("0123456789abcdef")),
			"VAULT_RECOVERY_PUBLIC_KEY_FILE="+writeSecret(t, "recovery.pub", rsaPublicKeyPEM(t)),
		)

		c.signal(t, syscall.SIGTERM)
		if code := c.waitForExit(t); code != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
		}
	})

	t.Run("malformed escrow key is fatal", func(t *testing.T) {
		f := newFixture(t)
		c := launch(t, childRoleRun, f.workDir, f.env(
			"HMAC_SECRET_FILE="+writeSecret(t, "hmac-secret", []byte("0123456789abcdef")),
			"VAULT_RECOVERY_PUBLIC_KEY_FILE="+writeSecret(t, "recovery.pub", []byte("-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----\n")),
		)...)

		if code := c.waitForExit(t); code != 1 {
			t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, c.stderr.String())
		}
		if out := c.stderr.String(); !strings.Contains(out, "admin-gateway: failed to load recovery public key:") {
			t.Errorf("stderr does not report the escrow key failure:\n%s", out)
		}
	})
}

// TestSeedFileFailuresAreNotFatal covers declarative admin seeding.
//
// Seeding is an operator convenience, not a precondition, so a broken seed file
// must not keep the gateway off the network. A gateway that refused to start
// over a malformed VAULT_SEED_FILE would be unreachable at exactly the moment
// an operator needs to log in and fix it.
func TestSeedFileFailuresAreNotFatal(t *testing.T) {
	validSeed := `{"admins":[{"username":"seeded","password":"correct-horse-battery","role":"super_admin"}]}`

	tests := []struct {
		name    string
		seed    func(t *testing.T) string
		wantLog string
	}{
		{
			name:    "missing file",
			seed:    func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.json") },
			wantLog: "admin-gateway: seed load error:",
		},
		{
			name:    "malformed JSON",
			seed:    func(t *testing.T) string { return writeSecret(t, "seed.json", []byte("{")) },
			wantLog: "admin-gateway: seed load error:",
		},
		{
			name:    "valid file against an unmigrated database",
			seed:    func(t *testing.T) string { return writeSecret(t, "seed.json", []byte(validSeed)) },
			wantLog: "admin-gateway: seed error:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			c := f.start(t, "VAULT_SEED_FILE="+tt.seed(t))

			c.waitForLog(t, tt.wantLog)

			c.signal(t, syscall.SIGTERM)
			if code := c.waitForExit(t); code != 0 {
				t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
			}
		})
	}
}

// TestListenFailureIsFatal checks that a gateway which cannot bind dies instead
// of lingering.
//
// The listener runs in its own goroutine, so its error has to be escalated
// deliberately. Without the log.Fatalf the process would sit on the signal
// channel forever: a healthy-looking container serving nothing, which is worse
// than a crash-loop because nothing reports it.
func TestListenFailureIsFatal(t *testing.T) {
	t.Run("port already bound", func(t *testing.T) {
		f := newFixture(t)

		blocker, err := net.Listen("tcp", f.addr)
		if err != nil {
			t.Fatalf("occupy %s: %v", f.addr, err)
		}
		defer func() { _ = blocker.Close() }()

		c := launch(t, childRoleRun, f.workDir, f.env()...)

		if code := c.waitForExit(t); code != 1 {
			t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, c.stderr.String())
		}
		if out := c.stderr.String(); !strings.Contains(out, "admin-gateway: listen error:") {
			t.Errorf("stderr does not report a listen error:\n%s", out)
		}
	})

	t.Run("server certificate path does not exist", func(t *testing.T) {
		f := newFixture(t)
		c := launch(t, childRoleRun, f.workDir,
			f.env("ADMIN_GW_TLS_CERT_FILE="+filepath.Join(t.TempDir(), "absent.crt"))...)

		if code := c.waitForExit(t); code != 1 {
			t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, c.stderr.String())
		}
		if out := c.stderr.String(); !strings.Contains(out, "admin-gateway: listen error:") {
			t.Errorf("stderr does not report a listen error:\n%s", out)
		}
	})
}

// TestGracefulShutdownOnSignal covers both signals the gateway subscribes to.
//
// SIGTERM is what a container runtime sends first, and SIGINT is what an
// operator running the binary by hand sends. Both must drain and exit 0.
// Exiting non-zero on SIGTERM would make every rolling update look like a
// crash; not handling it at all would make the runtime escalate to SIGKILL and
// drop in-flight admin operations.
func TestGracefulShutdownOnSignal(t *testing.T) {
	tests := []struct {
		name string
		sig  os.Signal
	}{
		{name: "SIGTERM", sig: syscall.SIGTERM},
		{name: "SIGINT", sig: os.Interrupt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			c := f.start(t)

			c.signal(t, tt.sig)
			c.waitForLog(t, "admin-gateway: shutting down...")
			c.waitForLog(t, "admin-gateway: stopped")

			if code := c.waitForExit(t); code != 0 {
				t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
			}
			if out := c.stderr.String(); strings.Contains(out, "shutdown error") {
				t.Errorf("an idle gateway reported a shutdown error:\n%s", out)
			}

			if _, err := net.DialTimeout("tcp", f.addr, time.Second); err == nil {
				t.Errorf("%s is still accepting connections after shutdown", f.addr)
			}
		})
	}
}

// TestShutdownTimeoutIsBounded checks that a stuck connection cannot hold the
// process open.
//
// The gateway budgets ADMIN_GW_SHUTDOWN_TIMEOUT for draining and then gives up,
// which is what keeps a half-open connection from outlasting the runtime's own
// grace period and turning a rolling update into a SIGKILL. The test parks a
// connection that has completed the TLS handshake but sent no request, so the
// server counts it as in flight, and then asserts the process still reports the
// failure and exits cleanly.
func TestShutdownTimeoutIsBounded(t *testing.T) {
	f := newFixture(t)
	c := f.start(t, "ADMIN_GW_SHUTDOWN_TIMEOUT=200ms")

	parked, err := tls.Dial("tcp", f.addr, f.pki.tlsClientConfig())
	if err != nil {
		t.Fatalf("park a connection: %v", err)
	}
	defer func() { _ = parked.Close() }()

	c.signal(t, syscall.SIGTERM)
	c.waitForLog(t, "admin-gateway: shutdown error:")
	c.waitForLog(t, "admin-gateway: stopped")

	if code := c.waitForExit(t); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, c.stderr.String())
	}
}

// TestConcurrentRequestsDuringShutdown is the race test for the process
// lifecycle.
//
// main() runs the listener in one goroutine, a keystore refresh loop in
// another, and the shutdown sequence on the main goroutine, and the deferred
// teardown closes the audit logger, the keystore and the database pool while
// requests may still be in flight. The child is built with the race detector,
// so a data race between a handler and teardown fails the child and therefore
// this test. Requests are expected to fail once the listener closes; what is
// asserted is that the process never wedges, never races, and still exits 0.
func TestConcurrentRequestsDuringShutdown(t *testing.T) {
	f := newFixture(t)
	c := f.start(t)

	const workers = 12
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := f.httpClient()
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := client.Get("https://" + f.addr + "/admin/status")
				if err != nil {
					// Expected once the listener closes.
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}

	// Let the workers get requests in flight before the signal arrives.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := f.httpClient().Get("https://" + f.addr + "/admin/status")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	c.signal(t, syscall.SIGTERM)
	code := c.waitForExit(t)
	close(stop)
	wg.Wait()

	out := c.stderr.String()
	if strings.Contains(out, "DATA RACE") {
		t.Fatalf("the race detector fired during shutdown:\n%s", out)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, out)
	}
	if !strings.Contains(out, "admin-gateway: stopped") {
		t.Errorf("the gateway did not report a completed shutdown:\n%s", out)
	}
}

// TestSanitizeDBError covers the redaction applied to every database error the
// gateway logs fatally.
//
// The gateway interpolates the vault_admin password into its connection string,
// and pgx echoes connection strings in parse errors, so an unredacted log line
// is a credential in whatever collects the pod's stderr. The cases below also
// pin two known limits of the pattern so that neither is mistaken for coverage
// it does not provide.
func TestSanitizeDBError(t *testing.T) {
	tests := []struct {
		name string
		in   error
		want string
	}{
		{
			name: "nil passes through",
			in:   nil,
		},
		{
			name: "password in a connection string is removed",
			in:   errors.New("cannot parse `postgres://vault_admin:hunter2@db:5432/vault?sslmode=require`: bad port"),
			want: "cannot parse `postgres://***:***@db:5432/vault?sslmode=require`: bad port",
		},
		{
			name: "redaction survives a wrapped error",
			in:   fmt.Errorf("ping: %w", errors.New("postgres://vault_admin:hunter2@db:5432/vault")),
			want: "ping: postgres://***:***@db:5432/vault",
		},
		{
			name: "every occurrence is redacted",
			in:   errors.New("postgres://a:b@h1 then postgres://c:d@h2"),
			want: "postgres://***:***@h1 then postgres://***:***@h2",
		},
		{
			name: "error without a connection string is untouched",
			in:   errors.New("failed to connect to `user=vault_admin database=vault`: connection refused"),
			want: "failed to connect to `user=vault_admin database=vault`: connection refused",
		},
		{
			name: "a later at sign no longer widens the redaction over the host",
			in:   errors.New("postgres://vault_admin:hunter2@db:5432/vault?options=a@b"),
			want: "postgres://***:***@db:5432/vault?options=a@b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeDBError(tt.in)
			if tt.in == nil {
				if got != nil {
					t.Fatalf("sanitizeDBError(nil) = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("sanitizeDBError returned nil for a non-nil error")
			}
			if got.Error() != tt.want {
				t.Errorf("sanitizeDBError = %q, want %q", got, tt.want)
			}
			if strings.Contains(got.Error(), "hunter2") {
				t.Errorf("the password survived redaction: %q", got)
			}
		})
	}
}

// TestSanitizeDBErrorMissesPasswordsContainingWhitespace documents a real hole
// in the redaction.
//
// The pattern matches postgres://[^\s]+@, so a password containing a space
// breaks the match and the whole connection string, password included, is
// logged verbatim. loadSecret only trims the ends of a secret file, so an
// interior space in a password file survives to the connection string. The
// pattern also only knows the postgres:// scheme, while pgx accepts
// postgresql:// as well.
//
// Neither case is reachable through the shipped generator, which emits hex
// passwords, but docs/config.md invites operators to supply their own. The test
// asserts the broken behavior so a fix shows up here as a failure rather than
// going unnoticed.
func TestSanitizeDBErrorRedactsTheShapesItUsedToMiss(t *testing.T) {
	// This test was named ...MissesPasswordsContainingWhitespace and asserted
	// that the password LEAKED. It documented the defect as expected behaviour,
	// which is why the leak survived: the suite was green over it.
	//
	// The pattern was `postgres://[^\s]+@`. [^\s]+ stops at whitespace, so a DSN
	// carrying a space before the @ did not match at all and the whole string
	// reached the log. And pgx accepts postgresql:// as well as postgres://,
	// while DATABASE_URL is operator-supplied, so the longer spelling was never
	// matched either.
	tests := []struct {
		name   string
		in     string
		secret string
	}{
		{
			name:   "a space in the password no longer defeats the pattern",
			in:     "cannot parse `postgres://vault_admin:hun ter2@db:5432/vault`: bad port",
			secret: "hun ter2",
		},
		{
			name:   "the postgresql scheme is matched too",
			in:     "cannot parse `postgresql://vault_admin:hunter2@db:5432/vault`: bad port",
			secret: "hunter2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeDBError(errors.New(tt.in)).Error()
			if strings.Contains(got, tt.secret) {
				t.Errorf("the password survived redaction: %q", got)
			}
			if !strings.Contains(got, "db:5432") {
				t.Errorf("the host was redacted away, leaving nothing to diagnose: %q", got)
			}
		})
	}
}

// TestKeystoreNewHasExactlyOneErrorPath pins the fact that makes main()'s
// keystore error branch unreachable rather than merely untested.
//
// main() dies on that error, and the branch is excluded from coverage on the
// grounds that LoadConfig has already refused every input that could produce
// it. That reasoning is a claim about keystore.New, not about main(), and it
// silently stops being true the moment keystore.New learns to fail for a
// second reason: a database handle it validates, a retention period it
// rejects, an entropy source it reads at construction. Nothing about this
// package would fail then, so the claim is asserted where it lives.
//
// If this test fails, do not relax it. Go read main() and decide whether the
// new error is one the gateway can survive.
func TestKeystoreNewHasExactlyOneErrorPath(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	path := filepath.Join(root, "internal", "keystore", "keystore.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing keystore.go: %v", err)
	}

	var newFn *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "New" && fn.Recv == nil {
			newFn = fn
			break
		}
	}
	if newFn == nil {
		t.Fatal("keystore.New not found; it was renamed and this gate has stopped seeing what it guards")
	}

	// Every return whose last result is anything but a bare nil is an error
	// path. Counting returns rather than if-statements catches an error
	// returned from a switch, a loop, or a helper call just as well.
	var errorReturns []int
	ast.Inspect(newFn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		last := ret.Results[len(ret.Results)-1]
		if id, isIdent := last.(*ast.Ident); isIdent && id.Name == "nil" {
			return true
		}
		errorReturns = append(errorReturns, fset.Position(ret.Pos()).Line)
		return true
	})

	if len(errorReturns) != 1 {
		t.Fatalf("keystore.New has %d error returns (lines %v), want exactly 1.\n"+
			"cmd/admin-gateway/main.go treats its error as unreachable because LoadConfig "+
			"already refuses the only input that produces it. A second error path breaks that "+
			"reasoning, and the gateway would die at boot on a condition nobody decided it "+
			"should die on.", len(errorReturns), errorReturns)
	}

	// And that the one path is still the length check the exclusion cites.
	src, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read keystore.go: %v", err)
	}
	lines := strings.Split(string(src), "\n")
	guard := strings.Join(lines[max(0, errorReturns[0]-3):errorReturns[0]], " ")
	if !strings.Contains(guard, "len(masterKey)") {
		t.Errorf("keystore.New's only error return at line %d is no longer guarded by the "+
			"master-key length check (context: %q). The coverage exclusion in "+
			"cmd/admin-gateway/main.go cites that check by name.", errorReturns[0], strings.TrimSpace(guard))
	}
}
