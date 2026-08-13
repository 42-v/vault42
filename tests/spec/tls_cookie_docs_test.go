// TLS and cookie documentation gate.
//
// docs/config.md told operators that VAULT_TLS_ENABLED=false "has no effect"
// and that disabling TLS required editing the profile source. That was false in
// every profile: applyProfileDefaults resolves the variable through
// setDefaultBool, which uses os.LookupEnv and strconv.ParseBool and therefore
// honors an explicit false. charts/vault/templates/honeypot-vault.yaml already
// shipped VAULT_TLS_ENABLED: "false" and relied on it working.
//
// The cost of the wrong sentence was not a confused reader. An operator behind
// a TLS-terminating proxy who believed the switch was dead had no reason to
// look for VAULT_FORCE_SECURE_COOKIES, so the deployment that did disable TLS
// (through the chart, or by setting the variable anyway) ended up serving
// session cookies without the Secure flag on the last hop, and nothing in the
// startup path said so: VAULT_ALLOW_PLAINTEXT silences the refusal without
// restoring the flag.
//
// These tests make the document answer to the code. The published truth table
// in docs/config.md is executed row by row against config.Load and
// Config.Validate, under every non-dev profile, and the two decisions that
// table reports but that live in internal/server are pinned by go/ast so the
// table cannot quietly describe an expression the server no longer evaluates.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/config"
)

// matrixBegin and matrixEnd delimit the published truth table. Sentinels rather
// than a heading match so the surrounding prose can be rewritten freely without
// disturbing the gate.
const (
	matrixBegin = "<!-- BEGIN TLS COOKIE MATRIX -->"
	matrixEnd   = "<!-- END TLS COOKIE MATRIX -->"
)

// configDoc is the single published environment-variable reference. The gate
// reads it from disk rather than from an embedded copy so a doc edit is what
// the test sees.
var configDoc = filepath.Join("docs", "config.md")

// inertnessClaims are phrasings that assert VAULT_TLS_ENABLED cannot be turned
// off from the environment. This is a tripwire for the exact regression, not a
// substitute for the behavioral checks below: the truth table proves what the
// code does, and this proves the prose around it does not go on contradicting
// the table the way it did for the whole pre-1.0 life of the file.
var inertnessClaims = []string{
	"no effect",
	"cannot be disabled",
	"is ignored",
	"modify the profile code",
	"setdefaultbool limitation",
}

// envKeysUnderTest is every variable that can move a truth-table outcome. The
// gate clears all of them before each row so a stray value in the developer's
// or CI runner's environment cannot make a wrong row pass.
var envKeysUnderTest = []string{
	"VAULT_PROFILE",
	"VAULT_TLS_ENABLED",
	"VAULT_TLS_CERT_FILE",
	"VAULT_TLS_KEY_FILE",
	"VAULT_FORCE_SECURE_COOKIES",
	"VAULT_ALLOW_PLAINTEXT",
	"VAULT_ORIGIN",
	"HMAC_SECRET_FILE",
	"VAULT_PEPPER_FILE",
	"MASTER_KEY_FILE",
	"REDIS_ADDR",
	"CACHE_BACKEND",
	"VAULT_RATE_LIMIT_ENABLED",
	"VAULT_ALLOW_RATE_LIMIT_DISABLED",
	"VAULT_EMBEDDED_TRUSTED_UPSTREAM",
	"VAULT_MINT_ENABLED",
	"VAULT_MINT_AUDIENCE",
	"VAULT_PRIMARY_COLOR",
	"VAULT_RECOVERY_PUBLIC_KEY_FILE",
	"VAULT_SECRET_FILE_CONSUME",
	"VAULT_SEED_FILE",
	"VAULT_OIDC_PROVIDERS",
}

// nonDevProfiles are the profiles Config.Validate actually inspects. Dev returns
// early from Validate, so it gets its own test rather than a row here.
var nonDevProfiles = []string{"production", "embedded", "honeypot"}

// TestTLSEnabledFalseIsNotInert is the primary gate on the original defect: the
// document claimed an env var was dead that config.Load honors in every profile.
func TestTLSEnabledFalseIsNotInert(t *testing.T) {
	root := repoRoot(t)
	secrets := writeSecretFiles(t)

	honored := map[string]bool{}
	for _, profile := range append(nonDevProfiles, "dev") {
		clearConfigEnv(t)
		applyEnv(t, secrets)
		setEnv(t, "VAULT_PROFILE", profile)
		setEnv(t, "VAULT_TLS_ENABLED", "false")

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("config.Load(profile=%s): %v", profile, err)
		}
		honored[profile] = !cfg.TLSEnabled
		if cfg.TLSEnabled {
			t.Errorf("profile %s: VAULT_TLS_ENABLED=false left TLSEnabled true; "+
				"the truth table in %s assumes the variable is honored", profile, configDoc)
		}
	}

	body, err := os.ReadFile(filepath.Join(root, configDoc))
	if err != nil {
		t.Fatalf("read %s: %v", configDoc, err)
	}
	for i, line := range strings.Split(string(body), "\n") {
		if !strings.Contains(line, "VAULT_TLS_ENABLED") {
			continue
		}
		lower := strings.ToLower(line)
		for _, claim := range inertnessClaims {
			if strings.Contains(lower, claim) {
				t.Errorf("%s:%d claims VAULT_TLS_ENABLED is inert (%q), but config.Load honors "+
					"VAULT_TLS_ENABLED=false in every profile (%v):\n\t%s",
					configDoc, i+1, claim, honored, strings.TrimSpace(line))
			}
		}
	}
}

// TestTLSCookieMatrixMatchesCode executes the published truth table. Every row
// is a combination an operator can type, and every column is an outcome the
// document promises, so a row the code no longer produces fails here instead of
// in someone's cluster.
func TestTLSCookieMatrixMatchesCode(t *testing.T) {
	root := repoRoot(t)
	rows := parseMatrix(t, root)
	if len(rows) == 0 {
		t.Fatalf("%s publishes no TLS cookie matrix rows between %s and %s",
			configDoc, matrixBegin, matrixEnd)
	}

	secureCookieExpr, listenerExpr := pinnedServerExprs(t, root)
	if secureCookieExpr != "cfg.TLSEnabled || cfg.ForceSecureCookies" {
		t.Fatalf("internal/server derives the Secure cookie flag from %q; the matrix column in %s "+
			"describes cfg.TLSEnabled || cfg.ForceSecureCookies and must be rewritten",
			secureCookieExpr, configDoc)
	}
	if listenerExpr != `cfg.TLSEnabled && cfg.TLSCertFile != ""` {
		t.Fatalf("internal/server selects the TLS listener on %q; the matrix column in %s "+
			`describes cfg.TLSEnabled && cfg.TLSCertFile != "" and must be rewritten`,
			listenerExpr, configDoc)
	}

	secrets := writeSecretFiles(t)
	for _, row := range rows {
		for _, profile := range nonDevProfiles {
			clearConfigEnv(t)
			applyEnv(t, secrets)
			setEnv(t, "VAULT_PROFILE", profile)
			applyEnv(t, row.env(secrets))

			cfg, err := config.Load()
			if err == nil {
				err = cfg.Validate()
			}

			gotStartup := "starts"
			if err != nil {
				gotStartup = "refused"
			}
			if gotStartup != row.startup {
				t.Errorf("%s:%d [profile=%s] documents startup %q, code says %q (err=%v)\n\t%s",
					configDoc, row.line, profile, row.startup, gotStartup, err, row.raw)
				continue
			}
			if gotStartup == "refused" {
				// A refused startup has no listener and sets no cookie. The
				// document must not describe one, or it teaches an operator to
				// expect a running server from a combination that never boots.
				if row.cookie != "n/a" || row.listener != "n/a" {
					t.Errorf("%s:%d [profile=%s] documents cookie=%q listener=%q for a combination "+
						"that refuses to start; both must be n/a\n\t%s",
						configDoc, row.line, profile, row.cookie, row.listener, row.raw)
				}
				continue
			}

			if got := boolWord(cfg.TLSEnabled); got != row.effective {
				t.Errorf("%s:%d [profile=%s] documents effective TLSEnabled %q, code says %q\n\t%s",
					configDoc, row.line, profile, row.effective, got, row.raw)
			}
			gotCookie := "unset"
			if cfg.TLSEnabled || cfg.ForceSecureCookies {
				gotCookie = "set"
			}
			if gotCookie != row.cookie {
				t.Errorf("%s:%d [profile=%s] documents Secure cookie %q, code says %q\n\t%s",
					configDoc, row.line, profile, row.cookie, gotCookie, row.raw)
			}
			gotListener := "plaintext"
			if cfg.TLSEnabled && cfg.TLSCertFile != "" {
				gotListener = "HTTPS"
			}
			if gotListener != row.listener {
				t.Errorf("%s:%d [profile=%s] documents listener %q, code says %q\n\t%s",
					configDoc, row.line, profile, row.listener, gotListener, row.raw)
			}
		}
	}
}

// TestDevProfileSkipsThePlaintextRefusal pins the caveat the matrix carries in
// prose. Validate returns before the TLS checks in dev, so a dev deployment
// serves plaintext with non-Secure cookies and no override variable, which is
// the one case where reading the matrix alone would mislead.
func TestDevProfileSkipsThePlaintextRefusal(t *testing.T) {
	secrets := writeSecretFiles(t)
	clearConfigEnv(t)
	applyEnv(t, secrets)
	setEnv(t, "VAULT_PROFILE", "dev")
	setEnv(t, "VAULT_TLS_ENABLED", "false")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load(profile=dev): %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("dev profile must start with TLS off and no override, got: %v", err)
	}
	if cfg.TLSEnabled {
		t.Error("dev profile ignored VAULT_TLS_ENABLED=false")
	}
	if cfg.TLSEnabled || cfg.ForceSecureCookies {
		t.Error("dev profile with TLS off must not mark cookies Secure")
	}
}

// TestPublishedExamplesStartWithTheirTLSSettings runs the TLS-relevant exports
// out of every shell example in the document.
//
// The published Production example carried no certificate or key while every
// profile defaults TLS on, so the block a reader was invited to copy hit the
// M4 refusal on the first boot. A worked example that cannot start is the same
// defect as a prose claim that is false, and it is the one an operator reaches
// for first.
func TestPublishedExamplesStartWithTheirTLSSettings(t *testing.T) {
	root := repoRoot(t)
	secrets := writeSecretFiles(t)

	for _, ex := range parseShellExamples(t, root) {
		if ex.env["VAULT_PROFILE"] == string("dev") {
			// Dev returns early from Validate, so its example proves nothing
			// about the TLS checks and would pass whatever it contained.
			continue
		}
		clearConfigEnv(t)
		applyEnv(t, secrets)
		applyEnv(t, ex.env)

		cfg, err := config.Load()
		if err == nil {
			err = cfg.Validate()
		}
		if err != nil {
			t.Errorf("%s:%d the %q example refuses to start: %v",
				configDoc, ex.line, ex.name, err)
			continue
		}
		if !cfg.TLSEnabled && !cfg.ForceSecureCookies {
			t.Errorf("%s:%d the %q example starts with TLS off and no VAULT_FORCE_SECURE_COOKIES, "+
				"so it publishes a deployment whose session cookies are not Secure",
				configDoc, ex.line, ex.name)
		}
	}
}

// shellExample is one fenced bash block, reduced to the exports that move a TLS
// or cookie outcome. Everything else in the block (database, SMTP, OAuth) is
// irrelevant to what this gate decides and is dropped so an unrelated edit
// cannot break it.
type shellExample struct {
	name string
	line int
	env  map[string]string
}

// tlsExampleKeys are the exports parseShellExamples carries over. VAULT_PROFILE
// is included because it selects which defaults and which checks apply.
var tlsExampleKeys = map[string]bool{
	"VAULT_PROFILE":              true,
	"VAULT_TLS_ENABLED":          true,
	"VAULT_TLS_CERT_FILE":        true,
	"VAULT_TLS_KEY_FILE":         true,
	"VAULT_FORCE_SECURE_COOKIES": true,
	"VAULT_ALLOW_PLAINTEXT":      true,
}

// parseShellExamples pulls the fenced bash blocks and the heading each sits
// under. Commented-out exports are skipped: a reader who uncomments one has
// left the published example behind.
func parseShellExamples(t *testing.T, root string) []shellExample {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, configDoc))
	if err != nil {
		t.Fatalf("read %s: %v", configDoc, err)
	}

	var out []shellExample
	var cur *shellExample
	heading := "(no heading)"
	for i, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case cur == nil && strings.HasPrefix(trimmed, "#"):
			heading = strings.TrimLeft(trimmed, "# ")
		case cur == nil && strings.HasPrefix(trimmed, "```bash"):
			cur = &shellExample{name: heading, line: i + 1, env: map[string]string{}}
		case cur != nil && strings.HasPrefix(trimmed, "```"):
			if len(cur.env) > 0 {
				out = append(out, *cur)
			}
			cur = nil
		case cur != nil && strings.HasPrefix(trimmed, "export "):
			k, v, ok := strings.Cut(strings.TrimPrefix(trimmed, "export "), "=")
			if ok && tlsExampleKeys[k] {
				cur.env[k] = strings.Trim(v, `"'`)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Matrix parsing
// ---------------------------------------------------------------------------

// matrixRow is one published combination. The env fields hold the literal value
// an operator would set, or "unset", so the table reads as instructions rather
// than as internal state.
type matrixRow struct {
	line      int
	raw       string
	tlsEnv    string
	certKey   string
	forceEnv  string
	allowEnv  string
	effective string
	startup   string
	cookie    string
	listener  string
}

// env renders the row's left-hand columns as the environment they describe.
func (r matrixRow) env(secrets map[string]string) map[string]string {
	out := map[string]string{}
	if r.tlsEnv != "unset" {
		out["VAULT_TLS_ENABLED"] = r.tlsEnv
	}
	switch r.certKey {
	case "set":
		out["VAULT_TLS_CERT_FILE"] = secrets["_certPath"]
		out["VAULT_TLS_KEY_FILE"] = secrets["_keyPath"]
	case "cert only":
		// The half-configured pair is its own row because Validate treats a
		// missing key exactly like a missing certificate, while the listener
		// selection looks only at the certificate. Documenting the pair as one
		// case would hide that the process starts and then dies on the listener.
		out["VAULT_TLS_CERT_FILE"] = secrets["_certPath"]
	}
	if r.forceEnv != "unset" {
		out["VAULT_FORCE_SECURE_COOKIES"] = r.forceEnv
	}
	if r.allowEnv != "unset" {
		out["VAULT_ALLOW_PLAINTEXT"] = r.allowEnv
	}
	return out
}

// parseMatrix reads the sentinel-delimited table out of the document. Header and
// separator rows are skipped by shape, not by index, so a column rename does not
// silently drop a row.
func parseMatrix(t *testing.T, root string) []matrixRow {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, configDoc))
	if err != nil {
		t.Fatalf("read %s: %v", configDoc, err)
	}
	lines := strings.Split(string(body), "\n")

	begin, end := -1, -1
	for i, line := range lines {
		switch {
		case strings.Contains(line, matrixBegin) && begin < 0:
			begin = i
		case strings.Contains(line, matrixEnd) && end < 0:
			end = i
		}
	}
	if begin < 0 || end < 0 || end < begin {
		t.Fatalf("%s is missing the %s / %s sentinels around the TLS cookie truth table",
			configDoc, matrixBegin, matrixEnd)
	}

	var rows []matrixRow
	for i := begin + 1; i < end; i++ {
		raw := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(raw, "|") {
			continue
		}
		cells := splitCells(raw)
		if len(cells) != 8 {
			continue
		}
		if cells[0] == "VAULT_TLS_ENABLED" || strings.HasPrefix(cells[0], "---") {
			continue
		}
		rows = append(rows, matrixRow{
			line:      i + 1,
			raw:       raw,
			tlsEnv:    cells[0],
			certKey:   cells[1],
			forceEnv:  cells[2],
			allowEnv:  cells[3],
			effective: cells[4],
			startup:   cells[5],
			cookie:    cells[6],
			listener:  cells[7],
		})
	}
	return rows
}

// splitCells turns a markdown table row into its trimmed, unquoted cells.
func splitCells(raw string) []string {
	parts := strings.Split(strings.Trim(raw, "|"), "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.Trim(strings.TrimSpace(p), "`"))
	}
	return out
}

func boolWord(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// ---------------------------------------------------------------------------
// Source pins
// ---------------------------------------------------------------------------

// pinnedServerExprs returns the two expressions in internal/server that the
// matrix's cookie and listener columns report on. Reading them out of the AST
// rather than restating them here means a change to either decision fails this
// gate and forces the document to be revisited, which is the failure mode the
// original defect had: the code moved and the prose did not.
func pinnedServerExprs(t *testing.T, root string) (secureCookie, listener string) {
	t.Helper()
	path := filepath.Join(root, "internal", "server", "server.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if secureCookie != "" || len(node.Lhs) != 1 || len(node.Rhs) != 1 {
				return true
			}
			if id, ok := node.Lhs[0].(*ast.Ident); ok && id.Name == "secureCookies" {
				secureCookie = exprText(t, fset, node.Rhs[0])
			}
		case *ast.IfStmt:
			if listener != "" || node.Cond == nil {
				return true
			}
			if strings.Contains(nodeText(t, fset, node.Body), "ListenAndServeTLS") {
				listener = exprText(t, fset, node.Cond)
			}
		}
		return true
	})

	if secureCookie == "" {
		t.Fatalf("%s no longer assigns secureCookies; the Secure cookie column in %s "+
			"has nothing to report on", path, configDoc)
	}
	if listener == "" {
		t.Fatalf("%s no longer guards ListenAndServeTLS with an if; the listener column in %s "+
			"has nothing to report on", path, configDoc)
	}
	return secureCookie, listener
}

func exprText(t *testing.T, fset *token.FileSet, e ast.Expr) string {
	t.Helper()
	return nodeText(t, fset, e)
}

func nodeText(t *testing.T, fset *token.FileSet, n ast.Node) string {
	t.Helper()
	var b strings.Builder
	if err := printer.Fprint(&b, fset, n); err != nil {
		t.Fatalf("render node: %v", err)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Environment control
// ---------------------------------------------------------------------------

// writeSecretFiles lays down the secrets every non-dev profile needs to reach
// the TLS checks in Validate, plus a cert and key path for the rows that
// document them as present. Validate stops at the first failure, so without
// these every row would report "refused" for the wrong reason.
func writeSecretFiles(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
		return p
	}
	const key32 = "0123456789abcdef0123456789abcdef"
	return map[string]string{
		"VAULT_ORIGIN":      "https://vault.test",
		"HMAC_SECRET_FILE":  write("hmac", key32),
		"VAULT_PEPPER_FILE": write("pepper", key32),
		"MASTER_KEY_FILE":   write("master", key32),
		"REDIS_ADDR":        "redis.test:6379",
		// Paths only. Nothing in Load or Validate reads the bytes, and the rows
		// that name them are about whether the variables are set.
		"_certPath": write("tls.crt", "cert"),
		"_keyPath":  write("tls.key", "key"),
	}
}

// applyEnv sets the map's entries, skipping the underscore-prefixed helper paths
// that are inputs to the row rendering rather than environment variables.
func applyEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		if strings.HasPrefix(k, "_") {
			continue
		}
		setEnv(t, k, v)
	}
}

// clearConfigEnv unsets every variable that can move an outcome. t.Setenv cannot
// express "unset", and for VAULT_TLS_ENABLED the difference is the whole point:
// os.LookupEnv sees an empty string as set.
func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, k := range envKeysUnderTest {
		unsetEnv(t, k)
	}
}

func setEnv(t *testing.T, key, val string) {
	t.Helper()
	restoreEnv(t, key)
	if err := os.Setenv(key, val); err != nil {
		t.Fatalf("setenv %s: %v", key, err)
	}
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	restoreEnv(t, key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unsetenv %s: %v", key, err)
	}
}

// restoreEnv registers a one-shot cleanup that puts the caller's value back, so
// the test binary hands the next package the environment it was given.
func restoreEnv(t *testing.T, key string) {
	t.Helper()
	if _, seen := envSaved[key]; seen {
		return
	}
	old, had := os.LookupEnv(key)
	envSaved[key] = struct{}{}
	t.Cleanup(func() {
		delete(envSaved, key)
		if had {
			_ = os.Setenv(key, old)
			return
		}
		_ = os.Unsetenv(key)
	})
}

// envSaved tracks which keys already have a pending restore. These tests are
// sequential by construction (they mutate process state), so a plain map is
// enough and a mutex would only hide an accidental t.Parallel.
var envSaved = map[string]struct{}{}
