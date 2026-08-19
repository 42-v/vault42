package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// bridgeEnvName matches a variable name and nothing else, so the error strings
// that quote one ("BRIDGE_REAL_UPSTREAM is required") do not become variables
// this file then insists somebody set.
var bridgeEnvName = regexp.MustCompile(`^BRIDGE_[A-Z0-9_]+$`)

// bridgeSourceDir returns the directory this package's source lives in, so the
// gates below can read config.go without a repo-root walk.
func bridgeSourceDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(thisFile)
}

// bridgeEnvVarsInSource reads every BRIDGE_* variable name LoadConfig looks up,
// out of the AST rather than out of a list somebody maintains by hand.
func bridgeEnvVarsInSource(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(bridgeSourceDir(t), "config.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse config.go: %v", err)
	}

	seen := map[string]struct{}{}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil || !bridgeEnvName.MatchString(v) {
			return true
		}
		seen[v] = struct{}{}
		return true
	})

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)

	if len(out) < 10 {
		t.Fatalf("only %d BRIDGE_* names found in config.go; the scan is broken and both gates "+
			"below would pass over anything", len(out))
	}
	return out
}

// TestEveryBridgeEnvVarIsClearedBetweenTests is the gate the isolation fixture
// did not have.
//
// bridgeEnvKeys is what clearBridgeEnv blanks, and its own comment says it is
// "every environment variable LoadConfig reads". It was not: BRIDGE_MAX_BODY_BYTES
// and BRIDGE_MAX_INFLIGHT were added to config.go and never to the list, so a
// developer or a CI runner with either exported in the environment changed what
// every config test measured, silently and in whichever direction their shell
// happened to point.
//
// A list that claims to be exhaustive is a claim, and this is the check on it.
func TestEveryBridgeEnvVarIsClearedBetweenTests(t *testing.T) {
	cleared := map[string]struct{}{}
	for _, k := range bridgeEnvKeys {
		cleared[k] = struct{}{}
	}

	for _, name := range bridgeEnvVarsInSource(t) {
		if _, ok := cleared[name]; !ok {
			t.Errorf("config.go reads %s and bridgeEnvKeys does not list it, so clearBridgeEnv "+
				"leaves whatever the runner exported in place and every config test measures a "+
				"different configuration on a different machine. Add it to bridgeEnvKeys.", name)
		}
	}

	for _, k := range bridgeEnvKeys {
		found := false
		for _, name := range bridgeEnvVarsInSource(t) {
			if name == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("bridgeEnvKeys lists %s, which config.go no longer reads. Remove it: a stale "+
				"entry hides the next variable that should have been added.", k)
		}
	}
}

// TestEveryBridgeEnvVarIsExercisedByATest checks the claim
// TestLoadConfigReadsEveryOverride makes in its own doc comment: that a variable
// "parsed but never wired into Config fails here rather than in a deployment".
//
// It did not hold. BRIDGE_MAX_BODY_BYTES and BRIDGE_MAX_INFLIGHT were added to
// config.go and set by no test in the package, so the two DoS caps could have
// been wired to the wrong field, or to nothing, and every test still passed.
//
// The rule is the weaker, truer one: some test in this package has to set each
// variable. Which test is a judgement — the admin token file needs a temporary
// file and has its own — but "no test at all" is not.
func TestEveryBridgeEnvVarIsExercisedByATest(t *testing.T) {
	dir := bridgeSourceDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	set := map[string]struct{}{}
	var files int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		files++
		ast.Inspect(parsed, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Setenv" && sel.Sel.Name != "Set") {
				return true
			}
			for _, arg := range call.Args {
				lit, ok := arg.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if v, err := strconv.Unquote(lit.Value); err == nil && bridgeEnvName.MatchString(v) {
					set[v] = struct{}{}
				}
			}
			return true
		})
	}

	if files < 5 {
		t.Fatalf("only %d test files parsed in %s; the scan is broken and this gate would report "+
			"every variable as unexercised or none", files, dir)
	}

	// clearBridgeEnv sets every name to "" through a loop variable rather than a
	// literal, so it contributes nothing to the set above — which is right:
	// blanking a variable is how a test asks for the default, not how it
	// exercises the variable.
	for _, name := range bridgeEnvVarsInSource(t) {
		if _, ok := set[name]; !ok {
			t.Errorf("config.go reads %s and no test in this package ever sets it. The variable "+
				"could be parsed into the wrong field, or into none, and the suite would not "+
				"notice — which is what happened to the two DoS caps.", name)
		}
	}
}
