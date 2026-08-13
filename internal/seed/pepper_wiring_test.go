package seed_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// seedRunCallSites are every place in the tree that drives declarative seeding.
// The map value is the expression each is expected to pass as the pepper.
//
// It is spelled out rather than discovered, because the failure being guarded
// is a call site that forgot the pepper entirely, and a check that only looks at
// the call sites it can find would be satisfied by a call site that is not
// there.
var seedRunCallSites = map[string]string{
	"cmd/vault/main.go":         "cfg.Pepper",
	"internal/cli/cli.go":       "c.pepper",
	"cmd/admin-gateway/main.go": "cfg.Pepper",
}

// TestEverySeedCallSitePassesThePepper is the regression for a lockout that
// left no trace anywhere.
//
// seed.Run hashes each seeded user's password with the pepper it is given, and
// crypto.applyPepper returns the password unchanged when that pepper is empty.
// AuthService.Login always verifies with the configured pepper. So a call site
// that omits it stores Argon2id(password) while login computes
// Argon2id(HMAC-SHA256(pepper, password)), and the two can never match.
//
// cmd/vault/main.go omitted it. internal/cli and cmd/admin-gateway did not,
// which is what made it invisible: seeding through the CLI worked, so the
// feature was demonstrably correct, and only the server's own startup path was
// broken. Config.Validate makes VAULT_PEPPER_FILE mandatory outside dev, so in
// production the mismatch was not an edge case but a certainty.
//
// What it looked like: the pod logged `seed: user "ops@example.com" created`,
// startup reported no error, and every POST /auth/login for that user returned
// 401 forever. docs/config.md recommends VAULT_SEED_FILE together with
// VAULT_REGISTRATION_ENABLED=false for sealed deployments, so the documented
// configuration produced a vault nobody could log into and nobody could
// register with. Seeding is idempotent by email, so restarting did not repair
// it.
//
// seed.Run now takes the pepper positionally, which makes omitting it a
// compile error. This test is the second line: it fails if a call site passes a
// literal empty string, or the wrong variable, to satisfy the compiler.
func TestEverySeedCallSitePassesThePepper(t *testing.T) {
	root := seedRepoRoot(t)

	for file, wantArg := range seedRunCallSites {
		t.Run(file, func(t *testing.T) {
			path := filepath.Join(root, file)
			fset := token.NewFileSet()
			parsed, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", file, err)
			}

			src, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}

			var found int
			ast.Inspect(parsed, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "seed" {
					return true
				}
				if sel.Sel.Name != "Run" && sel.Sel.Name != "RunAdmins" {
					return true
				}
				found++

				// The pepper is the last argument of both entry points.
				last := call.Args[len(call.Args)-1]
				start := fset.Position(last.Pos()).Offset
				end := fset.Position(last.End()).Offset
				got := strings.TrimSpace(string(src[start:end]))

				if got != wantArg {
					t.Errorf("%s:%d passes %q as the seeding pepper, want %q. A seeded user's "+
						"password is hashed with this value and verified at login with the "+
						"configured pepper, so anything else locks every seeded account out "+
						"permanently and silently.",
						file, fset.Position(call.Pos()).Line, got, wantArg)
				}
				return true
			})

			if found == 0 {
				t.Fatalf("%s makes no seed.Run or seed.RunAdmins call; either seeding was removed "+
					"from it or this gate has stopped seeing what it guards", file)
			}
		})
	}
}

// seedRepoRoot walks up from this file to the module root.
func seedRepoRoot(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above this test file")
		}
		dir = parent
	}
}
