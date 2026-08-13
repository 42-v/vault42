// Authentication entry-point account-state gate.
//
// account_state_mapping_test.go guards the transport half of this property: a
// handler that receives ErrAccountBanned/Disabled/Locked has to turn it into a
// 403 naming the policy. This file guards the half above it. An entry point that
// resolves a user and then mints a token has to decide, itself, whether that
// user is allowed to authenticate at all, and every such entry point has to
// decide it against the same set of states.
//
// The OAuth callback did not. It checked Deleted, Banned and Disabled, carried a
// comment claiming "parity with password login + token refresh", and never read
// LockedUntil. So POST /admin/users/{id}/lock, which internal/rbac describes as
// the first response to a suspected takeover, stopped password login and burned
// refresh families while the attacker's linked social identity kept completing
// callbacks and collecting brand new token families. The lock stopped every
// login except the one the attacker already had.
//
// A gate spelling out "oauth.go must mention LockedUntil" would have closed that
// one hole and nothing else, and would have been written only after somebody
// found it. This one derives its work list from the code: the minting primitives
// come from TokenService, the user-repository field names come from the struct
// declarations, and an entry point is any function that reaches for both. A new
// authentication path is therefore in scope the moment it is written, whether or
// not anyone remembers this file exists.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// accountStateGuards are the user-row states that must refuse a new session.
// Deleted and Banned/Disabled are the platform's own verdicts; LockedUntil is
// the operator's, and it is the one that went missing. Each is checked by name
// because the check itself is a plain field read, not a call this gate could
// follow.
var accountStateGuards = []string{"Deleted", "Banned", "Disabled", "LockedUntil"}

// authSourceDirs are the packages that may mint a session.
var authSourceDirs = [][]string{
	{"internal", "service"},
	{"internal", "handler"},
}

// parsedGoFile pairs an AST with the source text its offsets index into.
type parsedGoFile struct {
	path string
	file *ast.File
	src  string
	fset *token.FileSet
}

// parseAuthSources reads every non-test Go file in the packages that can mint a
// session.
func parseAuthSources(t *testing.T, root string) []parsedGoFile {
	t.Helper()

	var out []parsedGoFile
	for _, parts := range authSourceDirs {
		dir := filepath.Join(append([]string{root}, parts...)...)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", filepath.Join(parts...), err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			out = append(out, parsedGoFile{path: path, file: f, src: readFileString(t, path), fset: fset})
		}
	}
	if len(out) == 0 {
		t.Fatal("no source files found in the packages that mint sessions; the layout changed " +
			"and this gate has stopped seeing what it guards")
	}
	return out
}

// tokenMintingPrimitives returns the TokenService methods that hand back a
// credential: the Issue* family. Derived from the receiver's own declarations so
// a new minting method is covered without editing this file.
func tokenMintingPrimitives(t *testing.T, root string) []string {
	t.Helper()

	path := filepath.Join(root, "internal", "service", "token.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing internal/service/token.go: %v", err)
	}

	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || !fn.Name.IsExported() {
			continue
		}
		if strings.HasPrefix(fn.Name.Name, "Issue") {
			out = append(out, fn.Name.Name)
		}
	}
	sort.Strings(out)

	if len(out) == 0 {
		t.Fatal("TokenService exposes no Issue* method; sessions are minted somewhere else " +
			"now and this gate has stopped seeing what it guards")
	}
	return out
}

// userRepoFields returns the struct field names declared as a
// repository.UserRepository. A function that reads a user row goes through one
// of these, so their names are how this gate tells "authenticates a person"
// apart from "authenticates a client": the client-credentials grant in
// client.go mints from a *repository.ClientRepository and owns no account state,
// which is a structural exemption rather than one this file has to assert.
func userRepoFields(t *testing.T, files []parsedGoFile) []string {
	t.Helper()

	seen := map[string]bool{}
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, field := range st.Fields.List {
				sel, ok := field.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "UserRepository" {
					continue
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "repository" {
					continue
				}
				for _, name := range field.Names {
					seen[name.Name] = true
				}
			}
			return true
		})
	}

	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)

	if len(out) == 0 {
		t.Fatal("no repository.UserRepository field is declared in the packages that mint " +
			"sessions; the wiring changed and this gate has stopped seeing what it guards")
	}
	return out
}

// authEntryPoint is a function that resolves a user row and mints a credential
// for it.
type authEntryPoint struct {
	file  string
	line  int
	name  string
	body  string
	mints []string
}

// findAuthEntryPoints walks every candidate function and keeps the ones that do
// both halves of an authentication: look the subject up through a
// UserRepository, and issue something with it.
//
// token.go is skipped because IssueRotatedPair calls IssueTokenPair: the
// primitives are the thing being handed out, not a decision about who may have
// it.
func findAuthEntryPoints(t *testing.T, files []parsedGoFile, primitives, repoFields []string) []authEntryPoint {
	t.Helper()

	var out []authEntryPoint
	for _, pf := range files {
		if filepath.Base(pf.path) == "token.go" {
			continue
		}
		for _, decl := range pf.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			start := pf.fset.Position(fn.Body.Pos()).Offset
			end := pf.fset.Position(fn.Body.End()).Offset
			if start < 0 || end > len(pf.src) || start >= end {
				continue
			}
			body := pf.src[start:end]

			var mints []string
			for _, p := range primitives {
				if strings.Contains(body, "."+p+"(") {
					mints = append(mints, p)
				}
			}
			if len(mints) == 0 {
				continue
			}

			var resolvesUser bool
			for _, f := range repoFields {
				if strings.Contains(body, f+".GetByID(") || strings.Contains(body, f+".GetByEmail(") {
					resolvesUser = true
					break
				}
			}
			if !resolvesUser {
				continue
			}

			sort.Strings(mints)
			out = append(out, authEntryPoint{
				file:  filepath.Base(pf.path),
				line:  pf.fset.Position(fn.Pos()).Line,
				name:  fn.Name.Name,
				body:  body,
				mints: mints,
			})
		}
	}
	return out
}

// TestEveryAuthEntryPointChecksTheSameAccountState fails when a function that
// resolves a user and mints a credential for them does not consider every state
// that is supposed to refuse a session.
//
// The check is on the enclosing function's source text, the same shape as the
// sibling gate in account_state_mapping_test.go: what matters is that the code
// deciding to mint also names each state, not where in the ladder the read sits.
// That cannot prove the comparison is correct, and it is not trying to. It
// proves the state was considered, which is the failure that actually happened
// here: three of four states checked, the fourth never mentioned, and a comment
// asserting parity on top of the gap.
func TestEveryAuthEntryPointChecksTheSameAccountState(t *testing.T) {
	root := repoRoot(t)
	files := parseAuthSources(t, root)
	primitives := tokenMintingPrimitives(t, root)
	repoFields := userRepoFields(t, files)

	entryPoints := findAuthEntryPoints(t, files, primitives, repoFields)
	if len(entryPoints) < 2 {
		t.Fatalf("found %d authentication entry point(s) across %v; there are at least the "+
			"password login, the refresh rotation, the MFA completion and the OAuth callback, "+
			"so this gate has stopped seeing what it guards",
			len(entryPoints), authSourceDirs)
	}

	// Every guard has to be live somewhere. If a state stops appearing entirely,
	// the loop below passes by agreeing with the drift instead of catching it.
	enforcedSomewhere := map[string]bool{}
	for _, ep := range entryPoints {
		for _, g := range accountStateGuards {
			if strings.Contains(ep.body, "."+g) {
				enforcedSomewhere[g] = true
			}
		}
	}
	for _, g := range accountStateGuards {
		if !enforcedSomewhere[g] {
			t.Fatalf("no authentication entry point reads %s; either the state was renamed or "+
				"every path dropped it, and this gate has stopped seeing what it guards", g)
		}
	}

	for _, ep := range entryPoints {
		var missing []string
		for _, g := range accountStateGuards {
			if !strings.Contains(ep.body, "."+g) {
				missing = append(missing, g)
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s:%d %s resolves a user and mints via %s without considering %s. "+
				"An authentication entry point that skips a state is a bypass for exactly the "+
				"subjects that state was written to stop, and it is silent: the other paths "+
				"keep refusing, so the platform looks like it is enforcing the policy.",
				ep.file, ep.line, ep.name, strings.Join(ep.mints, ", "), strings.Join(missing, ", "))
		}
	}
}
