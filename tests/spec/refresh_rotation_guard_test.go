// Refresh-token reuse detection gate.
//
// Rotation is three separate statements: read the presented row, consume it,
// insert its successor. Reuse detection is one more: revoke the family. Nothing
// in the schema ties them together, so whether a stolen family actually dies
// comes down to which predicates those statements carry.
//
// It came down the wrong way. The consume statement asked only whether the token
// was unused, and the insert asked nothing at all. Two requests presenting one
// stolen token both passed the read, one consumed it, the other revoked the
// family, and the first then inserted a successor into the family that had just
// been revoked. The loser was told replay_detected and the audit log recorded a
// revocation, so the control reported itself as working while the winner kept a
// rotating session for the rest of VAULT_MAX_SESSION_LIFETIME.
//
// The tests that existed did not see it: tests/attack/refresh_token_race_test.go
// never called Refresh, and the repository tests called one method at a time,
// which is exactly where a defect that lives between three statements hides.
//
// So this gate reads the shipped SQL and the shipped mapping rather than any
// list of methods someone believed was complete. Both halves are derived: every
// statement that consumes a token, and every statement that inserts one.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// refreshTokenStorePath is the file that owns every refresh-token statement.
var refreshTokenStorePath = filepath.Join("internal", "repository", "postgres", "refresh_token.go")

// statement is one SQL literal as it is actually shipped, with the method it
// lives in, so a failure names the call site rather than the file.
type statement struct {
	method string
	line   int
	sql    string
}

// refreshTokenStatements returns every SQL literal in the refresh-token store.
func refreshTokenStatements(t *testing.T, root string) []statement {
	t.Helper()

	path := filepath.Join(root, refreshTokenStorePath)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", refreshTokenStorePath, err)
	}

	var out []statement
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			sql, err := strconv.Unquote(lit.Value)
			if err != nil || !strings.Contains(sql, "auth.refresh_tokens") {
				return true
			}
			out = append(out, statement{
				method: fn.Name.Name,
				line:   fset.Position(lit.Pos()).Line,
				sql:    normalizeSQL(sql),
			})
			return true
		})
	}

	if len(out) == 0 {
		t.Fatalf("no statement against auth.refresh_tokens found in %s; this gate has stopped "+
			"seeing what it guards", refreshTokenStorePath)
	}
	return out
}

// normalizeSQL collapses the whitespace a multi-line literal carries so the
// assertions below can look for a predicate without depending on how the
// statement happens to be wrapped.
func normalizeSQL(sql string) string { return strings.Join(strings.Fields(sql), " ") }

// TestConsumingATokenRequiresAnUnrevokedRow covers the compare-and-set that
// spends a refresh token. The caller read the row earlier, so "not revoked" was
// established against a snapshot; only this statement establishes it at the
// instant the token is actually spent.
func TestConsumingATokenRequiresAnUnrevokedRow(t *testing.T) {
	root := repoRoot(t)

	var checked int
	for _, st := range refreshTokenStatements(t, root) {
		if !strings.Contains(st.sql, "SET used = TRUE") {
			continue
		}
		checked++
		if !strings.Contains(st.sql, "revoked = FALSE") {
			t.Errorf("%s:%d %s spends a refresh token without requiring revoked = FALSE. A request "+
				"that read the row a moment before a revocation landed still consumes it and goes on "+
				"to rotate, so a family an operator has just burned issues a fresh session anyway.",
				refreshTokenStorePath, st.line, st.method)
		}
	}
	if checked == 0 {
		t.Fatalf("no statement in %s marks a refresh token used; the rotation scheme changed and "+
			"this gate has stopped seeing what it guards", refreshTokenStorePath)
	}
}

// TestInsertingATokenRefusesARevokedFamily covers the other end of the window.
// Reuse detection revokes the rows a family has at that instant, so an insert
// with no precondition produces a successor that no revocation ever touched.
//
// FOR UPDATE is asserted along with the predicate because a plain read of the
// family cannot see a revocation that has not committed yet. Without the lock the
// two statements are invisible to each other and both succeed, which is the
// original defect with an extra query in front of it.
func TestInsertingATokenRefusesARevokedFamily(t *testing.T) {
	root := repoRoot(t)

	var checked int
	for _, st := range refreshTokenStatements(t, root) {
		if !strings.Contains(st.sql, "INSERT INTO auth.refresh_tokens") {
			continue
		}
		checked++
		if !strings.Contains(st.sql, "revoked") {
			t.Errorf("%s:%d %s inserts a refresh token without asking whether the family is revoked. "+
				"A rotation that runs alongside reuse detection inserts its successor after the "+
				"revocation has already passed over the family, so the stolen session survives the "+
				"replay that was supposed to end it.",
				refreshTokenStorePath, st.line, st.method)
			continue
		}
		if !strings.Contains(st.sql, "FOR UPDATE") {
			t.Errorf("%s:%d %s checks the family's revocation state without locking it. A snapshot "+
				"read cannot see a revocation that is still in flight, so the insert and the "+
				"revocation pass through each other and the successor is born outside the family "+
				"that was just burned.",
				refreshTokenStorePath, st.line, st.method)
		}
	}
	if checked == 0 {
		t.Fatalf("no statement in %s inserts a refresh token; the rotation scheme changed and this "+
			"gate has stopped seeing what it guards", refreshTokenStorePath)
	}
}

// TestRevokingAFamilyLocksItFirst is the mirror image. A single UPDATE takes its
// snapshot when it starts, which is before it waits for a rotation's row locks,
// so it revokes every row of the family except the successor that rotation added
// while it waited. Taking the locks in a statement of their own is what gives the
// UPDATE a snapshot that contains the successor.
func TestRevokingAFamilyLocksItFirst(t *testing.T) {
	root := repoRoot(t)
	statements := refreshTokenStatements(t, root)

	revokers := map[string]int{}
	for _, st := range statements {
		if strings.Contains(st.sql, "SET revoked = TRUE") && strings.Contains(st.sql, "WHERE family_id") {
			revokers[st.method] = st.line
		}
	}
	if len(revokers) == 0 {
		t.Fatalf("no statement in %s revokes a rotation family; reuse detection has nothing to "+
			"execute and this gate has stopped seeing what it guards", refreshTokenStorePath)
	}

	for method, line := range revokers {
		var locks bool
		for _, st := range statements {
			if st.method == method && strings.Contains(st.sql, "FOR UPDATE") {
				locks = true
			}
		}
		if !locks {
			t.Errorf("%s:%d %s revokes a family without locking its rows first. The UPDATE waits for "+
				"a rotation in progress and then runs on a snapshot taken before that rotation "+
				"inserted its successor, so the one row that matters is the one row it misses and "+
				"the burned family keeps a usable token.",
				refreshTokenStorePath, line, method)
		}
	}
}

// TestARefusedRotationIsReportedAsAReplay checks the service half. The store can
// only refuse the insert; whether that refusal ends the session depends on the
// rotation path treating it as the replay it always is, rather than letting it
// fall through to the generic error path and answer 500 while the caller retries
// with a token that still works.
//
// The function is found by what it handles rather than by name, so moving the
// rotation tail out of Refresh does not quietly retire the gate.
func TestARefusedRotationIsReportedAsAReplay(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "internal", "service", "auth.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse internal/service/auth.go: %v", err)
	}
	src := readFileString(t, path)

	var handlers int
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		if start < 0 || end > len(src) || start >= end {
			continue
		}
		body := src[start:end]
		if !strings.Contains(body, "repository.ErrFamilyRevoked") {
			continue
		}
		handlers++
		if !strings.Contains(body, "ErrReplayDetected") {
			t.Errorf("%s handles repository.ErrFamilyRevoked without returning ErrReplayDetected. "+
				"The store refused to insert a successor into a family that a concurrent replay had "+
				"just revoked, and the caller is told something else: the one request that has to be "+
				"stopped is the one that is not reported as a replay.", fn.Name.Name)
		}
	}

	if handlers == 0 {
		t.Fatal("no method in internal/service/auth.go handles repository.ErrFamilyRevoked. The " +
			"store refuses to extend a revoked family and the service returns that refusal as an " +
			"unclassified error, so the caller gets a 500 and retries and nothing records that a " +
			"replay of the family was what stopped it.")
	}
}
