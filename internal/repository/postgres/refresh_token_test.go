package postgres

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// family_created_at (migration 013) is the only fact that bounds a session's
// total age. Rotation issues a fresh refresh TTL every time, so if this column
// can be moved forward, or read as "unknown" without anyone noticing, the
// absolute session lifetime silently stops existing and every session is
// unbounded again — which is the state migration 013 was written to end.

// A lookup failure that came back as a usable timestamp would be the worst
// outcome: the service would compare a real deadline against a fabricated origin.
// It must be an error, and the service fails closed on it.
func TestRefreshTokenRepo_FamilyOriginSurfacesDatabaseFailures(t *testing.T) {
	repo := NewRefreshTokenRepo(deadPool(t))

	origin, err := repo.FamilyOrigin(context.Background(), "fam-1")
	if err == nil {
		t.Error("FamilyOrigin reported success against an unreachable database")
	}
	if !origin.IsZero() {
		t.Errorf("FamilyOrigin returned %v on failure; a non-zero origin would be read as a dated session", origin)
	}
}

func TestRefreshTokenRepo_FamilyOriginReturnsTheStoredOrigin(t *testing.T) {
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	db := blobClientFakeDB(t, blobClientRowScript{
		match:  "SELECT MIN(family_created_at)",
		fields: []pgproto3.FieldDescription{blobClientField("min", blobClientOIDTimestamptz)},
		rows:   [][][]byte{{blobClientTimestamptz(created)}},
	})
	repo := NewRefreshTokenRepo(db)

	origin, err := repo.FamilyOrigin(blobClientCtx(t), "fam-1")
	if err != nil {
		t.Fatalf("FamilyOrigin: %v", err)
	}
	if !origin.Equal(created) {
		t.Errorf("FamilyOrigin = %v, want %v", origin.UTC(), created)
	}
}

// A family with no rows aggregates to NULL. That is "there is no session to
// date", not "the session began at the epoch" — an epoch origin would expire
// every session, and a zero-with-no-error is what the service reads as unknown.
func TestRefreshTokenRepo_FamilyOriginOfAVanishedFamilyIsZero(t *testing.T) {
	db := blobClientFakeDB(t, blobClientRowScript{
		match:  "SELECT MIN(family_created_at)",
		fields: []pgproto3.FieldDescription{blobClientField("min", blobClientOIDTimestamptz)},
		rows:   [][][]byte{{nil}},
	})
	repo := NewRefreshTokenRepo(db)

	origin, err := repo.FamilyOrigin(blobClientCtx(t), "fam-gone")
	if err != nil {
		t.Fatalf("FamilyOrigin: %v", err)
	}
	if !origin.IsZero() {
		t.Errorf("FamilyOrigin = %v for a family with no rows, want the zero time", origin)
	}
}

// The invariant is structural, so the test is too: a rotation must not be able to
// hand the database a new family origin. family_created_at is derived from the
// family itself, and no future edit may quietly turn it into a bound parameter —
// a caller-supplied origin is a session that renews its own deadline, which is
// exactly the finding migration 013 closes.
//
// This used to be spelled "Create binds nine parameters", counting the derived
// column as the tenth. That proxy expired when migration 038 added dpop_jkt,
// which is a real tenth parameter: supplied, but consumed only on a family's
// first row. Counting was the weaker statement in any case — it says how many
// parameters exist, never which column each one reaches — so the assertion is
// now written against the expression that actually produces the origin.
func TestRefreshTokenRepo_CreateNeverTakesTheFamilyOriginFromItsCaller(t *testing.T) {
	sql := createStatementSQL(t)

	if !strings.Contains(sql, "family_created_at") {
		t.Fatal("Create does not write family_created_at; the absolute session lifetime has nothing to measure from")
	}
	if !strings.Contains(sql, "SELECT MIN(family_created_at) FROM auth.refresh_tokens WHERE family_id = $5") {
		t.Error("Create does not read the family's existing origin back; each rotation would stamp a new one")
	}
	// The only parameter the origin expression may fall back to is $9, the row's
	// own created_at, which migration 013 permits for a family with no rows yet.
	// Any other placeholder in that slot is a caller-supplied origin.
	if !strings.Contains(sql,
		"COALESCE((SELECT MIN(family_created_at) FROM auth.refresh_tokens WHERE family_id = $5), $9)") {
		t.Error("the family_created_at expression is no longer COALESCE(<the family's own MIN>, $9); " +
			"a rotation can hand the database an origin of its choosing and renew its own deadline")
	}
}

// The same shape of invariant for the DPoP sender constraint (migration 038).
//
// dpop_jkt IS a bound parameter, unlike family_created_at, because a login has to
// be able to establish a binding. So the guard cannot be "it is never supplied";
// it is "it is consumed only when the family has no rows".
//
// The CASE is load-bearing and a COALESCE is not equivalent. NULL is a meaningful
// value in this column — it is an ordinary bearer family — so COALESCE would let
// a rotation of an UNBOUND family fall through to the caller's argument and bind
// the session to a key the caller chose. That is the same laundering
// AuthService.enforceDPoPBinding refuses, reached through the store instead.
func TestRefreshTokenRepo_CreateOnlyTakesADPoPBindingForAFamilysFirstRow(t *testing.T) {
	sql := createStatementSQL(t)

	if !strings.Contains(sql, "dpop_jkt") {
		t.Fatal("Create does not write dpop_jkt; a rotation then has no stored binding to be held " +
			"to, and mints cnf.jkt from whoever presented the cookie")
	}
	if !strings.Contains(sql, "CASE WHEN COUNT(*) = 0 THEN $10::varchar ELSE MIN(dpop_jkt) END") {
		t.Error("the dpop_jkt expression no longer distinguishes an empty family from an unbound " +
			"one; a COALESCE here lets a presented proof bind a family that never had a binding, " +
			"and lets a rotation re-bind one that did")
	}
	if highestPlaceholder(sql) != 10 {
		t.Errorf("Create binds %d parameters, want 10: the row's nine columns plus the binding a "+
			"login establishes on the family's first row", highestPlaceholder(sql))
	}
}

// The erasure gate is structural for the same reason the origin is: the
// interleaving that exposes its absence needs the cascade to land between one
// request's account-state read and its insert, so every functional test in the
// suite passes without it. A family erasure emptied carries no revoked row, so
// the guard above it is satisfied by an empty set and the rotation puts a
// fingerprint hash and a device reference straight back into the table the
// erasure reported it had cleared.
func TestRefreshTokenRepo_CreateRefusesARotationIntoAnErasedAccount(t *testing.T) {
	sql := createStatementSQL(t)

	if !strings.Contains(sql, "FROM auth.users WHERE id = $2 AND deleted = FALSE") {
		t.Error("Create no longer asks whether the account survives; erasure removes this table's rows " +
			"rather than marking them, so the revoked-row guard has nothing left to see and a rotation " +
			"in flight repopulates the family it just emptied")
	}
	// The gate must reuse the user id the row already carries rather than take one
	// of its own; a second user-id parameter is a gate that can be pointed at a
	// different account than the row is written for. Asserted as the expression
	// rather than as a parameter count, for the reason given above.
	if strings.Contains(sql, "FROM auth.users WHERE id = $11") {
		t.Error("the account gate binds a user id of its own instead of reusing $2")
	}
}

// createStatementSQL returns the SQL literal inside RefreshTokenRepo.Create as it
// is actually shipped.
func createStatementSQL(t *testing.T) string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "refresh_token.go", nil, 0)
	if err != nil {
		t.Fatalf("parse refresh_token.go: %v", err)
	}

	// The INSERT lives in a package-level const that Create references so the
	// capped and uncapped insert paths share one statement; resolve those const
	// references so the gate reads the SQL Create actually issues.
	sqlConsts := sqlStringConsts(file)

	var sql string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Create" || fn.Recv == nil {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			switch node := inner.(type) {
			case *ast.BasicLit:
				if node.Kind == token.STRING {
					if unquoted, err := strconv.Unquote(node.Value); err == nil && strings.Contains(unquoted, "INSERT INTO auth.refresh_tokens") {
						sql = unquoted
					}
				}
			case *ast.Ident:
				if unquoted, ok := sqlConsts[node.Name]; ok && strings.Contains(unquoted, "INSERT INTO auth.refresh_tokens") {
					sql = unquoted
				}
			}
			return true
		})
		return false
	})

	if sql == "" {
		t.Fatal("no INSERT statement found in RefreshTokenRepo.Create")
	}
	return sql
}

// sqlStringConsts maps every package-level string const in the parsed file to its
// value, so a walk over a method body can resolve SQL that has been lifted into a
// shared const back to the statement the method issues.
func sqlStringConsts(file *ast.File) map[string]string {
	consts := map[string]string{}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if unquoted, err := strconv.Unquote(lit.Value); err == nil {
					consts[name.Name] = unquoted
				}
			}
		}
	}
	return consts
}

// highestPlaceholder reports the largest $N bound parameter in a statement.
func highestPlaceholder(sql string) int {
	highest := 0
	for i := 0; i < len(sql); i++ {
		if sql[i] != '$' {
			continue
		}
		j := i + 1
		for j < len(sql) && sql[j] >= '0' && sql[j] <= '9' {
			j++
		}
		if n, err := strconv.Atoi(sql[i+1 : j]); err == nil && n > highest {
			highest = n
		}
	}
	return highest
}
