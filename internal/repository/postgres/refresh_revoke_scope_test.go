package postgres

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// Revoking a family, a device, a user's sessions or every session in the system
// are four scopes of one operation, and they share a hazard in both directions.
// Written as a bare UPDATE, each of them misses the successor of a rotation it
// overlapped. Given a lock, each of them starts competing for rows the rotation
// path already locks by family, and two transactions taking the same rows in
// different orders is a deadlock in the authentication path.
//
// The tests here pin both halves at the level a race test cannot reach: that the
// statements are shaped the way the argument needs, on every path, whether or
// not a scheduler ever produces the interleaving that would expose the loss.

// statementsByMethod returns every SQL literal in refresh_token.go, keyed by the
// method it is issued from.
func statementsByMethod(t *testing.T) map[string][]string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "refresh_token.go", nil, 0)
	if err != nil {
		t.Fatalf("parse refresh_token.go: %v", err)
	}

	found := map[string][]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Recv == nil {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			lit, ok := inner.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			unquoted, err := strconv.Unquote(lit.Value)
			if err != nil || !strings.Contains(unquoted, "auth.refresh_tokens") {
				return true
			}
			found[fn.Name.Name] = append(found[fn.Name.Name], unquoted)
			return true
		})
		return false
	})
	return found
}

// The lock order is a property of every locking statement at once: one scan that
// does not sort is enough to reintroduce the cycle, because it only takes two
// transactions disagreeing about which row comes first. It is asserted
// structurally because the interleaving that exposes it needs a third
// transaction holding exactly the right row at exactly the right moment, so a
// statement can lose its ordering and every race test in the suite can still
// pass.
func TestRefreshTokenRepo_EveryLockingScanTakesItsRowsInAscendingIdOrder(t *testing.T) {
	byMethod := statementsByMethod(t)

	// A statement that stopped locking would satisfy the assertion below
	// vacuously, so the set of methods that must lock is pinned too.
	for _, method := range []string{
		"Create", "RevokeByDeviceID", "RevokeFamily", "RevokeAllForUser", "DeleteExpired",
	} {
		if !anyContains(byMethod[method], "FOR UPDATE") {
			t.Errorf("%s no longer takes row locks; what it writes is decided on a snapshot, "+
				"which cannot see a revocation or a rotation that is still in flight", method)
		}
	}

	for method, statements := range byMethod {
		for _, sql := range statements {
			if !strings.Contains(sql, "FOR UPDATE") || strings.Contains(sql, "ORDER BY id FOR UPDATE") {
				continue
			}
			t.Errorf("%s locks rows without ordering them: %q\n"+
				"a scan takes its rows one at a time, so it can hold one and wait for another. "+
				"Two paths doing that in different orders deadlock, and the caller PostgreSQL "+
				"picks loses a logout or a legitimate client's refresh with 40P01", method, sql)
		}
	}
}

func anyContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// A mass write locks every row it touches whether or not it says so. DELETE and
// UPDATE take their row locks as the scan reaches each row, so a statement with
// no FOR UPDATE anywhere in it is still a transaction holding one row and
// waiting for the next, in whatever order the planner picked. That is how the
// expiry reaper becomes able to kill a user's logout with 40P01, despite saying
// nothing about locking and only ever removing rows that are already spent.
//
// So the rule is about the write, not about the lock: every statement here that
// can touch more than one row must either lock those rows in the file's order
// first, or take the table.
func TestRefreshTokenRepo_NoStatementWritesManyRowsWithoutLockingThemFirst(t *testing.T) {
	byMethod := statementsByMethod(t)

	for method, statements := range byMethod {
		guarded := anyContains(statements, "FOR UPDATE") || anyContains(statements, "LOCK TABLE")
		for _, sql := range statements {
			if !strings.Contains(sql, "UPDATE auth.refresh_tokens SET") &&
				!strings.Contains(sql, "DELETE FROM auth.refresh_tokens") {
				continue
			}
			// A write keyed on the primary key touches one row, so it holds one
			// lock and waits for nothing. It cannot be half of a cycle.
			if strings.Contains(sql, "WHERE id = $1") {
				continue
			}
			if guarded {
				continue
			}
			t.Errorf("%s writes many rows with nothing locking them first: %q\n"+
				"it takes its snapshot before it waits, so it misses the successor of any rotation "+
				"it overlapped, and it takes its row locks in the planner's order, which deadlocks "+
				"against every scoped revocation in this file", method, sql)
		}
	}
}

// The pre-lock is the whole fix and it is invisible in the result: the write
// that follows it touches the same rows either way, and only a rotation
// committing in the window between the two tells them apart. So the shape is
// asserted directly, as one transaction holding a lock across the write. A
// refactor that folds the two back into a single statement produces a repository
// that passes every functional test and silently stops ending sessions that are
// mid-rotation.
func TestRefreshTokenRepo_EveryWideRevocationLocksBeforeItWrites(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		call func(*RefreshTokenRepo) error
		// wantLock and wantWrite are the fragments each statement must carry.
		wantLock  []string
		wantWrite []string
	}{
		{
			name:      "the reuse-detection response burns one family",
			call:      func(r *RefreshTokenRepo) error { return r.RevokeFamily(ctx, "fam-1") },
			wantLock:  []string{"family_id", "ORDER BY id FOR UPDATE"},
			wantWrite: []string{"UPDATE auth.refresh_tokens SET revoked = TRUE", "family_id"},
		},
		{
			name:      "signing out one device",
			call:      func(r *RefreshTokenRepo) error { return r.RevokeByDeviceID(ctx, "dev-1") },
			wantLock:  []string{"device_id", "ORDER BY id FOR UPDATE"},
			wantWrite: []string{"UPDATE auth.refresh_tokens SET revoked = TRUE", "device_id"},
		},
		{
			name:      "logging out every session for a user",
			call:      func(r *RefreshTokenRepo) error { return r.RevokeAllForUser(ctx, "u-1") },
			wantLock:  []string{"user_id", "ORDER BY id FOR UPDATE"},
			wantWrite: []string{"UPDATE auth.refresh_tokens SET revoked = TRUE", "user_id"},
		},
		{
			// The break-glass revoke names every row there is, so it takes the
			// table instead of sorting it. EXCLUSIVE is the mode that stops
			// every writer without stopping a plain read.
			name:      "the break-glass system-wide revoke",
			call:      func(r *RefreshTokenRepo) error { return r.RevokeAll(ctx) },
			wantLock:  []string{"LOCK TABLE auth.refresh_tokens", "EXCLUSIVE MODE"},
			wantWrite: []string{"UPDATE auth.refresh_tokens SET revoked = TRUE", "revoked = FALSE"},
		},
		{
			// Erasure removes the rows outright, and a row a rotation inserts
			// after the delete has taken its snapshot is a fingerprint hash and
			// a device reference outliving the erasure that reported them gone.
			// It takes the table because vault_admin, which runs admin-side
			// erasure, holds DELETE but not UPDATE, and a row lock needs UPDATE.
			name:      "erasing every token row for a user",
			call:      func(r *RefreshTokenRepo) error { return r.DeleteAllForUser(ctx, "u-1") },
			wantLock:  []string{"LOCK TABLE auth.refresh_tokens", "EXCLUSIVE MODE"},
			wantWrite: []string{"DELETE FROM auth.refresh_tokens", "user_id"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sent []string
			record := func(tag string) apPGReply {
				return func(q string) []byte {
					sent = append(sent, q)
					return append(apMsg('C', apCStr(tag)), apReadyInTx()...)
				}
			}

			db := apStartPG(t,
				apPGRule{match: "begin", reply: record("BEGIN")},
				apPGRule{match: "FOR UPDATE", reply: record("SELECT 2")},
				apPGRule{match: "LOCK TABLE", reply: record("LOCK TABLE")},
				apPGRule{match: "UPDATE auth.refresh_tokens", reply: record("UPDATE 2")},
				apPGRule{match: "DELETE FROM auth.refresh_tokens", reply: record("DELETE 2")},
				apPGRule{match: "commit", reply: func(q string) []byte {
					sent = append(sent, q)
					return append(apMsg('C', apCStr("COMMIT")), apReadyIdle()...)
				}},
			)

			if err := tc.call(NewRefreshTokenRepo(db)); err != nil {
				t.Fatalf("revoke: %v", err)
			}

			if len(sent) != 4 {
				t.Fatalf("statements sent = %q, want begin, a lock, the write and commit; a revocation "+
					"outside a transaction cannot hold its lock across the write, which is the "+
					"only thing the lock is for", sent)
			}
			if !strings.Contains(strings.ToLower(sent[0]), "begin") {
				t.Errorf("first statement = %q, want begin", sent[0])
			}
			for _, frag := range tc.wantLock {
				if !strings.Contains(sent[1], frag) {
					t.Errorf("lock statement = %q, want it to contain %q", sent[1], frag)
				}
			}
			for _, frag := range tc.wantWrite {
				if !strings.Contains(sent[2], frag) {
					t.Errorf("write statement = %q, want it to contain %q", sent[2], frag)
				}
			}
			if !strings.Contains(strings.ToLower(sent[3]), "commit") {
				t.Errorf("last statement = %q, want commit", sent[3])
			}
		})
	}
}
