// Subject-linked table register: every table that holds data about a person must
// declare what an Art. 17 erasure does to it.
//
// The bug this exists to prevent is not "someone forgot a table". It is a wrong
// premise that any competent schema author would reach: migration 028 wrote
//
//     user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE
//
// and concluded, in the file, that "account erasure (Art. 17) removes a user's
// countries automatically with no bespoke cascade step". Every word of that is
// standard PostgreSQL and it is false here, because vault42 never deletes the
// parent row: erasure tombstones auth.users through auth.erase_user_identity()
// and leaves it in place so the foreign keys stay valid. A referential action
// that fires only on DELETE therefore never fires at all, and the table quietly
// kept a user's login-country history across an erasure that reported success.
//
// internal/service/erasure.go had already written the correction down for the MFA
// tables. It did not help: a comment in a Go file is not reachable from the mind
// of someone writing SQL eighteen migrations later. So the check moves into the
// build.
//
// HOW IT WORKS
//
// The set of subject-linked tables is derived from migrations/*.sql, not from a
// list someone maintains: a table qualifies if it references auth.users or
// carries a column that names a data subject (user_id, pseudonym, pseudonym_id,
// subject_hash). Each one must appear in erasureRegister below with either the
// cascade step that clears it — proven against both the repository source and the
// SQL — or a written reason it is deliberately retained. A new migration that
// adds a PII table and says nothing fails this test, which is the point: the
// erasure story has to be decided when the table is written, by the person who
// knows what is in it.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go/ast"
	"go/parser"
	"go/token"
)

// subjectColumns name a data subject. A table carrying one holds personal data
// about somebody, whether or not it also declares a foreign key: the
// pseudonym-keyed stores (identity.profiles, objects.blobs,
// objects.service_documents) have no FK at all and are just as much in scope.
var subjectColumns = map[string]bool{
	"user_id":      true,
	"pseudonym":    true,
	"pseudonym_id": true,
	"subject_hash": true,
}

// erasureEntry is one table's erasure story.
//
// Exactly one of erasedBy and retained is set. erasedBy names the repository
// method DeleteAccount must call; retained is the written justification for a
// table erasure deliberately does not clear, and it is prose on purpose — the
// point of the register is that somebody had to think, not that a box was ticked.
type erasureEntry struct {
	// erasedBy is the call the erasure cascade must make, written
	// "<field>.<Method>" as it appears in DeleteAccount. The field matters as much
	// as the method: half the cascade calls something named DeleteAllForUser, so a
	// method name alone would let the login-country delete be removed entirely
	// while the devices delete kept this entry green.
	erasedBy string
	// source is the repository file, relative to the repo root, whose
	// implementation of erasedBy carries the SQL.
	source string
	// proof is the SQL fragment that must appear in source. When it does not
	// itself name the table (a SECURITY DEFINER erasure function does not), some
	// migration must name both, which is what ties the function to the table.
	proof string
	// retained explains why erasure does not clear this table.
	retained string
	// note records what the table holds and anything a reader of this register
	// needs in order to judge the entry. Required on every entry.
	note string
}

// erasureRegister is the audit. Adding a subject-linked table means adding a line
// here, and the compiler will not tell you: this test will.
var erasureRegister = map[string]erasureEntry{
	// --- cleared by the cascade -------------------------------------------
	"auth.password_history": {
		erasedBy: "pwHistory.DeleteAllForUser",
		source:   "internal/repository/postgres/password_history.go",
		proof:    "DELETE FROM auth.password_history",
		note:     "previous password hashes (migration 001)",
	},
	"auth.social_accounts": {
		erasedBy: "social.DeleteAllForUser",
		source:   "internal/repository/postgres/social_account.go",
		proof:    "DELETE FROM auth.social_accounts",
		note:     "provider identity, provider email and encrypted provider tokens (migration 001)",
	},
	"auth.refresh_tokens": {
		erasedBy: "tokens.DeleteAllForUser",
		source:   "internal/repository/postgres/refresh_token.go",
		proof:    "DELETE FROM auth.refresh_tokens",
		note: "session lineage and device references (migration 001). Hard-deleted rather " +
			"than revoked: a revoked row keeps the fingerprint hash",
	},
	"auth.devices": {
		erasedBy: "devices.DeleteAllForUser",
		source:   "internal/repository/postgres/device.go",
		proof:    "DELETE FROM auth.devices",
		note:     "device fingerprints, IP addresses and user agents (migration 001)",
	},
	"auth.totp_secrets": {
		erasedBy: "totp.DeleteByUserID",
		source:   "internal/repository/postgres/totp.go",
		proof:    "DELETE FROM auth.totp_secrets",
		note:     "encrypted TOTP seed (migration 001). ON DELETE CASCADE never fires; erased explicitly",
	},
	"auth.webauthn_credentials": {
		erasedBy: "webauthn.DeleteAllForUser",
		source:   "internal/repository/postgres/webauthn.go",
		proof:    "DELETE FROM auth.webauthn_credentials",
		note:     "authenticator public keys and credential ids (migration 001)",
	},
	"auth.backup_codes": {
		erasedBy: "backupCodes.PurgeAllForUser",
		source:   "internal/repository/postgres/backup_code.go",
		proof:    "DELETE FROM auth.backup_codes",
		note: "recovery-code hashes (migration 001). Purge, not DeleteAllForUser: the latter " +
			"only marks codes used and leaves the hash and the user_id behind",
	},
	"auth.login_countries": {
		erasedBy: "loginCountries.DeleteAllForUser",
		source:   "internal/repository/postgres/login_country.go",
		proof:    "auth.erase_login_countries",
		note: "the countries an account has signed in from (migration 028) — location data. " +
			"This is the table the register was written for: its ON DELETE CASCADE cannot " +
			"fire, so the rows outlived every erasure until migration 030",
	},
	"identity.profiles": {
		erasedBy: "identity.Delete",
		source:   "internal/repository/postgres/identity.go",
		proof:    "DELETE FROM identity.profiles",
		note: "the encrypted identity profile (migration 001), keyed by HMAC pseudonym. The " +
			"cascade derives the same pseudonym the identity service does; a divergence " +
			"would delete nothing and report success",
	},
	"objects.blobs": {
		erasedBy: "blobs.DeleteAllForPseudonym",
		source:   "internal/repository/postgres/blob.go",
		proof:    "DELETE FROM objects.blobs",
		note:     "user-stored encrypted objects and their encrypted labels (migration 001)",
	},
	"objects.service_documents": {
		erasedBy: "svcDocs.DeleteAllForSubject",
		source:   "internal/repository/postgres/servicedoc.go",
		proof:    "DELETE FROM objects.service_documents",
		note: "documents other services filed ABOUT the user (migration 014). Keyed by subject " +
			"across every owning client, so a service registered after the account still " +
			"loses its documents",
	},
	"auth.users": {
		erasedBy: "users.SoftDeleteScrub",
		source:   "internal/repository/postgres/user.go",
		proof:    "auth.erase_user_identity",
		note: "the account row itself. Scrubbed in place rather than deleted — the row stays " +
			"so every foreign key above stays valid, and the account-state gate refuses " +
			"deleted rows at login. auth.erase_user_identity() is the only writer",
	},

	// --- deliberately retained --------------------------------------------
	"auth.account_recovery": {
		retained: "This table IS the erasure: it holds the encrypted, pseudonym-keyed recovery " +
			"record the cascade writes before it scrubs, readable only with the offline " +
			"recovery private key. Clearing it would defeat its purpose. It is bounded by " +
			"time instead — VAULT_RECOVERY_RETENTION_DAYS, migrations 007 and 011 — and " +
			"append-only by trigger, so nothing can rewrite an escrow record either.",
		note: "pseudonym, encrypted profile payload, deleted_at/deleted_by/reason (migration 007)",
	},
	"audit.audit_log": {
		retained: "Art. 17(3): the security and abuse record a controller must keep, and the " +
			"only evidence that an erasure happened at all. Append-only by trigger " +
			"(migration 001) and unreachable for DELETE by either application role, so " +
			"erasure could not clear it even if it should. Bounded by the retention job " +
			"instead (migrations 012 and 018) under Art. 5(1)(e).",
		note: "user_id, ip, user_agent, fingerprint_hash, device_id, metadata (migration 001)",
	},
}

// erasureCascadeSource is the file whose DeleteAccount must call every erasedBy
// method in the register.
var erasureCascadeSource = filepath.Join("internal", "service", "erasure.go")

var (
	createTableRe = regexp.MustCompile(`(?i)^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_]+\.[a-z_]+)`)
	sqlCommentRe  = regexp.MustCompile(`--.*$`)
	firstWordRe   = regexp.MustCompile(`^[a-z_][a-z0-9_]*`)
)

// subjectTablesFromMigrations reads the schema as the source of truth and returns
// every table that holds data about a data subject.
//
// Deriving the set rather than listing it is what makes the gate hold: a list
// would have to be updated by the same person who forgot the erasure step.
func subjectTablesFromMigrations(t *testing.T, root string) map[string]string {
	t.Helper()
	dir := filepath.Join(root, "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		t.Fatal("no migrations found; this gate has stopped seeing the schema it guards")
	}

	found := map[string]string{} // table -> migration file that created it
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("read migration %s: %v", f, err)
		}

		var table string
		var isSubject bool
		for _, line := range strings.Split(string(raw), "\n") {
			// Comments come off first. Several migrations discuss "REFERENCES
			// auth.users" in prose, and a header paragraph is not a schema.
			code := strings.TrimSpace(sqlCommentRe.ReplaceAllString(line, ""))
			if code == "" {
				continue
			}

			if table == "" {
				if m := createTableRe.FindStringSubmatch(code); m != nil {
					table, isSubject = m[1], m[1] == "auth.users"
				} else if strings.Contains(strings.ToUpper(code), "REFERENCES AUTH.USERS") {
					// A foreign key added outside a CREATE TABLE (an ALTER TABLE ...
					// ADD CONSTRAINT). Nothing does this today, and rather than
					// guess which table it attached to, say so and stop.
					t.Fatalf("%s: a reference to auth.users appears outside a CREATE TABLE:\n\t%s\n"+
						"This gate only reads CREATE TABLE bodies, so that table is invisible to it. "+
						"Teach it to read this form before landing the migration.", f, code)
				}
				continue
			}

			if strings.HasPrefix(code, ")") { // end of the CREATE TABLE body
				if isSubject {
					if _, seen := found[table]; !seen {
						found[table] = f
					}
				}
				table = ""
				continue
			}

			if strings.Contains(strings.ToUpper(code), "REFERENCES AUTH.USERS") {
				isSubject = true
			}
			if col := firstWordRe.FindString(strings.ToLower(code)); subjectColumns[col] {
				isSubject = true
			}
		}
		if table != "" {
			t.Fatalf("%s: CREATE TABLE %s has no closing line this gate could find; "+
				"it cannot tell whether the table holds subject data", f, table)
		}
	}
	return found
}

// cascadeCalls returns every "<field>.<Method>" invoked on the service receiver
// inside DeleteAccount, read with go/ast rather than grep so a change in call
// style is caught rather than silently passing. Calls inside closures count: the
// service-document delete is wrapped in one.
//
// The field half is what makes the result usable. Four stores expose a method
// called DeleteAllForUser, so a set of bare method names would still contain it
// after the login-country delete was deleted outright.
func cascadeCalls(t *testing.T, root string) map[string]bool {
	t.Helper()
	path := filepath.Join(root, erasureCascadeSource)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", erasureCascadeSource, err)
	}

	calls := map[string]bool{}
	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name.Name != "DeleteAccount" {
			return true
		}
		found = true
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// s.<field>.<Method>(...) — the only shape the cascade uses to reach a
			// store. Anything else (a bare helper, a closure variable) is not a
			// repository call and is not what the register describes.
			if recv, ok := sel.X.(*ast.SelectorExpr); ok {
				calls[recv.Sel.Name+"."+sel.Sel.Name] = true
			}
			return true
		})
		return true
	})
	if !found {
		t.Fatalf("no DeleteAccount found in %s; this gate has stopped seeing the cascade it guards",
			erasureCascadeSource)
	}
	return calls
}

// TestEverySubjectLinkedTableDeclaresItsErasure is the gate. A subject-linked
// table the register does not mention fails the build.
func TestEverySubjectLinkedTableDeclaresItsErasure(t *testing.T) {
	root := repoRoot(t)
	tables := subjectTablesFromMigrations(t, root)

	// A gate that silently matches nothing is worse than no gate.
	if len(tables) < 12 {
		t.Fatalf("found only %d subject-linked table(s) in migrations/: %v.\n"+
			"The schema has at least twelve, so the detector has stopped seeing them.",
			len(tables), tables)
	}

	for _, table := range sortedKeys(tables) {
		if _, ok := erasureRegister[table]; !ok {
			t.Errorf("%s (created in migrations/%s) holds data about a data subject and no entry "+
				"in erasureRegister says what an Art. 17 erasure does to it.\n"+
				"Add one: either the cascade step that clears it, or a written reason it is "+
				"retained. Do not assume ON DELETE CASCADE covers it — erasure tombstones "+
				"auth.users and never deletes the row, so that clause never fires.",
				table, tables[table])
		}
	}

	// The register must not rot in the other direction either: an entry for a table
	// that no longer exists is a claim nothing backs.
	for _, table := range sortedRegisterKeys(erasureRegister) {
		if _, ok := tables[table]; !ok {
			t.Errorf("erasureRegister has an entry for %s, which migrations/ does not create as "+
				"a subject-linked table. Either the table was dropped and the entry should go, "+
				"or its subject column was renamed and the detector no longer sees it.", table)
		}
	}
}

// TestErasureRegisterEntriesAreBacked checks the register's claims against the
// code. A register nobody verifies degrades into a list of intentions.
func TestErasureRegisterEntriesAreBacked(t *testing.T) {
	root := repoRoot(t)
	calls := cascadeCalls(t, root)
	migrations := allMigrationText(t, root)

	for _, table := range sortedRegisterKeys(erasureRegister) {
		e := erasureRegister[table]
		t.Run(table, func(t *testing.T) {
			if strings.TrimSpace(e.note) == "" {
				t.Errorf("%s: no note. Say what the table holds, so the next reader can judge "+
					"the entry without opening the migration.", table)
			}
			if (e.erasedBy == "") == (e.retained == "") {
				t.Fatalf("%s: set exactly one of erasedBy and retained; a table is either cleared "+
					"by the cascade or deliberately kept, and it must be clear which.", table)
			}

			if e.retained != "" {
				// The bar is a reason, not a word. Anything shorter than a sentence is
				// somebody moving past the check rather than making a decision.
				if len(strings.Fields(e.retained)) < 12 {
					t.Errorf("%s: the retention reason is too thin to be a decision:\n\t%q\n"+
						"Say what the data is for, what lawful basis keeps it, and what bounds "+
						"it instead of erasure.", table, e.retained)
				}
				return
			}

			if !calls[e.erasedBy] {
				t.Errorf("%s: the register says erasure clears it via s.%s, but %s's DeleteAccount "+
					"makes no such call. The table is retained across every erasure while the "+
					"endpoint reports success.", table, e.erasedBy, erasureCascadeSource)
			}

			src, err := os.ReadFile(filepath.Join(root, e.source))
			if err != nil {
				t.Fatalf("%s: register names %s as the eraser and it cannot be read: %v",
					table, e.source, err)
			}
			body := string(src)
			method := e.erasedBy[strings.LastIndex(e.erasedBy, ".")+1:]
			if !strings.Contains(body, "func (r *") || !strings.Contains(body, method+"(ctx context.Context") {
				t.Errorf("%s: %s does not define %s. The register is pointing at the wrong file.",
					table, e.source, method)
			}
			if !strings.Contains(body, e.proof) {
				t.Errorf("%s: %s does not contain %q. Either the statement changed or the "+
					"register is describing code that no longer exists.", table, e.source, e.proof)
			}

			// The proof either names the table itself, or names a SECURITY DEFINER
			// function — in which case a migration must tie that function to this
			// table. Without this an erasure could call a correctly-named function
			// that clears something else entirely.
			if strings.Contains(e.proof, table) {
				return
			}
			var tied bool
			for file, text := range migrations {
				if strings.Contains(text, e.proof) && strings.Contains(text, table) {
					tied = true
					_ = file
					break
				}
			}
			if !tied {
				t.Errorf("%s: the eraser runs %q, which does not name the table, and no migration "+
					"defines that function against %s. Nothing connects the call to the rows it "+
					"is supposed to remove.", table, e.proof, table)
			}
		})
	}
}

// allMigrationText returns every migration's contents keyed by filename.
func allMigrationText(t *testing.T, root string) map[string]string {
	t.Helper()
	dir := filepath.Join(root, "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read migration %s: %v", e.Name(), err)
		}
		out[e.Name()] = string(raw)
	}
	return out
}

// sortedRegisterKeys keeps the failure output stable across runs; the package
// already has sortedKeys for map[string]string, which the register is not.
func sortedRegisterKeys(m map[string]erasureEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
