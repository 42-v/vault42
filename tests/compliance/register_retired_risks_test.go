package compliance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// =============================================================================
// Retired risks have to stay retired.
//
// The register's accepted_risks map is heavily gated: every entry owes a
// rationale, a compensating control, a residual-risk statement, a revisit
// condition and a named accepting party, and a test checks all five. The
// retired_risks map, which is where a risk goes once it is closed, owed
// nothing. Twelve entries, each a paragraph asserting that something is fixed,
// and no rule that anything keeps it fixed.
//
// That is the wrong way round. An open risk is watched because it is open. A
// closed one is the entry nobody looks at again, so a regression in the code
// that closed it is silent -- the register would go on saying the risk is
// retired, in prose, with a citation to a line that had since moved.
//
// This is SSDF RV.3.3 and RV.3.4 made checkable: eradicate a class of
// vulnerability, then change the process so it cannot come back. The gate is
// that every retired risk names a test, and that the test still exists.
//
// Seven of the twelve already named one, out of habit rather than rule. The
// other five named source lines instead. The tests existed in every case; some
// were in the package's own suite rather than in tests/compliance, which is why
// the index below reads the whole repository.
// =============================================================================

// testNameInProse matches a Go test identifier written in a sentence.
var testNameInProse = regexp.MustCompile(`\bTest[A-Za-z0-9_]+`)

// repoTestNames indexes every Go test function in the repository by name,
// mapping it to the file it is declared in.
//
// Deliberately not scoped to tests/compliance. A risk is closed by whatever
// test holds the behavior, and for the SMTP STARTTLS risk that is
// internal/email/smtp_starttls_test.go, which drives a fake relay that does not
// advertise the capability. Requiring the citation to point into
// tests/compliance would have meant either duplicating that test or citing a
// weaker one.
func repoTestNames(t *testing.T) map[string]string {
	t.Helper()

	root := repoRoot(t)
	names := make(map[string]string)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "dist", "coverage", "tmp", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		parsed, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// A file that does not parse is a build failure elsewhere, not this
			// test's business.
			return nil //nolint:nilerr // parse errors surface in the build, not here
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			names[fn.Name.Name] = filepath.ToSlash(rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}

	if len(names) < 500 {
		t.Fatalf("only %d test functions found in the repository; the scan is broken and every "+
			"citation below would fail for the wrong reason", len(names))
	}
	return names
}

// TestComplianceRegister_EveryRetiredRiskNamesTheTestThatKeepsItClosed covers
// SSDF RV.3.3 and RV.3.4.
func TestComplianceRegister_EveryRetiredRiskNamesTheTestThatKeepsItClosed(t *testing.T) {
	reg := loadRegister(t)
	if len(reg.RetiredRisks) == 0 {
		t.Fatal("the register lists no retired risks; the gate would be vacuous")
	}

	known := repoTestNames(t)

	ids := make([]string, 0, len(reg.RetiredRisks))
	for id := range reg.RetiredRisks {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		prose := reg.RetiredRisks[id]

		cited := testNameInProse.FindAllString(prose, -1)
		if len(cited) == 0 {
			t.Errorf("retired risk %s says what was fixed and names no test that keeps it fixed. "+
				"A closed risk is the entry nobody re-reads, so a regression in the code that "+
				"closed it would be silent and the register would go on saying it is retired. "+
				"Name the test.", id)
			continue
		}

		for _, name := range cited {
			file, ok := known[name]
			if !ok {
				t.Errorf("retired risk %s names %s as what keeps it closed, and no test by that "+
					"name exists anywhere in the repository", id, name)
				continue
			}
			t.Logf("%-7s %-70s %s", id, name, file)
		}
	}
}
