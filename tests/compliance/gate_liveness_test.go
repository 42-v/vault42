package compliance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// =============================================================================
// The gate on the gates: a check that cannot fail is worse than no check.
//
// Three separate gates in this repository have never been capable of failing,
// and each looked healthy from the outside — a green tick next to a claim
// nothing was testing.
//
//   - TestASVS_V10_4_8_PerTokenExpiryExistsAndFamilyAgeIsStillUnrecorded read
//     migrations/001_initial_schema.sql for family_created_at. That column
//     landed in 013_session_lifetime.sql, so the tripwire it was named for
//     could never trip.
//   - A fuzz target fuzzed a local copy of a validator instead of the shipped
//     one, so no input it found could ever reach the code that ships.
//   - Fifty-two Met rows rest on five umbrella tests, which means a single test
//     is the sole evidence for a dozen distinct requirements and cannot
//     possibly assert all of them.
//
// A false negative in a gate is invisible by construction: nothing goes red, so
// nobody looks. The only defense is to check the gates the way the gates check
// the code. That is what this file is.
// =============================================================================

// --- 1. A test with no failure call cannot fail -----------------------------

// failureCalls are the ways a Go test reports a failure. A test function that
// contains none of them is a program that runs and returns, which is exactly
// what a passing test looks like from the outside.
var failureCalls = map[string]struct{}{
	"Error": {}, "Errorf": {}, "Fatal": {}, "Fatalf": {}, "FailNow": {}, "Fail": {},
}

// assertionFreeByDesign are the tests that deliberately assert nothing, with the
// reason each is a measurement or a runtime-checked exercise rather than a gate.
//
// Every entry is a hole in the check below, so it is a ratchet in both
// directions: a test that grows an assertion loses its entry, and a new name may
// not be added without an argument that the runtime, not testing.T, is what
// fails it. None of these is cited as evidence by the compliance register.
var assertionFreeByDesign = map[string]string{
	"TestTOTPAttack_MeasureLengthMismatchTiming": "a measurement. It logs median compare times " +
		"per input length to show the time tracks the attacker's input rather than the secret. " +
		"A threshold here would be a timing flake on shared CI, which is a worse gate than none: " +
		"the timing property itself is asserted by SecureCompare's own tests",
	"TestKMSAttack_CloseRacesWrapOnRootSecret": "fails through the runtime, not through " +
		"testing.T: 64 goroutines wrap while Close runs, so the failure it hunts is a panic on a " +
		"released root secret or a -race report, and both fail the test without an assertion",
	"TestKeystoreAttack_RaceDetectorIsBlindToAESKeyReads": "asserts nothing on purpose, and its " +
		"own comment says why: it demonstrates that -race does not report an assembly-implemented " +
		"AES read racing a key wipe. A toolchain that started reporting it would be an " +
		"improvement, so failing on the current silence would fail on the fix",
}

func TestGateLiveness_NoComplianceTestIsIncapableOfFailing(t *testing.T) {
	for _, fn := range complianceTestFunctions(t) {
		if fn.hasSubtests {
			// A table-driven test delegates its assertions to t.Run bodies,
			// which the walk below already descends into; this flag only exists
			// so the message can say so if one is ever empty.
			continue
		}
		if reason, exempt := assertionFreeByDesign[fn.name]; exempt {
			if reason == "" {
				t.Errorf("assertionFreeByDesign[%q] carries no reason. An exemption without one is "+
					"indistinguishable from an oversight.", fn.name)
			}
			if fn.failureCalls > 0 {
				t.Errorf("%s is in assertionFreeByDesign and now contains %d failure call(s). "+
					"Delete the entry: the list may only shrink.", fn.name, fn.failureCalls)
			}
			continue
		}
		if fn.failureCalls == 0 {
			t.Errorf("%s (%s) contains no t.Error, t.Fatal or t.Fail of any kind. It runs, it "+
				"returns, and it reports success whatever the code does. A register row naming it "+
				"as evidence has a green tick and no assertion behind it. If it is a measurement "+
				"or an exercise the runtime fails, add %q to assertionFreeByDesign with that "+
				"reason.", fn.name, fn.file, fn.name)
		}
	}
}

// TestGateLiveness_NoStaleAssertionFreeExemption deletes an entry whose test has
// been deleted or renamed, so a future test reusing the name cannot inherit an
// argument written for a different one.
func TestGateLiveness_NoStaleAssertionFreeExemption(t *testing.T) {
	present := map[string]struct{}{}
	for _, fn := range complianceTestFunctions(t) {
		present[fn.name] = struct{}{}
	}
	for name := range assertionFreeByDesign {
		if _, ok := present[name]; !ok {
			t.Errorf("assertionFreeByDesign names %q, which no longer exists in %v. Remove the "+
				"entry, so a future test reusing the name cannot inherit an exemption written for "+
				"a different one.", name, gateCorpora)
		}
	}
}

// --- 2. A scan over an empty corpus passes vacuously ------------------------

// corpusBuilders are the calls that produce the set a structural test then
// asserts over. If the set comes back empty — a moved directory, a changed
// suffix, a walk that errors and is ignored — every assertion inside the loop
// is skipped and the test is green.
var corpusBuilders = map[string]string{
	"productionGoFiles":     "the production Go tree",
	"complianceTestNames":   "the compliance test functions",
	"os.ReadDir":            "a directory listing",
	"filepath.WalkDir":      "a directory walk",
	"filepath.Walk":         "a directory walk",
	"FindAllString":         "a regular-expression match set",
	"FindAllStringSubmatch": "a regular-expression match set",
}

// TestGateLiveness_EveryCorpusScanAssertsItsCorpusIsNonEmpty requires a
// structural test to state the floor it expects.
//
// productionGoFiles and complianceTestNames carry their own floors, which is why
// this looks for one in the test as well only when the test builds its corpus
// directly. The rule is the same either way: a number, compared, with a failure
// on the wrong side of it.
func TestGateLiveness_EveryCorpusScanAssertsItsCorpusIsNonEmpty(t *testing.T) {
	for _, fn := range complianceTestFunctions(t) {
		if len(fn.corpusBuilders) == 0 {
			continue
		}
		if _, exempt := corpusFloorExemptions[fn.name]; exempt {
			if fn.hasCorpusFloor {
				t.Errorf("%s is in corpusFloorExemptions and now asserts a floor. Delete the entry: "+
					"the list may only shrink.", fn.name)
			}
			continue
		}
		if !fn.hasCorpusFloor {
			sort.Strings(fn.corpusBuilders)
			t.Errorf("%s (%s) builds a corpus from %v and never asserts it is non-empty. If the "+
				"walk finds nothing — a moved directory, a renamed suffix, an error swallowed by "+
				"the callback — the loop body never runs and the test passes. Assert a floor and "+
				"fail below it, the way productionGoFiles does.", fn.name, fn.file, fn.corpusBuilders)
		}
	}
}

// corpusFloorExemptions are the tests whose corpus comes from a helper that
// already asserts its own floor, and which add nothing by repeating it. Each
// entry is a hole in the gate above, so the list is short and is a ratchet.
var corpusFloorExemptions = map[string]struct{}{
	// This one iterates productionGoFiles, which already fails below 100 files,
	// and its assertion is that a construct is absent. It records which case it
	// observed instead of counting, which is the same guarantee written the
	// other way round.
	"TestASVS_V12_3_2_NoInsecureSkipVerifyInProductionCode": {},
}

// --- 3. A tripwire over one file of a numbered family cannot see the rest ---

var (
	// migrationFile matches a migration named as a whole string, in either of
	// the two shapes the suites use: "migrations/013_session_lifetime.sql" for a
	// repo-relative read, and "013_session_lifetime.sql" for the last argument of
	// a filepath.Join. Matching the value rather than the call means a tripwire
	// is seen however it opens the file — the previous form pinned the literal
	// call shape readProductionSource(t, "migrations/…"), so a gate that read a
	// migration any other way was invisible, which is the same class of defect
	// this file exists for.
	migrationFile   = regexp.MustCompile(`^(?:migrations/)?(\d{3}_[A-Za-z0-9_]+\.sql)$`)
	tripwirePhrases = []string{"now exists", "now has", "has since", "no longer absent", "is closed"}
	// migrationDirReaders are the calls that take a whole directory. A test that
	// makes one against migrations/ already sees every file, so naming one of
	// them as well is a detail of the message, not a narrowed corpus.
	migrationDirReaders = map[string]struct{}{
		"ReadDir": {}, "WalkDir": {}, "Walk": {}, "Glob": {},
	}
)

// TestGateLiveness_NoTripwireWatchesOnlyOneMigration is the shape of the bug
// that started this file.
//
// A test that fails when a column appears has to look everywhere that column
// could appear. migrations/ is a numbered family: 001 creates the schema and
// every later file alters it, so reading 001 alone and concluding a column does
// not exist is a conclusion about 2023, not about the database.
func TestGateLiveness_NoTripwireWatchesOnlyOneMigration(t *testing.T) {
	root := repoRoot(t)

	migrations, err := os.ReadDir(filepath.Join(root, "migrations"))
	if err != nil {
		t.Fatalf("read migrations/: %v", err)
	}
	sqlFiles := 0
	for _, m := range migrations {
		if strings.HasSuffix(m.Name(), ".sql") {
			sqlFiles++
		}
	}
	if sqlFiles < 2 {
		t.Fatalf("only %d migration files found; this gate has no family to reason about and would "+
			"pass vacuously", sqlFiles)
	}

	for _, fn := range complianceTestFunctions(t) {
		if len(fn.namedMigrations) == 0 || fn.readsMigrationDir {
			continue
		}

		tripwire := ""
		lowered := strings.ToLower(fn.source)
		for _, phrase := range tripwirePhrases {
			if strings.Contains(lowered, phrase) {
				tripwire = phrase
				break
			}
		}
		if tripwire == "" {
			continue // reading one migration to assert what it does contain is fine
		}

		named := map[string]struct{}{}
		for _, m := range fn.namedMigrations {
			named[m] = struct{}{}
		}
		if len(named) < sqlFiles {
			missing := sqlFiles - len(named)
			t.Errorf("%s (%s) fails on %q — it is a tripwire — but reads only %d of the %d files in "+
				"migrations/. %d later migration(s) can introduce exactly the thing it is watching "+
				"for and it will never see them. This is the bug that made "+
				"TestASVS_V10_4_8_PerTokenExpiryExistsAndFamilyAgeIsStillUnrecorded incapable of "+
				"failing: it read 001_initial_schema.sql for a column that landed in "+
				"013_session_lifetime.sql. Read the whole directory.",
				fn.name, fn.file, tripwire, len(named), sqlFiles, missing)
		}
	}
}

// --- 4. One test cannot be the sole evidence for a dozen requirements -------
//
// This check does not read gateCorpora, and cannot: its corpus is the register's
// Met rows, and it counts how many of them name one test. A test in tests/spec
// or tests/attack that no row cites is not evidence for anything, so there is no
// number to compare. The widening that applies to checks 1 to 3 does not apply
// here — the corpus is the document, not the suite.

// umbrellaTestCeiling is the number of Met rows one test may be the *only*
// named evidence for before the register is asked to say more.
//
// The number is not a law of nature; it is a threshold above which a reader
// should stop believing the row and start reading the test. Fifty-two Met rows
// currently rest on five tests, which is how a suite comes to look thorough
// while a dozen requirements share one assertion.
const umbrellaTestCeiling = 6

func TestGateLiveness_NoSingleTestIsTheSoleEvidenceForTooManyRequirements(t *testing.T) {
	reg := loadRegister(t)

	soleEvidence := map[string][]string{}
	for _, r := range reg.Requirements {
		if r.Status != statusMet || len(r.Tests) != 1 {
			continue
		}
		soleEvidence[r.Tests[0]] = append(soleEvidence[r.Tests[0]], r.Standard+" "+r.RequirementID)
	}

	names := make([]string, 0, len(soleEvidence))
	for name := range soleEvidence {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		rows := soleEvidence[name]
		if len(rows) <= umbrellaTestCeiling {
			continue
		}
		if allowed, exempt := umbrellaTestBaseline[name]; exempt {
			if len(rows) > allowed {
				t.Errorf("%s is the sole evidence for %d Met requirements, up from the %d recorded "+
					"when this baseline was frozen. An umbrella test may not grow: give the new rows "+
					"a test that asserts what they specifically require. Rows: %v",
					name, len(rows), allowed, rows)
			}
			continue
		}
		t.Errorf("%s is the sole named evidence for %d Met requirements, above the ceiling of %d. "+
			"One assertion cannot prove a dozen different things; a reader following any of these "+
			"rows lands on a test that was written for one of them. Rows: %v",
			name, len(rows), umbrellaTestCeiling, rows)
	}

	total := 0
	for _, rows := range soleEvidence {
		if len(rows) > umbrellaTestCeiling {
			total += len(rows)
		}
	}
	t.Logf("%d Met rows have a single named test; %d of those rest on an umbrella test above the ceiling of %d",
		len(soleEvidence), total, umbrellaTestCeiling)
}

// umbrellaTestBaseline freezes the umbrella tests that already exist, at the
// count they already carry.
//
// Forty-six Met rows currently rest on four tests. That is not the same defect
// as a test that cannot fail — each of these four asserts something real, and
// each would go red if its property broke — but it is the same *shape*: a
// reader following any one of those rows lands on a test that was written for
// a different one, and the register's promise that a Met row names a test which
// proves it is weaker than it reads.
//
// Splitting them is work on the suite rather than on the register, and doing it
// in the same change that discovered the problem is how a register acquires
// errors instead of losing them. So they are frozen at their current counts.
// The list is a ratchet: a frozen umbrella may not grow by one row, and a new
// one is not permitted at all, so the number can only come down.
var umbrellaTestBaseline = map[string]int{
	// 17 rows. A taint-and-validation scan over the input path, standing in for
	// every encoding, canonicalisation and validation requirement in V1 and V2.
	"TestNIST80053_SI_10_InputIsValidatedBeforeUse": 17,
	// 13 rows. A route-table property, standing in for every requirement that
	// says a particular route must be authenticated.
	"TestOWASP_A01_2025_EveryNonPublicRouteIsAuthenticated": 13,
	// 8 rows each. Configuration defaults and rate limiting.
	"TestOWASP_A02_2025_ProductionProfileRefusesInsecureDefaults": 8,
	"TestOWASP_A06_2025_CredentialEndpointsRateLimitFailClosed":   8,
}

// --- shared: parse the package's own test functions -------------------------

type complianceTestFn struct {
	name              string
	file              string // repo-relative, slash-separated
	corpus            string // the gateCorpora entry it came from
	source            string
	failureCalls      int
	corpusBuilders    []string
	hasCorpusFloor    bool
	hasSubtests       bool
	namedMigrations   []string
	readsMigrationDir bool
}

// gateCorpora are the suites the three structural checks above read.
//
// This file started at tests/compliance and nothing else, which is why it saw
// none of the eleven dead gates a later mutation sweep found in tests/spec: the
// corpus was the one directory already known to be clean. A gate that reads only
// where it was written is the same defect one level up.
//
// tests/spec and tests/attack are the other two suites written as structural
// property gates — they read the source tree, build a corpus out of it and
// assert over it, which is the shape all three checks are about.
//
// internal/ and cmd/ are deliberately excluded. Their tests exercise behavior by
// calling the code, so "builds a corpus from a directory walk and never asserts
// it found anything" is not a shape they take, and check 1 would report every
// test whose assertions live in a helper it calls. The claim those packages
// need is a different one, and internal/middleware/log_privacy_test.go is where
// it is made.
var gateCorpora = []string{
	filepath.Join("tests", "compliance"),
	filepath.Join("tests", "spec"),
	filepath.Join("tests", "attack"),
}

func complianceTestFunctions(t *testing.T) []complianceTestFn {
	t.Helper()
	root := repoRoot(t)

	var out []complianceTestFn
	for _, corpus := range gateCorpora {
		dir := filepath.Join(root, corpus)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", corpus, err)
		}

		// Two passes: the suite's own integer constants first, because a floor
		// written against one is only recognizable as a floor once they are known.
		type parsedTestFile struct {
			name   string
			fset   *token.FileSet
			file   *ast.File
			source []byte
		}
		var suite []parsedTestFile
		var asts []*ast.File
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", entry.Name(), err)
			}
			fset := token.NewFileSet()
			parsed, err := parser.ParseFile(fset, path, raw, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", entry.Name(), err)
			}
			suite = append(suite, parsedTestFile{name: entry.Name(), fset: fset, file: parsed, source: raw})
			asts = append(asts, parsed)
		}
		intConsts, strConsts := suiteConsts(asts)

		before := len(out)
		for _, pf := range suite {
			fset, parsed, raw := pf.fset, pf.file, pf.source
			rel := filepath.ToSlash(filepath.Join(corpus, pf.name))
			lines := strings.Split(string(raw), "\n")
			for _, decl := range parsed.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Body == nil {
					continue
				}
				start := fset.Position(fn.Pos()).Line
				end := fset.Position(fn.End()).Line
				body := strings.Join(lines[start-1:min(end, len(lines))], "\n")

				info := complianceTestFn{name: fn.Name.Name, file: rel, corpus: corpus, source: body}
				builders := map[string]struct{}{}

				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					name := callName(call)
					if _, isFailure := failureCalls[name]; isFailure {
						info.failureCalls++
					}
					if name == "Run" {
						info.hasSubtests = true
					}
					if _, isBuilder := corpusBuilders[name]; isBuilder {
						builders[name] = struct{}{}
					}
					if q := selectorName(call.Fun); q != "" {
						if _, isBuilder := corpusBuilders[q]; isBuilder {
							builders[q] = struct{}{}
						}
					}
					return true
				})

				for b := range builders {
					info.corpusBuilders = append(info.corpusBuilders, b)
				}
				info.hasCorpusFloor = hasCorpusFloor(fn, intConsts)
				info.namedMigrations, info.readsMigrationDir = migrationReads(fn, strConsts)
				out = append(out, info)
			}
		}

		// Per corpus, not only in total. A suite that silently contributes
		// nothing — a renamed directory, a changed suffix — would leave the
		// other two holding the floor up while this one goes unchecked, which is
		// the vacuous-corpus failure this file exists to detect.
		if got := len(out) - before; got < 20 {
			t.Fatalf("only %d test functions parsed from %s; this gate's own corpus is broken over "+
				"that suite, which would make every assertion in this file vacuous for it — "+
				"precisely the failure it exists to detect", got, corpus)
		}
	}

	if len(out) < 250 {
		t.Fatalf("only %d test functions parsed across %v; this gate's own corpus is broken, which "+
			"would make every assertion in this file vacuous — precisely the failure it exists to "+
			"detect", len(out), gateCorpora)
	}
	return out
}

// --- 5. A comment naming a test is a claim about the tree -------------------

// commentTestName matches a Go test, fuzz or benchmark identifier where it
// appears inside a comment. Fuzz and Benchmark are included because the
// fuzz-a-local-dummy defect was found by reading a comment that named a target,
// and a target is as easy to rename out from under a sentence as a test is.
var commentTestName = regexp.MustCompile(`\b((?:Test|Fuzz|Benchmark)[A-Z][A-Za-z0-9_]*)\b`)

// commentTestNameExemptions are the Test-shaped identifiers in Go comments that
// are deliberately not the name of a function that exists, each with the reason.
//
// Every entry is a hole in the gate below, so each has to earn its place, and
// TestGateLiveness_NoStaleCommentTestNameExemption deletes it again as soon as
// the name it names comes into existence. The shape is the one
// tests/spec/ratelimit_failclosed_test.go uses for failOpenByDesign: an
// exemption with no written reason is indistinguishable from an oversight.
var commentTestNameExemptions = map[string]string{
	"FuzzEmailValidation": "the target this repository deleted, named by the comment on " +
		"tests/spec/fuzz_targets_test.go's workflow gate and by the one on tests/fuzz/" +
		"fuzz_sanitize_email_test.go that replaced it. Both sentences exist to say the name is " +
		"gone: it fuzzed an isValidEmail defined in the same file, and ci.yml went on naming it " +
		"in a -fuzz= flag that then matched nothing and exited 0",
	"TestASVS_V10_4_8_PerTokenExpiryExistsAndFamilyAgeIsStillUnrecorded": "the historical dead " +
		"gate this file was written about, named in the header so a reader can look it up. It was " +
		"rewritten under a different name; naming the old one is the point",
	"TestCLI_CleanupAudit": "retired along with the CLI subcommand it drove. " +
		"cli_ops_test.go names it to say where the contract went",
	"TestK8sPSS_Restricted_TheExcludedWorkloadsAreStillExcluded": "retired the day it fired. " +
		"register_gates_test.go names it in the comment explaining why that gate reads the " +
		"register's prose as well as its tests[] arrays, so naming it is the point",
	"TestSSDF_800_218_DependencyUpdateAutomationIsAbsent": "retired the day it fired, and named " +
		"in the same comment for the same reason as its sibling above",
	"TestComplianceRegister": "a `go test -run` regular expression, not a function: it matches " +
		"every TestComplianceRegister_* gate in tests/compliance",
	"TestNIST63B4_2_2_3_TheAbsoluteBoundIsStillUnwired": "a name that has never existed, quoted " +
		"in register_gates_test.go as the example of the defect that gate closes",
	"TestNIST80053_IA_11_": "an elided reference — the comment writes " +
		"`TestNIST80053_IA_11_...` because the point is the family, not one member of it",
	"TestParseJWKHeaderValidECP384": "deleted, because it pinned as a contract a branch that " +
		"cannot produce an accepted proof. Its replacement's doc comment names it to say what was " +
		"removed and why",
	"TestWithPerm": "removed during review, and adminapi_v076_test.go records the removal and " +
		"the reason. A note saying a test was deleted is the one comment that must name a test " +
		"which does not exist",
}

// TestGateLiveness_EveryTestNamedInAGoCommentExists fails when a comment names
// a test function that is nowhere in the tree.
//
// internal/middleware/ratelimit.go argued that its namespace() fallback was safe
// because "the production limiters are named and TestRateLimitersAreNamespaced
// asserts it". No such test had ever been written. A whole-tree grep returned
// one hit: the sentence making the claim.
//
// That is worse than an absent gate, because it is an absent gate with a
// citation. The next reader sees "asserts it" and stops looking, which is the
// same mechanism that let a CI job pipe go test into tee without pipefail for
// eleven months — the control was documented, so nobody checked it.
//
// docs/COMPLIANCE.md already gets this check, from
// TestComplianceDocs_EveryTestNamedInProseExists. This is its Go-source half:
// the same claim, in the place a maintainer is most likely to believe it.
func TestGateLiveness_EveryTestNamedInAGoCommentExists(t *testing.T) {
	defined, mentions := goCommentTestNames(t)

	for _, mention := range mentions {
		m := mention.resolve(defined)
		if _, exists := defined[m]; exists {
			continue
		}
		if _, exempt := commentTestNameExemptions[m]; exempt {
			continue
		}
		t.Errorf("%s:%d names %s, and no func %s( exists anywhere in the tree. A comment that "+
			"says a test asserts something is a claim, and this repository has shipped one that "+
			"was false: internal/middleware/ratelimit.go cited TestRateLimitersAreNamespaced as "+
			"the reason its key fallback was safe, and the only hit for that name was the comment "+
			"itself. Either write the test, rename the reference, or add %q to "+
			"commentTestNameExemptions with the reason it names something that does not exist.",
			mention.file, mention.line, m, m, m)
	}
}

// TestGateLiveness_NoStaleCommentTestNameExemption keeps the list above from
// outliving the holes it describes.
//
// An exemption naming a test that now exists is a standing permission nobody
// has to justify any more, and it hides the next one: a real test renamed onto
// an exempt name would inherit an amnesty written for a deleted one. The list
// is a ratchet, so it may only shrink.
func TestGateLiveness_NoStaleCommentTestNameExemption(t *testing.T) {
	defined, mentions := goCommentTestNames(t)

	mentioned := map[string]struct{}{}
	for _, m := range mentions {
		mentioned[m.resolve(defined)] = struct{}{}
	}

	for name, reason := range commentTestNameExemptions {
		if reason == "" {
			t.Errorf("commentTestNameExemptions[%q] carries no reason. An exemption without one "+
				"is indistinguishable from an oversight.", name)
		}
		if _, exists := defined[name]; exists {
			t.Errorf("commentTestNameExemptions names %q, which now exists as a function. Delete "+
				"the entry: the exemption was written for a name that was absent, and leaving it "+
				"would let a future rename onto that name inherit it.", name)
		}
		if _, still := mentioned[name]; !still {
			t.Errorf("commentTestNameExemptions names %q, which no Go comment mentions any more. "+
				"Delete the entry: the list may only shrink.", name)
		}
	}
}

// commentMention is one Test-shaped identifier read out of a Go comment.
//
// joined is the same identifier with the first word of the following comment
// line appended, set only when the match ended a line and so may have been
// split by a wrap. Which of the two the comment meant is decided against the
// set of declared functions, not by guessing from the text.
type commentMention struct {
	name   string
	joined string
	file   string // repo-relative, slash-separated
	line   int
}

// resolve returns the identifier the comment meant: the rejoined one when a
// wrap split it and the join names a real function, and the bare match
// otherwise.
func (m commentMention) resolve(defined map[string]struct{}) string {
	if m.joined != "" {
		if _, ok := defined[m.joined]; ok {
			return m.joined
		}
	}
	return m.name
}

// goCommentTestNames returns every function declared anywhere in the tree and
// every Test-shaped identifier named in a Go comment.
//
// It reads production files as well as test files, because the claim this gate
// exists for was made in production source: the comment on namespace() in
// internal/middleware/ratelimit.go.
func goCommentTestNames(t *testing.T) (map[string]struct{}, []commentMention) {
	t.Helper()
	root := repoRoot(t)

	defined := map[string]struct{}{}
	var mentions []commentMention
	var files int

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "tmp", "dist", "build":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		parsed, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			// A file that does not compile is a different gate's problem, so it
			// contributes nothing rather than failing the walk. Returning the
			// error would make every gate in this file red whenever any file in
			// the tree is mid-edit, which trains people to ignore them.
			return nil //nolint:nilerr // an unparseable file is another gate's failure, not this one's
		}
		files++

		for _, decl := range parsed.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				defined[fn.Name.Name] = struct{}{}
			}
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		for _, group := range parsed.Comments {
			for _, m := range mentionsInCommentGroup(group, fset) {
				m.file = rel
				mentions = append(mentions, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	// Both floors are the gate's own anti-vacuity check. A walk that finds no
	// files, or a comment reader that extracts no names, would make every
	// assertion above pass without looking at anything.
	if files < 500 {
		t.Fatalf("only %d Go files parsed under %s; the walk is broken and both gates above would "+
			"pass vacuously", files, root)
	}
	if len(defined) < 200 {
		t.Fatalf("only %d functions found across %d Go files; the declaration scan is broken",
			len(defined), files)
	}
	if len(mentions) < 50 {
		t.Fatalf("only %d Test-shaped identifiers found in Go comments across %d files; the "+
			"comment reader is broken, which is how this gate would come to pass over a false "+
			"claim", len(mentions), files)
	}
	return defined, mentions
}

// mentionsInCommentGroup reads the Test-shaped identifiers out of one comment
// group, rejoining the ones a line wrap split in two.
//
// A long test name is exactly the thing a fill-paragraph breaks across lines,
// leaving one line ending in "...HorizonMatchesThe" and the next beginning
// "Oracle below asks Postgres instead". Reading those halves separately reports
// a name nobody wrote. So a match that ends a line is re-tried with the first
// word of the next line appended, and the join wins when it names a real
// function.
func mentionsInCommentGroup(group *ast.CommentGroup, fset *token.FileSet) []commentMention {
	type commentLine struct {
		text string
		line int
	}
	var lines []commentLine
	for _, c := range group.List {
		start := fset.Position(c.Pos()).Line
		if strings.HasPrefix(c.Text, "//") {
			lines = append(lines, commentLine{text: c.Text[2:], line: start})
			continue
		}
		body := strings.TrimSuffix(strings.TrimPrefix(c.Text, "/*"), "*/")
		for i, raw := range strings.Split(body, "\n") {
			lines = append(lines, commentLine{
				text: strings.TrimPrefix(strings.TrimSpace(raw), "*"),
				line: start + i,
			})
		}
	}

	var out []commentMention
	for i, cl := range lines {
		for _, loc := range commentTestName.FindAllStringIndex(cl.text, -1) {
			name := cl.text[loc[0]:loc[1]]
			m := commentMention{name: name, line: cl.line}
			if loc[1] == len(cl.text) && i+1 < len(lines) {
				if head := leadingWord(lines[i+1].text); head != "" {
					m.joined = name + head
				}
			}
			out = append(out, m)
		}
	}
	return out
}

// leadingWord returns the identifier characters a comment line starts with,
// after the single space that follows the marker, and "" when the line does not
// start with one. It is how a wrapped identifier is put back together.
func leadingWord(text string) string {
	text = strings.TrimPrefix(text, " ")
	end := 0
	for end < len(text) {
		c := text[end]
		if c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			end++
			continue
		}
		break
	}
	return text[:end]
}

// hasCorpusFloor reports whether a function compares a len() against a numeric
// literal, which is the shape of "the scan found nothing and that is a bug".
//
// intConsts are the package-level integer constants of the suite the function
// came from. A floor written against a named constant — `if checked <
// chartWorkloadTemplates` — is the same guard as one written against 8, and is
// the better version of it, because the number then has a name and a doc
// comment. Reading only literals reported that shape as an absent floor.
func hasCorpusFloor(fn *ast.FuncDecl, intConsts map[string]struct{}) bool {
	isNumber := func(e ast.Expr) bool {
		if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.INT {
			return true
		}
		if ident, ok := e.(*ast.Ident); ok {
			_, named := intConsts[ident.Name]
			return named
		}
		return false
	}

	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		if bin.Op != token.LSS && bin.Op != token.LEQ && bin.Op != token.EQL &&
			bin.Op != token.GTR && bin.Op != token.GEQ && bin.Op != token.NEQ {
			return true
		}
		lenSide := func(e ast.Expr) bool {
			call, ok := e.(*ast.CallExpr)
			if !ok {
				return false
			}
			ident, ok := call.Fun.(*ast.Ident)
			return ok && ident.Name == "len"
		}
		numSide := func(e ast.Expr) bool {
			if isNumber(e) {
				return true
			}
			ident, isIdent := e.(*ast.Ident)
			return isIdent && (ident.Name == "sqlFiles" || ident.Name == "scanned")
		}
		if (lenSide(bin.X) && numSide(bin.Y)) || (numSide(bin.X) && lenSide(bin.Y)) {
			found = true
		}
		// A counter compared against a number is the same guard written the
		// other way: `if scanned < 10 { t.Fatalf(...) }`.
		if id, ok := bin.X.(*ast.Ident); ok {
			if isNumber(bin.Y) &&
				(strings.Contains(strings.ToLower(id.Name), "count") ||
					strings.Contains(strings.ToLower(id.Name), "scanned") ||
					strings.Contains(strings.ToLower(id.Name), "checked") ||
					strings.Contains(strings.ToLower(id.Name), "sites") ||
					strings.Contains(strings.ToLower(id.Name), "named") ||
					strings.Contains(strings.ToLower(id.Name), "files") ||
					strings.Contains(strings.ToLower(id.Name), "strict") ||
					strings.Contains(strings.ToLower(id.Name), "total")) {
				found = true
			}
		}
		return true
	})
	return found
}

// suiteConsts collects the package-level constants a suite declares with a
// literal value: the integers, so a floor written against one is recognized as a
// floor, and the strings, so a migration opened through a named constant is
// recognized as a migration.
func suiteConsts(files []*ast.File) (ints map[string]struct{}, strs map[string]string) {
	ints, strs = map[string]struct{}{}, map[string]string{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok {
						continue
					}
					// token.Token has ninety-odd members and this walk cares
					// about two of them, so the default is the whole point
					// rather than an oversight.
					switch lit.Kind { //nolint:exhaustive // only INT and STRING constants can be a floor or a corpus root
					case token.INT:
						ints[name.Name] = struct{}{}
					case token.STRING:
						if v, err := strconv.Unquote(lit.Value); err == nil {
							strs[name.Name] = v
						}
					}
				}
			}
		}
	}
	return ints, strs
}

// migrationReads reports which migration files a test names, and whether it
// reads the whole migrations directory instead.
//
// It matches the value, not the call: a migration is recognized whether it
// arrives as "migrations/013_session_lifetime.sql", as the last argument of a
// filepath.Join, or through a package-level string constant. A directory read
// short-circuits the whole question, because a test that walks migrations/
// already sees every file that could introduce what it is watching for.
func migrationReads(fn *ast.FuncDecl, strConsts map[string]string) ([]string, bool) {
	named := map[string]struct{}{}
	wholeDir := false

	add := func(v string) {
		if m := migrationFile.FindStringSubmatch(v); m != nil {
			named[m[1]] = struct{}{}
		}
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				if v, err := strconv.Unquote(node.Value); err == nil {
					add(v)
				}
			}
		case *ast.Ident:
			if v, ok := strConsts[node.Name]; ok {
				add(v)
			}
		case *ast.CallExpr:
			if _, isDirRead := migrationDirReaders[callName(node)]; !isDirRead {
				return true
			}
			ast.Inspect(node, func(inner ast.Node) bool {
				lit, ok := inner.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if v, err := strconv.Unquote(lit.Value); err == nil && strings.Contains(v, "migrations") {
					wholeDir = true
				}
				return true
			})
		}
		return true
	})

	out := make([]string, 0, len(named))
	for m := range named {
		out = append(out, m)
	}
	sort.Strings(out)
	return out, wholeDir
}

// --- 6. A skipped test reports success --------------------------------------
//
// A skip and a pass print the same color. `go test` reports `ok` for a package
// whose every assertion skipped, so a gate that retires itself at runtime is
// strictly worse than one that was deleted: the deleted one is missing from the
// report and this one is not.
//
// This is not hypothetical here. Seven chart assertions in tests/spec skipped
// for an entire release because no CI job installed helm, and it was found by
// somebody counting [no tests to run] lines rather than by anything going red.
// The two shapes that produce it:
//
//   - a precondition the environment may not meet (a tool, a container runtime,
//     a fetched tag), which is legitimate locally and must never be legitimate
//     on a runner; and
//   - a structural gate that skips when its needle moves, which retires the
//     control at exactly the moment the code it guards was restructured.
//
// The second shape has no legitimate instance: if a gate can no longer find
// what it watches, the claim it evidences is unevidenced, and that is a
// failure. The rule below is therefore that every skip is registered with an
// argument, and the registry is a ratchet in both directions.

// skipCalls are the ways a Go test retires itself at runtime.
var skipCalls = map[string]struct{}{"Skip": {}, "Skipf": {}, "SkipNow": {}}

// skipRule is one registered skip.
type skipRule struct {
	// reason is why this skip is not the silent-retirement defect. An entry
	// without one is indistinguishable from an oversight and fails.
	reason string
	// ciStrictPredicate, when set, names the function whose result decides that
	// the same condition is fatal rather than skippable on a CI runner. The
	// entry then has to prove it: the enclosing function must call that
	// predicate and must contain a failure call, so "impossible in CI" is a
	// property of the code and not of this comment.
	ciStrictPredicate string
}

// skipsByDesign registers every skip in the gate corpora, keyed by
// "<repo-relative file>:<enclosing function>".
//
// Keyed by function rather than by line so that editing the file above a skip
// does not turn an argument stale, and by file as well as name because the
// three suites are separate packages that may reuse a helper name.
//
// Every entry is a hole in the check below, exactly as with failOpenByDesign in
// tests/spec/ratelimit_failclosed_test.go and assertionFreeByDesign above, and
// TestGateLiveness_NoStaleSkipExemption removes an entry the moment its skip
// stops existing. The list may only shrink.
var skipsByDesign = map[string]skipRule{
	"tests/spec/citool_test.go:requireTool": {
		reason: "the one place this suite resolves an external renderer. Locally a missing helm " +
			"skips, so `go test ./...` stays runnable without a Kubernetes toolchain; on a runner " +
			"it is fatal, because the job exists to run the gate and a skip there is the defect " +
			"this whole check is about",
		ciStrictPredicate: "runningInCI",
	},
	"tests/spec/chart_immutable_selector_test.go:lastReleaseTag": {
		reason: "the previously released chart is rendered from the last reachable tag, and a " +
			"clone with no tags cannot produce one. NOT ci-strict, and that is a known gap rather " +
			"than an argument: ci.yml's Tests job checks out at the default depth, which fetches " +
			"no tags, so this gate does not run on a pull request. Making it fatal would turn a " +
			"silent skip into a red CI on work that did not cause it; the fix is fetch-depth: 0 " +
			"on that checkout, which is a workflow change with its own owner",
	},
	"tests/attack/atk_crypto_argon2_pressure_test.go:TestArgon2Attack_MeasureQueueingUnderFlood": {
		reason: "a latency measurement. Under -race every duration is instrumentation, and -short " +
			"exists to skip exactly this; both conditions are the runner's own declaration that " +
			"wall-clock numbers are meaningless in it",
	},
	"tests/attack/atk_crypto_argon2_pressure_test.go:TestArgon2Attack_MeasureUserExistsTimingGap": {
		reason: "a timing measurement, skipped under -race and -short for the same reason. It " +
			"carries a 5% threshold that has been observed to flake at 6.29% on a loaded runner, " +
			"which is why it may not run where the timings are not trustworthy",
	},
	"tests/attack/atk_crypto_dpop_totp_test.go:TestTOTPAttack_MeasureValidationTimingGap": {
		reason: "a timing measurement, meaningless under -race and skipped in -short",
	},
	"tests/attack/atk_crypto_dpop_totp_test.go:TestTOTPAttack_MeasureLengthMismatchTiming": {
		reason: "a timing measurement, meaningless under -race and skipped in -short. Also in " +
			"assertionFreeByDesign, with the argument for why it asserts nothing",
	},
	"tests/attack/totp_replay_test.go:TestTOTPWrongCode": {
		reason: "the wrong-code path is driven with random six-digit codes, and roughly one in a " +
			"million is the right one. Skipping the coincidence is correct: asserting a rejection " +
			"on a code that is genuinely valid would be asserting the wrong behavior",
	},
}

// skipSite is one Skip call found in the gate corpora.
type skipSite struct {
	key      string // "<repo-relative file>:<enclosing function>"
	file     string
	fn       string
	line     int
	fails    bool                // the enclosing function can also fail
	idents   map[string]struct{} // every identifier the enclosing function names
	inCorpus string
}

// TestGateLiveness_NoGateRetiresItselfWithAnUnregisteredSkip is the check the
// helm outage would have failed. A skip with no entry here is a control that
// switched itself off, and `go test` said `ok`.
func TestGateLiveness_NoGateRetiresItselfWithAnUnregisteredSkip(t *testing.T) {
	for _, site := range skipSites(t) {
		rule, registered := skipsByDesign[site.key]
		if !registered {
			t.Errorf("%s:%d in %s skips, and no entry in skipsByDesign says why. A skipped test "+
				"prints the same `ok` as one that ran, so this control is off and the report says "+
				"it is on. Either fail instead of skipping — which is the right answer whenever a "+
				"structural gate can no longer find what it watches — or add %q to skipsByDesign "+
				"with the argument for why the skip is not a silent retirement.",
				site.file, site.line, site.fn, site.key)
			continue
		}
		if strings.TrimSpace(rule.reason) == "" {
			t.Errorf("skipsByDesign[%q] carries no reason. An exemption without one is "+
				"indistinguishable from an oversight.", site.key)
		}
		if rule.ciStrictPredicate == "" {
			continue
		}
		// "Impossible in CI" is a claim about the code, so the code has to
		// carry it: the same function must consult the predicate and must have
		// a way to fail. Deleting either half is what turns a CI-mandatory
		// tool back into a silent local convenience everywhere.
		if _, consults := site.idents[rule.ciStrictPredicate]; !consults {
			t.Errorf("skipsByDesign[%q] claims the skip is impossible in CI via %s, but %s never "+
				"calls it. The exemption rests on a predicate the code does not consult.",
				site.key, rule.ciStrictPredicate, site.fn)
		}
		if !site.fails {
			t.Errorf("skipsByDesign[%q] claims the skip is impossible in CI, but %s contains no "+
				"t.Fatal, t.Error or t.Fail of any kind, so there is no branch in which the "+
				"missing precondition is a failure. On a runner it would skip exactly as it does "+
				"locally.", site.key, site.fn)
		}
	}
}

// TestGateLiveness_NoStaleSkipExemption deletes an entry whose skip is gone, so
// an argument written for one skip cannot be inherited by the next one to take
// the name. It is also this file's floor: a scan that walked nothing reports
// every entry as stale rather than reporting nothing at all.
func TestGateLiveness_NoStaleSkipExemption(t *testing.T) {
	present := map[string]struct{}{}
	for _, site := range skipSites(t) {
		present[site.key] = struct{}{}
	}
	for key, rule := range skipsByDesign {
		if _, ok := present[key]; !ok {
			t.Errorf("skipsByDesign names %q, which no longer skips. Remove the entry: the list "+
				"may only shrink, and an argument left behind is one a future skip inherits "+
				"without making it. (Reason on file: %s)", key, rule.reason)
		}
	}
}

// skipSites walks the gate corpora and returns every Skip call in them, with
// the enclosing top-level function rather than the closure, so a skip inside a
// t.Run body is attributed to the test that owns it.
func skipSites(t *testing.T) []skipSite {
	t.Helper()
	root := repoRoot(t)

	var out []skipSite
	var files int
	for _, corpus := range gateCorpora {
		dir := filepath.Join(root, corpus)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", corpus, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			files++
			path := filepath.Join(dir, entry.Name())
			fset := token.NewFileSet()
			parsed, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", entry.Name(), err)
			}
			rel := filepath.ToSlash(filepath.Join(corpus, entry.Name()))

			for _, decl := range parsed.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				var skips []int
				fails := false
				idents := map[string]struct{}{}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					switch node := n.(type) {
					case *ast.Ident:
						idents[node.Name] = struct{}{}
					case *ast.CallExpr:
						name := callName(node)
						if _, isSkip := skipCalls[name]; isSkip {
							skips = append(skips, fset.Position(node.Pos()).Line)
						}
						if _, isFailure := failureCalls[name]; isFailure {
							fails = true
						}
					}
					return true
				})
				for _, line := range skips {
					out = append(out, skipSite{
						key:      rel + ":" + fn.Name.Name,
						file:     rel,
						fn:       fn.Name.Name,
						line:     line,
						fails:    fails,
						idents:   idents,
						inCorpus: corpus,
					})
				}
			}
		}
	}

	// The corpora are three whole suites. A walk that came back with a handful
	// of files did not find them, and every check above would then be vacuous
	// in precisely the way this file exists to detect.
	if files < 100 {
		t.Fatalf("only %d test files walked across %v; this gate's own corpus is broken, so every "+
			"skip in the tree would read as absent", files, gateCorpora)
	}
	return out
}

// --- 7. A comment satisfies a substring assertion ---------------------------
//
// tests/spec asserts most of its properties by reading a production file and
// asking whether a construct is in it. Read raw, "is it in the file" is answered
// yes by a sentence describing the construct, by a commented-out draft of it,
// and by the note explaining why it was taken out. The gate then certifies a
// claim the code does not make.
//
// The canonical instance is one level up from here: a comment on namespace() in
// internal/middleware/ratelimit.go argued the fallback was safe because
// TestRateLimitersAreNamespaced asserted it, and for weeks the only occurrence
// of that name in the tree was the sentence making the claim. Check 5 above
// catches that one. This catches the same shape in a chart template, a
// Dockerfile, a migration and a Go file: the line in the template that explains
// what the template no longer does still contains the words the gate looks for.
//
// tests/spec resolves it with commentFreeSource, which blanks comments and
// preserves byte offsets. The rule here is that a text scan may not run on a
// read that did not go through it.
//
// Scope: tests/spec only, and deliberately so rather than by oversight.
// tests/compliance reads production source through readProductionSource in over
// a hundred places and has the same exposure; converting it is its own piece of
// work with its own findings, and is recorded as such rather than half-done
// here.

// textScanners are the calls that answer "does this text contain that" — the
// question a comment answers wrongly.
var textScanners = map[string]struct{}{
	"Contains": {}, "Index": {}, "LastIndex": {}, "Count": {}, "Split": {}, "SplitN": {},
	"containsIdentifier": {},
}

// rawSourceReaders return production source with its comments intact.
var rawSourceReaders = map[string]struct{}{"readFileString": {}, "ReadFile": {}}

// sourceSanitizers return source a text scan may be run on.
var sourceSanitizers = map[string]struct{}{
	"commentFreeSource": {}, "blankComments": {}, "withoutComments": {}, "stripSQLComments": {},
}

// rawSourceScanByDesign are the text scans allowed to run on an unsanitized
// read, keyed by "<repo-relative file>:<enclosing function>", each with why.
//
// Empty on purpose: every one of the 22 found when this check was written was
// fixed rather than exempted. The map and its ratchet exist so that the next one
// has to be argued for in writing instead of merged in silence.
var rawSourceScanByDesign = map[string]string{}

func TestGateLiveness_NoSpecGateScansProductionSourceWithItsCommentsIntact(t *testing.T) {
	scans, sanitized := rawSourceScans(t)

	// If commentFreeSource stopped being used, this check would find nothing to
	// complain about and report the same green as a clean suite. The number of
	// sanitized reads is therefore the floor: it can rise, and it cannot fall
	// to nothing without somebody noticing.
	const sanitizedReadFloor = 15
	if sanitized < sanitizedReadFloor {
		t.Fatalf("only %d sanitized production reads in tests/spec, below the floor of %d. Either "+
			"the suite stopped stripping comments before scanning, or this scan has stopped "+
			"recognizing that it does; both make every assertion below vacuous",
			sanitized, sanitizedReadFloor)
	}

	for _, s := range scans {
		if reason, exempt := rawSourceScanByDesign[s.key]; exempt {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("rawSourceScanByDesign[%q] carries no reason. An exemption without one "+
					"is indistinguishable from an oversight.", s.key)
			}
			continue
		}
		t.Errorf("%s:%d in %s runs %s over %s, which was read with its comments intact. A "+
			"construct that appears only in a comment satisfies the assertion, so the gate "+
			"certifies a claim the file does not make. Read it through commentFreeSource, or add "+
			"%q to rawSourceScanByDesign with the argument for why the comments have to be there.",
			s.file, s.line, s.fn, s.scanner, s.target, s.key)
	}
}

// TestGateLiveness_NoStaleRawSourceScanExemption deletes an entry whose scan is
// gone, so an argument written for one read cannot be inherited by the next.
func TestGateLiveness_NoStaleRawSourceScanExemption(t *testing.T) {
	scans, _ := rawSourceScans(t)
	present := map[string]struct{}{}
	for _, s := range scans {
		present[s.key] = struct{}{}
	}
	for key, reason := range rawSourceScanByDesign {
		if _, ok := present[key]; !ok {
			t.Errorf("rawSourceScanByDesign names %q, which no longer scans an unsanitized read. "+
				"Remove the entry: the list may only shrink. (Reason on file: %s)", key, reason)
		}
	}
}

// rawSourceScan is one text scan over source that still carries its comments.
type rawSourceScan struct {
	key     string
	file    string
	fn      string
	line    int
	scanner string
	target  string
}

// rawSourceScans walks tests/spec and returns every text scan over an
// unsanitized read, together with the number of sanitized reads it saw.
//
// Scoped per function rather than per file: a variable holding raw source in one
// test says nothing about a same-named variable in the next, and treating the
// file as one scope would report the second as an offender because the first
// read raw.
func rawSourceScans(t *testing.T) ([]rawSourceScan, int) {
	t.Helper()

	corpus := filepath.Join("tests", "spec")
	dir := filepath.Join(repoRoot(t), corpus)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", corpus, err)
	}

	var out []rawSourceScan
	sanitized := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		rel := filepath.ToSlash(filepath.Join(corpus, entry.Name()))

		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			raw := map[string]struct{}{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok || len(assign.Rhs) == 0 || len(assign.Lhs) == 0 {
					return true
				}
				call, ok := assign.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				name := callName(call)
				if _, isSanitizer := sourceSanitizers[name]; isSanitizer {
					sanitized++
					return true
				}
				if _, isRaw := rawSourceReaders[name]; !isRaw {
					return true
				}
				if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name != "_" {
					raw[ident.Name] = struct{}{}
				}
				return true
			})

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				name := callName(call)
				if _, isScan := textScanners[name]; !isScan {
					return true
				}
				// A bare Contains is this package's own helper; a qualified one
				// has to be strings', because bytes.Contains over source has the
				// same exposure and a different first argument.
				if q := selectorName(call.Fun); q != "" && !strings.HasPrefix(q, "strings.") {
					return true
				}
				target := call.Args[0]
				if slice, ok := target.(*ast.SliceExpr); ok {
					target = slice.X
				}
				scanner := name
				if q := selectorName(call.Fun); q != "" {
					scanner = q
				}
				record := func(desc string) {
					out = append(out, rawSourceScan{
						key:     rel + ":" + fn.Name.Name,
						file:    rel,
						fn:      fn.Name.Name,
						line:    fset.Position(call.Pos()).Line,
						scanner: scanner,
						target:  desc,
					})
				}
				switch v := target.(type) {
				case *ast.Ident:
					if _, isRaw := raw[v.Name]; isRaw {
						record(v.Name)
					}
				case *ast.CallExpr:
					if _, isRaw := rawSourceReaders[callName(v)]; isRaw {
						record(callName(v) + "(...)")
					}
				}
				return true
			})
		}
	}
	return out, sanitized
}
