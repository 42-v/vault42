// README badge / badges.json parity gate.
//
// The badge table publishes a test count and a coverage figure for each of the
// three languages that ship: Go, the Vue frontend, and the C# SDKs. Those six
// numbers are the most-read claim in the repository and the least likely to be
// noticed when they go stale, because a badge that is wrong looks exactly like a
// badge that is right.
//
// scripts/readme-gen.sh writes both the table and docs/badges.json from one run,
// so at the moment of generation they agree by construction. What the parity
// half of this gate catches is the hand-edit afterwards: a number nudged in the
// README, a languages block updated without regenerating, a column dropped.
//
// Parity alone cannot catch a regeneration that never happened, because the pair
// stays consistent with each other while both drift from the tree. The second
// half, TestBadgeFiguresMatchTheRepository, recounts the figures a checkout can
// be counted for and compares those against the pair, so the two artifacts can
// no longer be jointly wrong.
//
// It also pins the shape. The 1.0.2 table is per-language on purpose -- a single
// "Tests" badge summing three suites hid that the C# SDKs had 46 tests and no
// pull request had ever built them -- and a later regeneration that quietly
// collapsed the columns would take that visibility away without failing
// anything.
//
// The test is read-only. It never writes to the source tree.
package spec_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// badgeBlock isolates the generated region, so prose elsewhere in the README
// that happens to contain a shields.io URL cannot satisfy or break this gate.
var badgeBlock = regexp.MustCompile(`(?s)<!-- badges -->\n(.*?)\n<!-- /badges -->`)

// shieldValue pulls the value segment out of a shields.io static badge, which is
// the middle field of `/badge/<label>-<value>-<color>`.
var shieldValue = regexp.MustCompile(`img\.shields\.io/badge/([^-]+)-([^-]+)-`)

// badgeLanguage is one shipped language and the JSON key its figures live under.
type badgeLanguage struct {
	column int    // zero-based column in the badge table
	key    string // key under "languages" in docs/badges.json
	name   string
}

// The column order is the table's contract: Go, Vue, C#, then the column that
// carries everything which is not per-language.
var badgeLanguages = []badgeLanguage{
	{0, "go", "Go"},
	{1, "vue", "Vue"},
	{2, "csharp", "C#"},
}

// badgeInfoColumn is the fourth column. It exists so the per-language columns
// stay per-language: totals, license and register counts belong to the project
// rather than to any one language, and mixing them in was what let a single
// "Coverage" badge stand for a tree that had three very different numbers in it.
const badgeInfoColumn = 3

type languageFigures struct {
	Tests          int     `json:"tests"`
	Coverage       string  `json:"coverage"`
	CoverageNum    float64 `json:"coverageNum"`
	Lines          int     `json:"lines"`
	Deps           int     `json:"deps"`
	TransitiveDeps int     `json:"transitiveDeps"`
}

type badgesFile struct {
	Tests      int                        `json:"tests"`
	GoFiles    int                        `json:"goFiles"`
	GoLines    int                        `json:"goLines"`
	TestFiles  int                        `json:"testFiles"`
	TotalTests int                        `json:"totalTests"`
	TotalDeps  int                        `json:"totalDeps"`
	Languages  map[string]languageFigures `json:"languages"`
}

// TestBadgeTableCarriesEveryShippedLanguage fails when the table loses a
// language column or stops reporting tests and coverage for one.
func TestBadgeTableCarriesEveryShippedLanguage(t *testing.T) {
	t.Parallel()

	rows := badgeRows(t)
	if len(rows) < 3 {
		t.Fatalf("the badge block has %d rows; the scan is broken and every assertion below "+
			"would pass vacuously", len(rows))
	}

	for _, row := range rows {
		if len(row) != badgeInfoColumn+1 {
			t.Fatalf("badge row %q has %d columns, want %d (Go, Vue, C#, project). The "+
				"per-language columns are the point of this table: one summed Tests badge is "+
				"what hid a C# suite of 46 tests that no pull request built.",
				strings.Join(row, " | "), len(row), badgeInfoColumn+1)
		}
	}

	// Row 0 is the header, row 1 the alignment marker; the data starts after.
	body := rows[2:]

	testsRow := findBadgeRow(t, body, "Tests")
	coverageRow := findBadgeRow(t, body, "Coverage")
	linesRow := findBadgeRow(t, body, "Lines")
	depsRow := findBadgeRow(t, body, "Deps")

	// Two dependency rows: what each language declares, and what those
	// declarations resolve to. A single Deps row published 3, 3 and 6 for a tree
	// that resolves an order of magnitude more, which is the flattering half of
	// the answer to a supply-chain question.
	transitiveRow := findBadgeRow(t, body, "Transitive")

	badges := loadBadgesJSON(t)
	if len(badges.Languages) != len(badgeLanguages) {
		t.Fatalf("docs/badges.json describes %d languages, want %d",
			len(badges.Languages), len(badgeLanguages))
	}

	for _, lang := range badgeLanguages {
		figures, ok := badges.Languages[lang.key]
		if !ok {
			t.Errorf("docs/badges.json has no %q entry, so the %s column has nothing backing it",
				lang.key, lang.name)
			continue
		}

		wantTests := fmt.Sprintf("%d", figures.Tests)
		if got := shieldValueAt(t, testsRow[lang.column]); got != wantTests {
			t.Errorf("%s test badge reads %q and docs/badges.json says %q. Regenerate with "+
				"scripts/readme-gen.sh rather than editing either by hand.",
				lang.name, got, wantTests)
		}

		// The Go figure is qualified ("100.00%_reachable") because its
		// denominator is the reachable set rather than the whole tree; the other
		// two are plain percentages. Comparing on the leading number keeps the
		// qualification without making the gate depend on its wording.
		gotCov := leadingNumber(shieldValueAt(t, coverageRow[lang.column]))
		wantCov := fmt.Sprintf("%.2f", figures.CoverageNum)
		if gotCov != wantCov {
			t.Errorf("%s coverage badge reads %q and docs/badges.json says %q",
				lang.name, gotCov, wantCov)
		}

		for _, figure := range []struct {
			label string
			cell  string
			want  int
		}{
			{"lines", linesRow[lang.column], figures.Lines},
			{"deps", depsRow[lang.column], figures.Deps},
			{"transitive deps", transitiveRow[lang.column], figures.TransitiveDeps},
		} {
			want := fmt.Sprintf("%d", figure.want)
			if got := shieldValueAt(t, figure.cell); got != want {
				t.Errorf("%s %s badge reads %q and docs/badges.json says %q. Regenerate with "+
					"scripts/readme-gen.sh rather than editing either by hand.",
					lang.name, figure.label, got, want)
			}
		}

		if figures.Tests == 0 {
			t.Errorf("docs/badges.json reports 0 tests for %s. A suite that did not run is "+
				"reported as absent, never as a zero: scripts/readme-gen.sh refuses to publish "+
				"one, so a zero here means the file was written by something else.", lang.name)
		}
	}

	// The total is the sum, and saying so is what stops a language being dropped
	// from the table while its tests keep inflating the headline figure.
	sum := 0
	for _, lang := range badgeLanguages {
		sum += badges.Languages[lang.key].Tests
	}
	if badges.TotalTests != sum {
		t.Errorf("docs/badges.json totalTests is %d and the three languages sum to %d",
			badges.TotalTests, sum)
	}

	if got := shieldValueAt(t, testsRow[badgeInfoColumn]); got != fmt.Sprintf("%d_tests", sum) {
		t.Errorf("the total badge reads %q and the three languages sum to %d", got, sum)
	}

	// The dependency total is the whole surface, direct and transitive, across
	// the three ecosystems. It is the figure that answers "how much third-party
	// code is in here", and the per-language rows are what it decomposes into.
	depSum := 0
	for _, lang := range badgeLanguages {
		depSum += badges.Languages[lang.key].Deps + badges.Languages[lang.key].TransitiveDeps
	}
	if badges.TotalDeps != depSum {
		t.Errorf("docs/badges.json totalDeps is %d and the three languages sum to %d",
			badges.TotalDeps, depSum)
	}
	if got := shieldValueAt(t, transitiveRow[badgeInfoColumn]); got != fmt.Sprintf("%d_total", depSum) {
		t.Errorf("the total dependency badge reads %q and the three languages sum to %d",
			got, depSum)
	}
}

// TestBadgeGoFigureStillMeansReachable keeps the one qualified number qualified.
//
// Go is measured against the reachable set, which is the whole tree minus the
// reviewed exclusion list. A badge reading a bare "100.00%" would claim
// something stronger than the release does, and it is the claim a reader quotes.
func TestBadgeGoFigureStillMeansReachable(t *testing.T) {
	t.Parallel()

	rows := badgeRows(t)
	coverageRow := findBadgeRow(t, rows[2:], "Coverage")

	value := shieldValueAt(t, coverageRow[0])
	if !strings.Contains(value, "reachable") {
		t.Errorf("the Go coverage badge reads %q. It has to say what the denominator is: the "+
			"figure is a percentage of reachable statements, not of the tree, and the "+
			"difference is exactly the exclusion set.", value)
	}
}

// TestBadgeFiguresMatchTheRepository is the half of this gate that can still
// fail when README.md and docs/badges.json agree with each other.
//
// Everything above compares the two generated artifacts. One scripts/readme-gen.sh
// run writes both, so their agreement is a property of the generator rather than
// evidence about the tree: a regeneration that never happened leaves a pair that
// still matches, and an edit applied to both passes. That is not hypothetical.
// The 1.0.3 badges published 48651 Go lines across 195 files for a tree holding
// 48062 across 192, and the parity gate was green for the whole release.
//
// So every figure a checkout can be recounted for is recounted here, from the
// files rather than from the generator's arithmetic, and compared against
// docs/badges.json. The parity assertions above carry the same numbers to the
// README, so a hand-edit has to move three things in step and still lose to a
// recount to get through.
//
// Deliberately not recounted:
//
//   - Test counts. There is no way to know how many tests pass without running
//     them, and a gate that guessed would be worse than none.
//   - Coverage, for the same reason.
//   - The transitive dependency figures. Those need the Go module graph, pnpm's
//     lockfile resolution and a NuGet restore. Reimplementing any of the three
//     here would put a second unverified resolver in the tree for the first one
//     to agree with, which is the defect this test exists to remove.
func TestBadgeFiguresMatchTheRepository(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	badges := loadBadgesJSON(t)

	goProd, goTests := goSourceFiles(t, root)
	goLines := countNewlines(t, goProd)
	goDeps := goImportedModules(t, goProd, goDirectRequires(t, root))

	vueLines := countNewlines(t, frontendSourceFiles(t, root))
	vueDeps := vueDirectDeps(t, root)

	csLines := countNewlines(t, dotnetSourceFiles(t, root))
	csDeps := dotnetDirectDeps(t, root)

	for _, figure := range []struct {
		key       string
		published int
		counted   int
		counting  string
	}{
		{
			"goFiles", badges.GoFiles, len(goProd),
			"non-test .go files, excluding vendor/, tmp/ and node_modules/",
		},
		{
			"testFiles", badges.TestFiles, len(goTests),
			"_test.go files, excluding vendor/, tmp/ and node_modules/",
		},
		{
			"goLines", badges.GoLines, goLines,
			"lines in the non-test .go files",
		},
		{
			"languages.go.lines", badges.Languages["go"].Lines, goLines,
			"lines in the non-test .go files",
		},
		{
			"languages.go.deps", badges.Languages["go"].Deps, len(goDeps),
			"go.mod requires without an // indirect marker that non-test Go source imports: " +
				strings.Join(goDeps, ", "),
		},
		{
			"languages.vue.lines", badges.Languages["vue"].Lines, vueLines,
			"lines in web/src and packages/vue/src, minus __tests__ and *.test.*",
		},
		{
			"languages.vue.deps", badges.Languages["vue"].Deps, len(vueDeps),
			"web's dependencies plus packages/vue's peerDependencies, minus the workspace " +
				"package: " + strings.Join(vueDeps, ", "),
		},
		{
			"languages.csharp.lines", badges.Languages["csharp"].Lines, csLines,
			"lines in packages/dotnet/src, minus obj/ and bin/",
		},
		{
			"languages.csharp.deps", badges.Languages["csharp"].Deps, len(csDeps),
			"PackageReference entries in packages/dotnet/src/*/*.csproj: " +
				strings.Join(csDeps, ", "),
		},
	} {
		if figure.published != figure.counted {
			t.Errorf("docs/badges.json %s is %d; counting the tree gives %d (%s).\n"+
				"The README badge carries the same figure, so the two can agree with each "+
				"other and both be stale. Run scripts/readme-gen.sh.",
				figure.key, figure.published, figure.counted, figure.counting)
		}
	}
}

// goSourceFilesSkip are directories whose Go files are not this module's source.
//
// vendor/ is the obvious one. tmp/ and node_modules/ are not obvious and are why
// this list exists: both are gitignored, both contain .go files nobody here
// wrote -- a scratch main.go from a 1.0.0 audit, another from a hardening
// experiment, and a Go implementation shipped inside the `flatted` npm package
// -- and counting them made this gate demand 195 non-test files where the
// module has 192. A walk that counts ignored directories measures the machine
// it runs on rather than the repository.
var goSourceFilesSkip = map[string]bool{
	"vendor":       true,
	"tmp":          true,
	"node_modules": true,
	".git":         true,
}

// goSourceFiles splits the module's Go files into non-test and test files, using
// the same set scripts/readme-gen.sh counts.
func goSourceFiles(t *testing.T, root string) (prod, tests []string) {
	t.Helper()

	walk := func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if goSourceFilesSkip[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(path, "_test.go"):
			tests = append(tests, path)
		case strings.HasSuffix(path, ".go"):
			prod = append(prod, path)
		}
		return nil
	}
	if err := filepath.WalkDir(root, walk); err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return prod, tests
}

// frontendSourceFiles returns the Vue and TypeScript sources the Lines badge
// counts: the two src trees, without their test files.
func frontendSourceFiles(t *testing.T, root string) []string {
	t.Helper()

	var out []string
	for _, dir := range []string{
		filepath.Join(root, "web", "src"),
		filepath.Join(root, "packages", "vue", "src"),
	} {
		out = append(out, filesUnder(t, dir, nil, func(path string, entry fs.DirEntry) bool {
			if ext := filepath.Ext(path); ext != ".vue" && ext != ".ts" {
				return false
			}
			return !strings.Contains(filepath.ToSlash(path), "__tests__") &&
				!strings.Contains(entry.Name(), ".test.")
		})...)
	}
	return out
}

// dotnetSourceFiles returns the C# sources the Lines badge counts. obj/ and bin/
// hold restore and build output, including generated .cs nobody wrote.
func dotnetSourceFiles(t *testing.T, root string) []string {
	t.Helper()

	skipBuildOutput := func(name string) bool { return name == "obj" || name == "bin" }
	return filesUnder(t, filepath.Join(root, "packages", "dotnet", "src"), skipBuildOutput,
		func(path string, _ fs.DirEntry) bool {
			ext := filepath.Ext(path)
			return ext == ".cs" || ext == ".razor"
		})
}

// filesUnder walks dir and returns the files keep accepts, descending into every
// directory skipDir does not name.
func filesUnder(t *testing.T, dir string, skipDir func(name string) bool,
	keep func(path string, entry fs.DirEntry) bool,
) []string {
	t.Helper()

	var out []string
	walk := func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if skipDir != nil && skipDir(entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if keep(path, entry) {
			out = append(out, path)
		}
		return nil
	}
	if err := filepath.WalkDir(dir, walk); err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

// countNewlines counts newline bytes, which is what `find ... -exec cat {} + |
// wc -l` reports in scripts/readme-gen.sh. A file whose last line has no newline
// contributes what wc counts, not one more.
func countNewlines(t *testing.T, paths []string) int {
	t.Helper()

	total := 0
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		total += bytes.Count(raw, []byte{'\n'})
	}
	return total
}

// goRequire matches a module path and version inside a go.mod require block.
var goRequire = regexp.MustCompile(`^\s+(\S+)\s+(v\S+)`)

// goDirectRequires returns the module paths go.mod requires without an
// `// indirect` marker.
func goDirectRequires(t *testing.T, root string) []string {
	t.Helper()

	var mods []string
	inBlock := false
	for _, raw := range strings.Split(readFileString(t, filepath.Join(root, "go.mod")), "\n") {
		// Everything after // is a comment, and a module path that appears only
		// in one is not a requirement. The "// indirect" marker is read from the
		// raw line below, before this strips it, because that marker is the one
		// piece of comment text that carries meaning here.
		line := raw
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "require ("):
			inBlock = true
		case inBlock && trimmed == ")":
			inBlock = false
		case strings.Contains(raw, "// indirect"):
		case inBlock:
			if m := goRequire.FindStringSubmatch(line); m != nil {
				mods = append(mods, m[1])
			}
		case strings.HasPrefix(trimmed, "require "):
			if fields := strings.Fields(trimmed); len(fields) > 1 {
				mods = append(mods, fields[1])
			}
		}
	}
	return mods
}

// goImportedModules returns the modules in mods that at least one of the given
// files imports.
//
// This is the recount behind the Go Deps badge, and it is deliberately not how
// scripts/readme-gen.sh gets the number. The generator intersects go.mod with
// `go list -deps ./...`, the module set the build links. Reaching the same
// answer from the import statements needs no module graph and no network, and
// two computations that share no code agreeing is the only thing that makes
// either of them evidence.
//
// The two agree because a require nothing shipped imports (testcontainers,
// yaml.v3 here) is a test dependency, and a require that is imported is by
// definition in the closure.
func goImportedModules(t *testing.T, files, mods []string) []string {
	t.Helper()

	imports := make(map[string]bool)
	fset := token.NewFileSet()
	for _, path := range files {
		parsed, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, spec := range parsed.Imports {
			imports[strings.Trim(spec.Path.Value, `"`)] = true
		}
	}

	var used []string
	for _, mod := range mods {
		for imported := range imports {
			if imported == mod || strings.HasPrefix(imported, mod+"/") {
				used = append(used, mod)
				break
			}
		}
	}
	sort.Strings(used)
	return used
}

// vueDirectDeps returns the frontend's declared dependencies: what a consumer of
// the published packages has to resolve.
func vueDirectDeps(t *testing.T, root string) []string {
	t.Helper()

	type manifest struct {
		Dependencies     map[string]string `json:"dependencies"`
		PeerDependencies map[string]string `json:"peerDependencies"`
	}
	read := func(path string) manifest {
		var parsed manifest
		if err := json.Unmarshal([]byte(readFileString(t, filepath.Join(root, path))), &parsed); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		return parsed
	}

	names := make(map[string]bool)
	for name := range read("web/package.json").Dependencies {
		names[name] = true
	}
	for name := range read("packages/vue/package.json").PeerDependencies {
		names[name] = true
	}

	// @vault42/vue is the workspace package itself, not something it depends on.
	delete(names, "@vault42/vue")
	return sortedSet(names)
}

// packageReference matches a NuGet dependency declared in an SDK project file.
var packageReference = regexp.MustCompile(`<PackageReference Include="([^"]+)"`)

// dotnetDirectDeps returns the NuGet packages the two published SDK projects
// declare. Analyzers injected by Directory.Build.props are build-time tools a
// consumer never resolves, and they are not in these files.
func dotnetDirectDeps(t *testing.T, root string) []string {
	t.Helper()

	projects, err := filepath.Glob(filepath.Join(root, "packages", "dotnet", "src", "*", "*.csproj"))
	if err != nil {
		t.Fatalf("glob csproj: %v", err)
	}
	if len(projects) == 0 {
		t.Fatal("no packages/dotnet/src/*/*.csproj; the C# dependency recount would be " +
			"vacuously zero and would agree with any badge")
	}

	names := make(map[string]bool)
	for _, project := range projects {
		for _, m := range packageReference.FindAllStringSubmatch(readFileString(t, project), -1) {
			names[m[1]] = true
		}
	}
	return sortedSet(names)
}

// sortedSet returns a set's members in a stable order, so a failure message
// reads the same on every run.
func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// badgeRows returns the badge table split into cells.
func badgeRows(t *testing.T) [][]string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	match := badgeBlock.FindSubmatch(raw)
	if match == nil {
		t.Fatal("README.md has no <!-- badges --> block; scripts/readme-gen.sh writes into it " +
			"and would have nowhere to write")
	}

	lines := strings.Split(strings.TrimSpace(string(match[1])), "\n")
	rows := make([][]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		rows = append(rows, cells)
	}
	return rows
}

// findBadgeRow returns the row whose first cell carries the given shields label.
func findBadgeRow(t *testing.T, rows [][]string, label string) []string {
	t.Helper()

	for _, row := range rows {
		if m := shieldValue.FindStringSubmatch(row[0]); m != nil && m[1] == label {
			return row
		}
	}
	t.Fatalf("no badge row whose first column is a %q badge; the table shape changed and the "+
		"per-language figures are no longer where this gate can check them", label)
	return nil
}

// shieldValueAt extracts the value a shields.io badge displays.
func shieldValueAt(t *testing.T, cell string) string {
	t.Helper()

	m := shieldValue.FindStringSubmatch(cell)
	if m == nil {
		t.Fatalf("badge cell %q is not a shields.io static badge", cell)
	}
	return m[2]
}

// leadingNumber returns the numeric prefix of a badge value, so "100.00%25_reachable"
// and "99.76%25" compare on the same footing.
func leadingNumber(value string) string {
	end := 0
	for end < len(value) && (value[end] == '.' || (value[end] >= '0' && value[end] <= '9')) {
		end++
	}
	return value[:end]
}

func loadBadgesJSON(t *testing.T) badgesFile {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "badges.json"))
	if err != nil {
		t.Fatalf("read docs/badges.json: %v", err)
	}
	var badges badgesFile
	if err := json.Unmarshal(raw, &badges); err != nil {
		t.Fatalf("parse docs/badges.json: %v", err)
	}
	return badges
}
