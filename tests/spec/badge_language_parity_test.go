// README badge / badges.json parity gate.
//
// The badge table publishes a test count and a coverage figure for each of the
// three languages that ship: Go, the Vue frontend, and the C# SDKs. Those six
// numbers are the most-read claim in the repository and the least likely to be
// noticed when they go stale, because a badge that is wrong looks exactly like a
// badge that is right.
//
// scripts/readme-gen.sh writes both the table and docs/badges.json from one run,
// so at the moment of generation they agree by construction. What this gate
// catches is the hand-edit afterwards: a number nudged in the README, a
// languages block updated without regenerating, a column dropped. Either
// artifact alone is unverifiable; the pair is checkable, so the pair is what is
// required to agree.
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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	Tests       int     `json:"tests"`
	Coverage    string  `json:"coverage"`
	CoverageNum float64 `json:"coverageNum"`
	Lines       int     `json:"lines"`
	Deps        int     `json:"deps"`
}

type badgesFile struct {
	Tests      int                        `json:"tests"`
	TotalTests int                        `json:"totalTests"`
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
