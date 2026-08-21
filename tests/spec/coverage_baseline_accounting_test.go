// Statement-floor accounting gate.
//
// scripts/cov-gaps.py carries BASELINE_TOTAL_STATEMENTS, the floor that catches
// a package falling out of -coverpkg as a smaller denominator rather than as a
// higher percentage. The rule the file states about itself is that the figure
// comes with its working: every raise is itemized package by package in the
// comment above it, so a reviewer can check the number instead of taking it.
//
// The rule has been broken twice, both times silently. Once the constant moved
// 270 statements past where the itemization stopped. Once the itemization was
// right and the sentence introducing it was three out. Prose cannot be gated,
// but arithmetic can: BASELINE_PACKAGE_STATEMENTS now holds each package's share
// of the same measurement, and this asserts that the shares are the total. A
// raise that skips the accounting no longer type-checks.
//
// It reads the source rather than a coverage profile on purpose. The invariant
// is between two constants in one file, so it needs no measurement, and a gate
// that needs the canonical run would report a typo twenty minutes after it was
// made instead of in the same test run as the edit.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// covGapsTotal matches the floor assignment.
var covGapsTotal = regexp.MustCompile(`(?m)^BASELINE_TOTAL_STATEMENTS = (\d+)`)

// covGapsShares matches the per-package dict, up to the closing brace in the
// first column. Anchoring the close at column 0 keeps a nested brace from
// ending the match early.
var covGapsShares = regexp.MustCompile(`(?s)\nBASELINE_PACKAGE_STATEMENTS = \{\n(.*?)\n\}\n`)

// covGapsShare matches one "package": count entry of that dict.
var covGapsShare = regexp.MustCompile(`(?m)^\s*"([^"]+)":\s*(\d+),`)

// covGapsDerivedPackages is the assignment that makes the shape guard read the
// same package list as the shares.
const covGapsDerivedPackages = "BASELINE_PACKAGES = tuple(BASELINE_PACKAGE_STATEMENTS)"

// covGapsSource reads scripts/cov-gaps.py.
func covGapsSource(t *testing.T) string {
	t.Helper()

	return readFileString(t, filepath.Join(repoRoot(t), "scripts", "cov-gaps.py"))
}

// TestCoverageBaselineAccountsForEveryStatement fails when the statement floor
// and its per-package accounting disagree.
func TestCoverageBaselineAccountsForEveryStatement(t *testing.T) {
	t.Parallel()

	src := covGapsSource(t)

	totalMatch := covGapsTotal.FindStringSubmatch(src)
	if totalMatch == nil {
		t.Fatal("scripts/cov-gaps.py no longer assigns BASELINE_TOTAL_STATEMENTS. That constant " +
			"is the coverage floor; if it moved or was renamed, point this gate at whatever " +
			"replaced it rather than deleting the check.")
	}
	var total int
	if _, err := fmt.Sscanf(totalMatch[1], "%d", &total); err != nil {
		t.Fatalf("parse BASELINE_TOTAL_STATEMENTS: %v", err)
	}

	sharesMatch := covGapsShares.FindStringSubmatch(src)
	if sharesMatch == nil {
		t.Fatal("scripts/cov-gaps.py no longer assigns BASELINE_PACKAGE_STATEMENTS. It is what " +
			"decomposes the floor into the per-package figures the comment above it has to " +
			"account for, and what the gate prints when the floor is behind.")
	}

	sum := 0
	seen := make(map[string]bool)
	for _, entry := range covGapsShare.FindAllStringSubmatch(sharesMatch[1], -1) {
		pkg := entry[1]
		var stmts int
		if _, err := fmt.Sscanf(entry[2], "%d", &stmts); err != nil {
			t.Fatalf("parse the share for %s: %v", pkg, err)
		}
		// Python keeps the last of two identical keys, so a duplicate would
		// drop a package's share from the sum the script computes while this
		// test still counted both. Catching it here says what happened;
		// catching it as an off-by-N in the total would not.
		if seen[pkg] {
			t.Errorf("BASELINE_PACKAGE_STATEMENTS names %s twice. Python keeps the last "+
				"binding, so one of the two figures is not in the floor at all.", pkg)
		}
		seen[pkg] = true
		sum += stmts
	}
	if len(seen) == 0 {
		t.Fatal("BASELINE_PACKAGE_STATEMENTS parsed as empty. The dict holds one " +
			`"package": count line per measured package; this gate reads them with ` +
			covGapsShare.String())
	}

	if sum != total {
		t.Errorf("BASELINE_PACKAGE_STATEMENTS sums to %d across %d packages, but "+
			"BASELINE_TOTAL_STATEMENTS is %d, a difference of %d.\n"+
			"The floor and its accounting are one measurement, so one of the two was raised "+
			"without the other. Rerun scripts/coverage.sh and take both figures from the same "+
			"profile: the gate prints the per-package delta when the floor is behind.",
			sum, len(seen), total, total-sum)
	}
}

// TestCoverageBaselineShapeGuardReadsTheShares fails when the package list the
// shape guard walks stops being derived from the shares.
//
// The shape guard catches what the floor cannot: a package dropped from the run
// while enough statements remain elsewhere to clear the count. It needs the list
// of packages that must contribute, and the shares already are that list. Two
// hand-written lists of the same packages drift, and the drift is invisible --
// a package missing from the guard is silently not guarded, which is exactly the
// state cmd/ sat in until 1.0.0.
func TestCoverageBaselineShapeGuardReadsTheShares(t *testing.T) {
	t.Parallel()

	if src := covGapsSource(t); !strings.Contains(src, covGapsDerivedPackages) {
		t.Errorf("scripts/cov-gaps.py no longer derives the shape guard's package list from "+
			"the shares. Expected the line %q. A second hand-written list of the same "+
			"packages can disagree with the first about which packages exist, and only one "+
			"of the two is checked against the floor.", covGapsDerivedPackages)
	}
}
