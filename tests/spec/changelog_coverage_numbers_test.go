// CHANGELOG coverage-number gate.
//
// The 1.0.0 entry says the exclusion set "stands at N entries" and that
// "scripts/cov-gaps.py ... a (N+1)th entry fails on its own". Both numbers were
// written when the set held 50, and the set has since moved to 52 -- so the
// release notes published a smaller exclusion set than the release ships, and a
// ratchet one lower than the one that actually fires.
//
// That is the drift this release exists to stop, arriving in the one document a
// reader consults to find out how much of the tree is excluded from the headline
// figure. The exclusion count is not decoration: 1.0.0 means "100.00% of
// reachable statements", and the size of the exclusion set is exactly the
// distance between that claim and "100% of the tree". Understating it overstates
// the release.
//
// The numbers are machine-checked at their source, so this gate reads the source
// and requires the prose to agree, rather than pinning a literal that goes stale
// the same way. It deliberately does not check the historical "39 it started
// from": that describes 0.9.9 and is not derivable from this tree.
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

// covGapsRatchet matches the assignment that fires when the set grows.
var covGapsRatchet = regexp.MustCompile(`(?m)^BASELINE_MAX_ENTRIES = (\d+)`)

// changelogEntryCount matches the sentence that publishes the set's size.
var changelogEntryCount = regexp.MustCompile(`set stands at (\d+) entries`)

// changelogRatchet matches the sentence that publishes the ratchet, in whatever
// ordinal form the prose uses.
var changelogRatchet = regexp.MustCompile(`a (\d+)(?:st|nd|rd|th) entry fails on its own`)

// TestChangelogPublishesTheRealExclusionCount fails when the release notes
// disagree with the exclusion file or with the ratchet that guards it.
func TestChangelogPublishesTheRealExclusionCount(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, ".coverage-exclusions.json"))
	if err != nil {
		t.Fatalf("read .coverage-exclusions.json: %v", err)
	}
	var excl struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(raw, &excl); err != nil {
		t.Fatalf("parse .coverage-exclusions.json: %v", err)
	}
	actual := len(excl.Entries)

	script, err := os.ReadFile(filepath.Join(root, "scripts", "cov-gaps.py"))
	if err != nil {
		t.Fatalf("read scripts/cov-gaps.py: %v", err)
	}
	m := covGapsRatchet.FindSubmatch(script)
	if m == nil {
		t.Fatal("scripts/cov-gaps.py no longer assigns BASELINE_MAX_ENTRIES. This gate ties the " +
			"published exclusion count to that ratchet; if the ratchet moved, point it at whatever " +
			"replaced it rather than deleting the check.")
	}
	var ratchet int
	if _, err := fmt.Sscanf(string(m[1]), "%d", &ratchet); err != nil {
		t.Fatalf("parse BASELINE_MAX_ENTRIES: %v", err)
	}

	// The ratchet exists to stop the set growing, so it must sit at the set's
	// current size. A ratchet above it silently admits new exclusions.
	if ratchet != actual {
		t.Errorf("BASELINE_MAX_ENTRIES is %d but .coverage-exclusions.json holds %d entries. A ratchet "+
			"above the current size admits new exclusions without failing, which is the opposite of "+
			"what it is for.", ratchet, actual)
	}

	body, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	text := string(body)

	if got := changelogEntryCount.FindStringSubmatch(text); got == nil {
		t.Error("CHANGELOG.md no longer publishes the exclusion-set size. 1.0.0 claims 100.00% of " +
			"reachable statements, so the size of the set excluded from that figure belongs in the " +
			"release notes.")
	} else if got[1] != fmt.Sprint(actual) {
		t.Errorf("CHANGELOG.md says the exclusion set stands at %s entries; the file holds %d. The "+
			"release notes are publishing a smaller excluded set than the release ships, which "+
			"overstates the coverage claim.", got[1], actual)
	}

	if got := changelogRatchet.FindStringSubmatch(text); got == nil {
		t.Error("CHANGELOG.md no longer states which entry the ratchet fails on.")
	} else if got[1] != fmt.Sprint(ratchet+1) {
		t.Errorf("CHANGELOG.md says entry %s fails the ratchet; BASELINE_MAX_ENTRIES is %d, so the "+
			"first failing entry is %d.", got[1], ratchet, ratchet+1)
	}

	// The headline claim is the reason the count matters, so it must still be the
	// reachable-statement claim and not a quietly widened one.
	if !strings.Contains(text, "100.00% of reachable statements") {
		t.Error("CHANGELOG.md no longer claims 100.00% of reachable statements. If the headline " +
			"changed, the exclusion arithmetic above is describing a claim that is no longer made.")
	}
}
