// The upgrade document has to exist, be findable, and stay true.
//
// Nothing in this tree said what `helm rollback` restores. It restores the
// chart; it cannot restore the schema, so a rolled-back binary runs against a
// database up to 23 migrations ahead of it, and migration 029 breaks 0.9.9's
// lock-user outright by revoking UPDATE (locked_until) from vault_app. An
// operator's first contact with any of that was a production upgrade.
//
// Two gates. The first is that the document is referenced from the three places
// an operator actually looks: the release notes, the documentation index, and
// the notes the chart prints on their own cluster. A document nobody is pointed
// at is not a remedy.
//
// The second is that the counts in it are the tree's counts. A document whose
// numbers drift is worse than none, because it is read as current. The next
// migration added without touching it turns this red.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const upgradingDoc = "UPGRADING.md"

// referencesToUpgradingDoc are the surfaces that have to point at it, each with
// the reader who arrives there.
var referencesToUpgradingDoc = map[string]string{
	"CHANGELOG.md":                     "the operator reading the release entry before deciding to upgrade",
	"docs/README.md":                   "the documentation index, whose own rule is that adding a document means adding a row",
	"charts/vault/templates/NOTES.txt": "the notes helm prints on the cluster, which is the only one of the three that reaches an operator who never opened the repository",
}

func TestUpgradingDocIsReferencedWhereAnOperatorLooks(t *testing.T) {
	root := repoRoot(t)

	if _, err := os.Stat(filepath.Join(root, "docs", upgradingDoc)); err != nil {
		t.Fatalf("docs/%s is missing: %v", upgradingDoc, err)
	}

	for file, reader := range referencesToUpgradingDoc {
		if !strings.Contains(commentFreeSource(t, filepath.Join(root, file)), upgradingDoc) {
			t.Errorf("%s does not mention %s, so it is invisible to %s.", file, upgradingDoc, reader)
		}
	}
}

// schemaCountSentence is the one machine-checked claim in the document. Keeping
// it to a fixed shape is what lets the gate read it; the failure message says so.
var schemaCountSentence = regexp.MustCompile(
	`(v[0-9][0-9.]*) shipped (\d+) migrations; this release ships (\d+), so an upgrade applies (\d+)`)

func TestUpgradingDocMigrationCountsMatchTheTree(t *testing.T) {
	root := repoRoot(t)
	doc := readFileString(t, filepath.Join(root, "docs", upgradingDoc))

	// All, not the first. FindStringSubmatch stops at the leading section, so a
	// second copy of this sentence further down -- in an older section that has
	// since gone stale -- was invisible to the gate that exists to catch exactly
	// that. One sentence in this shape, checked; more than one, and the gate
	// cannot tell which describes the release.
	matches := schemaCountSentence.FindAllStringSubmatch(doc, -1)
	if len(matches) == 0 {
		t.Fatalf("docs/%s no longer carries the sentence this gate reads. It has to keep the "+
			"shape `vX.Y.Z shipped N migrations; this release ships M, so an upgrade applies K`, "+
			"because an upgrade document whose numbers have drifted is read as current.",
			upgradingDoc)
	}
	if len(matches) > 1 {
		t.Fatalf("docs/%s carries %d sentences in the machine-read shape. Exactly one describes "+
			"this release; the others will drift silently because only the first was ever checked.",
			upgradingDoc, len(matches))
	}
	match := matches[0]
	statedTag, statedFrom := match[1], atoi(t, match[2])
	statedTo, statedApplied := atoi(t, match[3]), atoi(t, match[4])

	if got := len(migrationFilesAt(t, root, "")); got != statedTo {
		t.Errorf("docs/%s says this release ships %d migrations; the tree has %d",
			upgradingDoc, statedTo, got)
	}
	if statedApplied != statedTo-statedFrom {
		t.Errorf("docs/%s says an upgrade applies %d migrations, but %d - %d is %d",
			upgradingDoc, statedApplied, statedTo, statedFrom, statedTo-statedFrom)
	}

	tag := lastReleaseTag(t, root)
	if tag != statedTag {
		t.Errorf("docs/%s describes the upgrade from %s; the most recent release tag reachable "+
			"from HEAD is %s. The document is describing a hop nobody is making.",
			upgradingDoc, statedTag, tag)
	}
	if got := len(migrationFilesAt(t, root, tag)); got != statedFrom {
		t.Errorf("docs/%s says %s shipped %d migrations; it shipped %d",
			upgradingDoc, tag, statedFrom, got)
	}
}

// backCompatCountSentence is the document's other migration claim: the note
// telling a reader coming from an older line which releases changed nothing.
// It went stale the moment this release added a migration, and the gate above
// could not see it -- different shape, and further down the document.
var backCompatCountSentence = regexp.MustCompile(
	`([0-9][0-9.]*) through ([0-9][0-9.]*) added no migrations, so the\s+count is the same (\d+)`)

// TestUpgradingDocBackCompatCountMatchesTheTree holds the second count sentence
// to the same standard as the first: the range it names must genuinely have
// added nothing, and the figure must be what that tag shipped.
func TestUpgradingDocBackCompatCountMatchesTheTree(t *testing.T) {
	root := repoRoot(t)
	doc := readFileString(t, filepath.Join(root, "docs", upgradingDoc))

	match := backCompatCountSentence.FindStringSubmatch(doc)
	if match == nil {
		t.Fatalf("docs/%s no longer carries the back-compatibility count sentence. It has to "+
			"keep the shape `X through Y added no migrations, so the count is the same N`: it "+
			"tells a reader on an older line whether they can skip ahead, and it is the sentence "+
			"that goes stale first when a release adds a migration.", upgradingDoc)
	}
	upperTag, stated := "v"+match[2], atoi(t, match[3])

	// A checkout without tags cannot answer what that tag shipped, and CI does
	// not always fetch them -- this failed there with exit status 128 while
	// passing locally. Skipping is what lastReleaseTag does for the same reason
	// and for the gate one function up, which reads the same history.
	if err := exec.Command("git", "-C", root, "rev-parse", "-q", "--verify",
		upperTag+"^{commit}").Run(); err != nil { // #nosec G204 -- tag comes from the document's own sentence
		if runningInCI() {
			// ci.yml sets fetch-tags: true on both jobs that run this suite, so
			// on a runner an unreachable tag means a checkout stopped fetching
			// them -- and this gate going quiet is exactly what that looks like.
			t.Fatalf("%s is not reachable on a CI runner. Both jobs that run ./tests/spec/... "+
				"fetch tags; if that changed, this gate stopped checking the count sentence "+
				"and reported ok while doing it.", upperTag)
		}
		t.Skipf("%s is not reachable in this checkout, so what it shipped cannot be read. "+
			"The count sentence is unverified here, not verified.", upperTag)
	}

	if got := len(migrationFilesAt(t, root, upperTag)); got != stated {
		t.Errorf("docs/%s says the count through %s is %d; that tag shipped %d. A release that "+
			"adds a migration has to move the upper bound of this sentence, not only the one "+
			"above it.", upgradingDoc, upperTag, stated, got)
	}
}

// migrationFilesAt lists the .sql migrations in the working tree (tag "") or at
// a git tag.
func migrationFilesAt(t *testing.T, root, tag string) []string {
	t.Helper()

	var names []string
	if tag == "" {
		entries, err := os.ReadDir(filepath.Join(root, "migrations"))
		if err != nil {
			t.Fatalf("read migrations: %v", err)
		}
		for _, e := range entries {
			names = append(names, e.Name())
		}
	} else {
		cmd := exec.Command("git", "-C", root, "ls-tree", "--name-only", tag, "migrations/") // #nosec G204 -- tag comes from git describe in this repo
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("list migrations at %s: %v", tag, err)
		}
		names = strings.Split(strings.TrimSpace(string(out)), "\n")
	}

	var sql []string
	for _, name := range names {
		if strings.HasSuffix(name, ".sql") {
			sql = append(sql, name)
		}
	}
	if len(sql) == 0 {
		t.Fatalf("no .sql migrations found at %q, so the count this gate compares is zero and "+
			"every claim would pass", tag)
	}
	return sql
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}
