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
		if !strings.Contains(readFileString(t, filepath.Join(root, file)), upgradingDoc) {
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

	match := schemaCountSentence.FindStringSubmatch(doc)
	if match == nil {
		t.Fatalf("docs/%s no longer carries the sentence this gate reads. It has to keep the "+
			"shape `vX.Y.Z shipped N migrations; this release ships M, so an upgrade applies K`, "+
			"because an upgrade document whose numbers have drifted is read as current.",
			upgradingDoc)
	}
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
