// Published-install-command gate.
//
// The chart job in CI proves that a default `helm install` resolves the image
// tag the release actually pushes. Nothing proved the same thing about the
// install commands published for humans to copy, and they drifted: the landing
// page told readers to run `--set image.tag=v1.0.0` while release.yml pushes
// `ghcr.io/42-v/vault42:1.0.0`, `:latest` and `:sha-...` and has never pushed a
// v-prefixed tag. Copy-pasting the project's own front page produced an
// ImagePullBackOff, which is the exact failure the appVersion fix had just
// closed everywhere else.
//
// scripts/version-bump.sh --check did not catch it because its rule for that
// line matched `--set image.tag=v` literally, so the prefix was baked into the
// definition of correct and every future bump would have recertified it.
//
// This test takes the release workflow's view instead: the only tags that exist
// are the VERSION file's contents, `latest`, and `sha-` builds. Anything a
// tracked document tells a reader to pull must be one of those.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// docsWithInstallCommands are the tracked files that publish a command a reader
// is expected to run verbatim. Listing them explicitly rather than walking the
// whole tree keeps the gate from being defeated by moving a command into a file
// the walk happened not to cover, and makes adding a new published surface a
// deliberate act.
var docsWithInstallCommands = []string{
	"README.md",
	"site/index.html",
	"docs/deployment-guide.md",
	"docs/bridge.md",
	"CONTRIBUTING.md",
	"SECURITY.md",
}

// imageRefs matches both shapes a published pull can take: the fully qualified
// image reference and the Helm value that becomes one.
var imageRefs = []*regexp.Regexp{
	regexp.MustCompile(`ghcr\.io/42-v/vault42:([A-Za-z0-9._-]+)`),
	regexp.MustCompile(`--set\s+image\.tag=([A-Za-z0-9._-]+)`),
}

// publishedTags reports the tag values release.yml actually pushes for the
// version in the VERSION file. Anything outside this set does not exist in the
// registry, whatever a document claims.
func publishedTags(t *testing.T, root string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	version := strings.TrimSpace(string(raw))
	if version == "" {
		t.Fatal("VERSION is empty")
	}
	return map[string]bool{
		version:  true,
		"latest": true,
	}
}

// TestPublishedImageTagsExist fails when a document tells a reader to pull a tag
// the release never publishes.
//
// Template placeholders are allowed through: a document demonstrating the shape
// of a command rather than a runnable one is not making a claim about the
// registry. Everything else has to name a real tag.
func TestPublishedImageTagsExist(t *testing.T) {
	root := repoRoot(t)
	valid := publishedTags(t, root)

	for _, rel := range docsWithInstallCommands {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			// A published surface that has been deleted is a documentation
			// question, not this gate's finding.
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", rel, err)
		}

		lines := strings.Split(string(body), "\n")
		for i, line := range lines {
			for _, re := range imageRefs {
				for _, m := range re.FindAllStringSubmatch(line, -1) {
					tag := m[1]
					switch {
					case valid[tag]:
					case strings.HasPrefix(tag, "sha-"):
					case strings.Contains(tag, "VERSION"), strings.Contains(tag, "X"):
						// A placeholder, not a claim.
					default:
						t.Errorf("%s:%d publishes image tag %q, which the release never pushes; "+
							"release.yml pushes the bare version, latest and sha- builds only",
							rel, i+1, tag)
					}
				}
			}
		}
	}
}

// TestVersionBumpRuleDoesNotBakeInAPrefix stops the generator from recertifying
// a broken tag.
//
// scripts/version-bump.sh drives both propagation and `--check` from one table
// of rules, each a prefix and suffix bracketing the version. A rule whose prefix
// ends in `v` for a value that is published without one will happily write the
// wrong string and then confirm it is correct, which is how the landing page
// stayed wrong through several releases while `--check` reported OK.
func TestVersionBumpRuleDoesNotBakeInAPrefix(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "scripts", "version-bump.sh"))
	if err != nil {
		t.Fatalf("read version-bump.sh: %v", err)
	}

	for i, line := range strings.Split(string(body), "\n") {
		if !strings.Contains(line, "image\\.tag=") {
			continue
		}
		if strings.Contains(line, "image\\.tag=v") {
			t.Errorf("scripts/version-bump.sh:%d brackets the image tag with a v prefix, "+
				"but the registry only ever receives the bare version: %s", i+1, strings.TrimSpace(line))
		}
	}
}
