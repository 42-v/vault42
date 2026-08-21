// Commit-type parity gate.
//
// Two gates decide whether a change may land, and each carries its own copy of
// the list of allowed conventional-commit types:
//
//   - commitlint.config.js `type-enum`, which every commit on a branch is
//     checked against.
//   - .github/workflows/commitlint.yml, whose pr-title job passes a `types:`
//     block to amannn/action-semantic-pull-request, which the PR title is
//     checked against.
//
// The comment above the workflow's list already says these "have to be the same
// list, or the gates contradict each other" -- it was written when `security`
// was added to the config and not to the workflow, so a `security:` title passed
// the commit check and failed the title check. Then `compliance` was added to
// the config and not to the workflow, and the same drift reappeared in the same
// place. A comment asking the next person to remember is not a gate.
//
// This is the gate. It reads both lists and fails when they disagree in either
// direction, so neither can gain a type the other rejects.
//
// The test is read-only. It never writes to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	commitlintConfig   = "commitlint.config.js"
	commitlintWorkflow = ".github/workflows/commitlint.yml"
)

// configTypeLine matches one entry of the type-enum array: a single-quoted type
// followed by a comma, with the trailing // comment ignored.
var configTypeLine = regexp.MustCompile(`^\s*'([a-z]+)',`)

func TestCommitTypeListsAgree(t *testing.T) {
	root := repoRoot(t)

	config := commitlintConfigTypes(t, root)
	workflow := prTitleActionTypes(t, root)

	// Floors first. Two empty lists agree, and would report the same ok as two
	// correct ones.
	if len(config) < 10 {
		t.Fatalf("%s: parsed %d types (%v), expected at least 10 -- the type-enum block "+
			"moved and this gate is reading the wrong thing", commitlintConfig, len(config), config)
	}
	if len(workflow) < 10 {
		t.Fatalf("%s: parsed %d types (%v), expected at least 10 -- the pr-title types "+
			"block moved and this gate is reading the wrong thing", commitlintWorkflow,
			len(workflow), workflow)
	}

	for _, typ := range missing(config, workflow) {
		t.Errorf("%q is allowed by %s but not by %s, so a commit using it lands and a pull "+
			"request titled with it is rejected", typ, commitlintConfig, commitlintWorkflow)
	}
	for _, typ := range missing(workflow, config) {
		t.Errorf("%q is allowed by %s but not by %s, so a pull request may be titled with a "+
			"type none of its commits are allowed to use", typ, commitlintWorkflow, commitlintConfig)
	}
}

// missing reports the entries of a that are not in b.
func missing(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, s := range b {
		have[s] = true
	}
	var out []string
	for _, s := range a {
		if !have[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// commitlintConfigTypes reads the type-enum array out of commitlint.config.js.
// The file is JavaScript with comments between the entries, so this reads the
// bracketed region rather than trying to parse the module.
func commitlintConfigTypes(t *testing.T, root string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, commitlintConfig))
	if err != nil {
		t.Fatalf("read %s: %v", commitlintConfig, err)
	}

	_, after, ok := strings.Cut(string(raw), "'type-enum': [2, 'always', [")
	if !ok {
		t.Fatalf("%s: no type-enum array -- the rule was renamed or reformatted, and this "+
			"gate can no longer see the list it is comparing", commitlintConfig)
	}
	body, _, ok := strings.Cut(after, "]]")
	if !ok {
		t.Fatalf("%s: type-enum array is not closed with ]] as this gate expects", commitlintConfig)
	}

	var out []string
	for _, line := range strings.Split(body, "\n") {
		if m := configTypeLine.FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// prTitleActionTypes reads the `types: |` block the pr-title job hands the
// action. It is a YAML block scalar of one type per line, so the parse is the
// indentation, not a YAML library: pulling in a parser to read four-space
// indented words would be the more fragile of the two.
func prTitleActionTypes(t *testing.T, root string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, commitlintWorkflow))
	if err != nil {
		t.Fatalf("read %s: %v", commitlintWorkflow, err)
	}

	_, after, ok := strings.Cut(string(raw), "types: |\n")
	if !ok {
		t.Fatalf("%s: no `types: |` block in the pr-title job", commitlintWorkflow)
	}

	var out []string
	for _, line := range strings.Split(after, "\n") {
		word := strings.TrimSpace(line)
		// The block ends at the first line that is not an indented bare word.
		if word == "" || !strings.HasPrefix(line, " ") || strings.ContainsAny(word, ":#-") {
			break
		}
		out = append(out, word)
	}
	sort.Strings(out)
	return out
}
