package compliance

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// =============================================================================
// A citation into a workflow has to land on something with a name.
//
// The register's evidence is `path:line`, and the relevance gate next door
// checks two failure modes for it: a line that has gone blank, and a line that
// only closes a block. Both are the shape a citation takes after the file above
// it grew and the number stayed still.
//
// Neither catches the third shape, which is the common one. A citation that
// drifts a few lines lands on a real line of YAML -- `timeout-minutes: 5`,
// `failed=0`, a bare `#` -- and passes, because those lines are neither blank
// nor a closing brace. They are also not evidence of anything. Adding one job
// to ci.yml moved eight citations onto lines like that, and the register went
// on presenting them as the proof of eight requirements.
//
// The rule here is narrow on purpose, because the obvious wider rule is wrong.
// "Cite a job key, a step name or a `uses:`" rejects `cache: false`,
// `contents: read` and `go-version-file: go.mod`, which are three of the best
// citations in the register: each is the substance of the requirement it is
// filed under. Frequency is no better -- `contents: read` appears eleven times
// and is still exactly what Token-Permissions is about.
//
// What actually distinguishes a drifted citation is that it points at a
// container rather than at content. `with:` is not evidence of anything; it
// appears 93 times across these workflows and introduces the block that holds
// the evidence. Neither is `timeout-minutes: 5`, or the `set -euo pipefail`
// that opens most run steps. Those are the lines a number lands on when the
// lines above it moved.
//
// So: reject bare mapping keys and a short list of named boilerplate, and let
// everything with content through. This does not prove a citation is right -- a
// drift from one `run:` to another still passes -- it removes the class where
// the cited line could not have been the intended one under any reading.
// =============================================================================

// workflowCitation matches an evidence entry pointing into .github/workflows.
var workflowCitation = regexp.MustCompile(`^(\.github/workflows/[^:]+\.yml):(\d+)$`)

// containerKey matches a mapping key with nothing after it: the line that opens
// a block rather than the line that says something. A job key like
// `lint-non-go:` is deliberately allowed, because naming a job is naming a
// location; the set below is the keys whose only job is to introduce children.
var containerKeys = map[string]bool{
	"with": true, "env": true, "steps": true, "permissions": true,
	"strategy": true, "matrix": true, "jobs": true, "on": true,
	"outputs": true, "defaults": true, "concurrency": true, "secrets": true,
}

// structuralOnly are lines that parse, carry no identity, and are where a
// drifted citation comes to rest. Listed explicitly so the failure message can
// say which one was hit rather than "did not match a regex".
var structuralOnly = map[string]string{
	"timeout-minutes":   "a timeout is on almost every job; landing on one says nothing about which",
	"runs-on":           "every job has one, and they are all the same value here",
	"shell":             "boilerplate on a run step",
	"set -euo pipefail": "the first line of most scripts in this repository",
	"set -eo pipefail":  "the first line of most scripts in this repository",
	"|":                 "a YAML block scalar introducer",
}

// TestComplianceRegister_WorkflowCitationsLandOnSomethingNamed is the third
// citation gate, after the blank line and the closing brace.
func TestComplianceRegister_WorkflowCitationsLandOnSomethingNamed(t *testing.T) {
	reg := loadRegister(t)
	root := repoRoot(t)

	cache := map[string][]string{}
	checked := 0

	for _, r := range reg.Requirements {
		for _, ev := range r.Evidence {
			m := workflowCitation.FindStringSubmatch(ev)
			if m == nil {
				continue
			}
			relPath, lineText := m[1], m[2]

			lines, ok := cache[relPath]
			if !ok {
				raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
				if err != nil {
					t.Errorf("%s %s cites %s, which does not exist", r.Standard, r.RequirementID, ev)
					continue
				}
				lines = strings.Split(string(raw), "\n")
				cache[relPath] = lines
			}

			line, err := strconv.Atoi(lineText)
			if err != nil || line < 1 || line > len(lines) {
				t.Errorf("%s %s cites %s, which is outside the file", r.Standard, r.RequirementID, ev)
				continue
			}
			checked++

			cited := strings.TrimSpace(lines[line-1])

			// A comment can be evidence -- several rows cite the paragraph that
			// explains why a step exists -- but only if it says something. A
			// bare marker is the same dead end as a closing brace.
			if cited == "#" || cited == "" {
				t.Errorf("%s %s cites %s, which is an empty comment marker. It carries no text "+
					"and no identifier, so a reader following the citation learns nothing.",
					r.Standard, r.RequirementID, ev)
				continue
			}
			if strings.HasPrefix(cited, "#") {
				continue
			}

			key := cited
			if idx := strings.Index(cited, ":"); idx > 0 {
				key = strings.TrimPrefix(cited[:idx], "- ")
			}
			if why, bad := structuralOnly[key]; bad {
				t.Errorf("%s %s cites %s, which is %q -- %s. This is what a citation looks like "+
					"after the lines above it moved: syntactically fine, and not the line anybody "+
					"wrote the citation for.", r.Standard, r.RequirementID, ev, cited, why)
				continue
			}
			if why, bad := structuralOnly[cited]; bad {
				t.Errorf("%s %s cites %s, which is %q -- %s", r.Standard, r.RequirementID, ev, cited, why)
				continue
			}

			if strings.HasSuffix(cited, ":") && containerKeys[strings.TrimSuffix(strings.TrimPrefix(cited, "- "), ":")] {
				t.Errorf("%s %s cites %s, which is %q -- a line that opens a block rather than "+
					"one that says anything. The evidence is inside it, and a citation to the lid "+
					"survives any change to the contents. Cite the line that carries the claim.",
					r.Standard, r.RequirementID, ev, cited)
			}
		}
	}

	if checked < 10 {
		t.Fatalf("only %d workflow citations found; the scan is broken and this gate would pass "+
			"over a register that had none left", checked)
	}
	t.Logf("%d workflow citations resolved to a named line", checked)
}
