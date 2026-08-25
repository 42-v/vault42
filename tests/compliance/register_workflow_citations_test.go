package compliance

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// =============================================================================
// Workflow citations are anchors, not line numbers.
//
// This is where the anchor grammar started. Evidence in the register was
// `path:line` everywhere, and for source files that looked fine: a Go function
// moves rarely and the relevance gate next door checks that the cited line
// still mentions what the row says. It was not fine there either, and
// register_anchors_test.go now applies this file's grammar to the other 98
// cited paths. What stays here is the part that only means something in a
// workflow: `job:`, and the `in:` scope that a job's block defines.
//
// For .github/workflows it was never fine. Adding one job to ci.yml shifts every
// citation below it, and three separate edits in one working session did
// exactly that. The existing gates catch the two shapes where a drifted
// citation lands somewhere obviously dead -- a blank line, a closing brace --
// and cannot catch the third and most common one, where it lands on a real line
// of YAML belonging to an unrelated step. Two rounds of that were found by
// reading all sixteen citations by hand, which is not a gate.
//
// So workflow evidence stops carrying a number. An anchor names what it points
// at, and the only way to break it is to delete the thing it names, which is
// the failure anybody would want reported.
//
//	path#job:<id>              the job key line
//	path#^<prefix>             the unique line starting with <prefix>
//	path#in:<job>:<substring>  the unique line containing <substring>, inside <job>
//	path#<substring>           the unique line containing <substring>
//
// Ambiguity is an error rather than a first-match: an anchor matching four
// lines is not identifying any of them, and the fix is to write a longer one.
//
// The scoping form is a prefix rather than a `<substring>@<job>` suffix,
// because @ is not a rare character in a workflow: every pinned action carries
// one, and so does every image digest and every `image@sha256:` reference. The
// first draft of this used the suffix form and misread three citations, one of
// them looking for a job named "${VAULT_DIGEST}".
// =============================================================================

// workflowEvidence matches an evidence entry pointing into .github/workflows.
var workflowEvidence = regexp.MustCompile(`^(\.github/workflows/[^:#]+\.yml)([:#])(.*)$`)

// jobKey builds the pattern for a job declaration: two spaces, the id, a colon,
// nothing else. Steps are indented further and never match.
func jobKey(id string) *regexp.Regexp {
	return regexp.MustCompile(`^  ` + regexp.QuoteMeta(id) + `:\s*$`)
}

// jobBounds returns the half-open line range of a job's block, or ok=false.
func jobBounds(lines []string, id string) (start, end int, ok bool) {
	key := jobKey(id)
	anyJob := regexp.MustCompile(`^  [a-z0-9][a-z0-9-]*:\s*$`)
	start = -1
	for i, line := range lines {
		if key.MatchString(line) {
			start = i
			break
		}
	}
	if start < 0 {
		return 0, 0, false
	}
	for i := start + 1; i < len(lines); i++ {
		if anyJob.MatchString(lines[i]) {
			return start, i, true
		}
	}
	return start, len(lines), true
}

// resolveAnchor returns the 1-based line numbers an anchor matches.
func resolveAnchor(lines []string, anchor string) (hits []int, err error) {
	switch {
	case strings.HasPrefix(anchor, "job:"):
		id := strings.TrimPrefix(anchor, "job:")
		if id == "" {
			return nil, fmt.Errorf("empty job id")
		}
		key := jobKey(id)
		for i, line := range lines {
			if key.MatchString(line) {
				hits = append(hits, i+1)
			}
		}

	case strings.HasPrefix(anchor, "^"):
		prefix := strings.TrimPrefix(anchor, "^")
		for i, line := range lines {
			if strings.HasPrefix(line, prefix) {
				hits = append(hits, i+1)
			}
		}

	case strings.HasPrefix(anchor, "in:"):
		rest := strings.TrimPrefix(anchor, "in:")
		colon := strings.Index(rest, ":")
		if colon < 1 || colon == len(rest)-1 {
			return nil, fmt.Errorf("in: anchors are in:<job-id>:<substring>")
		}
		job, sub := rest[:colon], rest[colon+1:]
		start, end, ok := jobBounds(lines, job)
		if !ok {
			return nil, fmt.Errorf("no job %q in this workflow", job)
		}
		for i := start; i < end; i++ {
			if strings.Contains(lines[i], sub) {
				hits = append(hits, i+1)
			}
		}

	default:
		for i, line := range lines {
			if strings.Contains(line, anchor) {
				hits = append(hits, i+1)
			}
		}
	}
	return hits, nil
}

// TestComplianceRegister_WorkflowCitationsResolveToExactlyOneLine is the gate.
func TestComplianceRegister_WorkflowCitationsResolveToExactlyOneLine(t *testing.T) {
	reg := loadRegister(t)
	root := repoRoot(t)

	cache := map[string][]string{}
	resolved := 0

	for _, r := range reg.Requirements {
		for _, ev := range r.Evidence {
			m := workflowEvidence.FindStringSubmatch(ev)
			if m == nil {
				continue
			}
			relPath, sep, anchor := m[1], m[2], m[3]

			if sep == ":" {
				t.Errorf("%s %s cites %s by line number. Workflow evidence uses an anchor, "+
					"because a line number in a workflow is invalidated by any job added above "+
					"it -- which happened three times in one working session, twice landing on a "+
					"real line belonging to an unrelated step, where nothing could report it. "+
					"Write %s#<something on the line> instead.",
					r.Standard, r.RequirementID, ev, relPath)
				continue
			}
			if strings.TrimSpace(anchor) == "" {
				t.Errorf("%s %s cites %s with an empty anchor", r.Standard, r.RequirementID, ev)
				continue
			}

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

			hits, err := resolveAnchor(lines, anchor)
			if err != nil {
				t.Errorf("%s %s cites %s: %v", r.Standard, r.RequirementID, ev, err)
				continue
			}

			switch len(hits) {
			case 1:
				resolved++
			case 0:
				t.Errorf("%s %s cites %s and nothing in the file matches the anchor. Either the "+
					"step it named is gone -- in which case the row's evidence is gone with it "+
					"and the row needs re-examining, which is the whole point of failing here -- "+
					"or the line was reworded and the anchor needs the same edit.",
					r.Standard, r.RequirementID, ev)
			default:
				t.Errorf("%s %s cites %s, which matches %d lines (%v). An anchor that matches "+
					"more than one line identifies none of them; lengthen it, or scope it to a "+
					"job with @<job-id>.", r.Standard, r.RequirementID, ev, len(hits), hits)
			}
		}
	}

	if resolved < 20 {
		t.Fatalf("only %d workflow anchors resolved; the scan is broken and this gate would "+
			"pass over a register whose workflow evidence had all gone stale", resolved)
	}
	t.Logf("%d workflow anchors resolved to exactly one line each", resolved)
}

// =============================================================================
// An anchor never carries a version pin.
//
// The grammar above says an anchor breaks only when the thing it names is
// deleted. A pinned reference breaks that promise, because the pin is the one
// part of a `uses:` line that exists in order to move. Dependabot rewrote
//
//	- uses: golangci/golangci-lint-action@4afd733a... # v8
//
// to the v9 sha, the step itself untouched, and three rows -- SSDF PW.5.1,
// SSDF PW.7.1 and Scorecard SAST -- reported their evidence as gone. Nothing
// was gone. The lint job still runs, still on the same line, still proving the
// same three requirements, and the register needed an edit anyway to say so.
// That is the failure this gate exists to prevent, arriving on the one class of
// change that is guaranteed to keep arriving.
//
// So a pin is rejected in the anchor rather than tolerated until it moves. What
// is left, `golangci/golangci-lint-action@`, names the step by the part that
// does not move, and still fails if the step is deleted or renamed.
//
// This is scoped to .github/workflows because that is where every pinned
// reference in the register's evidence lives: `uses:` steps and pinned `go
// install` lines. A cited `FROM image@sha256:` in a Dockerfile would deserve
// the same treatment, and none of the other 98 cited paths pins anything today.
// =============================================================================

// versionPin matches the pin on a dependency reference -- a commit sha, an image
// digest, or a version tag -- introduced by `@` and running to whitespace or the
// end of the anchor. Requiring that boundary is what keeps `evey@42-v.com` and
// `${{ matrix.go }}@...` from reading as pins.
var versionPin = regexp.MustCompile(`@(?:sha256:[0-9a-f]+|[0-9a-f]{7,40}|v?\d+(?:\.\d+)*)(?:\s|$)`)

// TestComplianceRegister_WorkflowAnchorsCarryNoVersionPin is the gate.
func TestComplianceRegister_WorkflowAnchorsCarryNoVersionPin(t *testing.T) {
	reg := loadRegister(t)
	checked := 0

	for _, r := range reg.Requirements {
		for _, ev := range r.Evidence {
			m := workflowEvidence.FindStringSubmatch(ev)
			if m == nil || m[2] != "#" {
				continue
			}
			anchor := m[3]
			checked++

			loc := versionPin.FindStringIndex(anchor)
			if loc == nil {
				continue
			}
			// Keep the `@`, drop the pin and whatever trailed it, which for a
			// pinned action is the `# vN` comment naming the same version again.
			t.Errorf("%s %s cites %s, whose anchor carries the version pin %q. A pin is the "+
				"part of that line meant to move: the next bump rewrites it, the step it names "+
				"stays exactly where it was, and this row would be reported as having lost its "+
				"evidence when it has lost nothing. Anchor the step by what does not move -- "+
				"%s#%s@ -- so the bump lands without a register edit.",
				r.Standard, r.RequirementID, ev,
				strings.TrimSpace(anchor[loc[0]:loc[1]]),
				m[1], strings.TrimSuffix(anchor[:loc[0]], "@"))
		}
	}

	if checked < 20 {
		t.Fatalf("only %d workflow anchors were checked for version pins; the scan is broken "+
			"and this gate would pass over a register full of them", checked)
	}
	t.Logf("%d workflow anchors carry no version pin", checked)
}
