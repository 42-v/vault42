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
// Evidence in the register is `path:line`, and for source files that is fine:
// a Go function moves rarely and the relevance gate next door checks that the
// cited line still mentions what the row says.
//
// For .github/workflows it was not fine. Adding one job to ci.yml shifts every
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
