package compliance

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// =============================================================================
// Prose citations, everywhere prose lives.
//
// The register cites code two ways. `evidence` is a list of file references and
// is gated hard. The other way is a sentence: "the session cookie is expired
// with MaxAge -1 on logout (internal/handler/auth.go:307)". Those read as the
// stronger citation, because a reader meets them mid-argument rather than in a
// list, and they were gated in four fields out of a dozen.
//
// The four were the accepted-risk bodies. Not gated: the `notes` on all 456
// requirement rows, which is where most of the register's prose is; the
// `revisit_when` on every risk, which is the field that says what would close
// it; and the retired-risk paragraphs, which are the closure argument itself.
//
// 117 citations were living in those fields unchecked. One had already gone
// stale -- V14.3.1 pointed at a blank line where the logout cookie clear used
// to be, and the code had moved into clearRefreshCookie a hundred lines further
// down. A reader following it landed on nothing, in a sentence claiming the
// server does its half of ASVS V14.3.1.
//
// This gate is deliberately the same shape as the evidence one and no stricter:
// the file exists, the line is in range, the line is not blank and not a lone
// brace. It cannot tell that a citation which still resolves points at the
// wrong code -- that is what reading it does -- but it removes every failure a
// machine can see.
// =============================================================================

// proseField is one citation-bearing string and enough context to name it.
type proseField struct {
	where string
	body  string
}

func registerProseFields(t *testing.T, reg registerFile) []proseField {
	t.Helper()

	fields := make([]proseField, 0,
		len(reg.Requirements)+2*len(reg.AcceptedRisks)+len(reg.RetiredRisks))
	for _, r := range reg.Requirements {
		fields = append(fields, proseField{
			where: r.Standard + " " + r.RequirementID + " notes",
			body:  r.Notes,
		})
	}
	for id, ar := range reg.AcceptedRisks {
		fields = append(fields,
			proseField{id + " revisit_when", ar.RevisitWhen},
			proseField{id + " title", ar.Title},
		)
	}
	for id, prose := range reg.RetiredRisks {
		fields = append(fields, proseField{id + " (retired)", prose})
	}
	return fields
}

// TestComplianceRegister_ProseCitationsResolve covers the fields the
// accepted-risk gate next door does not reach.
func TestComplianceRegister_ProseCitationsResolve(t *testing.T) {
	reg := loadRegister(t)
	root := repoRoot(t)

	cache := map[string][]string{}
	checked := 0

	for _, field := range registerProseFields(t, reg) {
		for _, m := range proseCitation.FindAllStringSubmatch(field.body, -1) {
			relPath, lineText := m[1], m[2]
			line, err := strconv.Atoi(lineText)
			if err != nil {
				continue
			}
			checked++

			lines, ok := cache[relPath]
			if !ok {
				raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
				if readErr != nil {
					t.Errorf("%s cites %s:%d, and the file does not exist",
						field.where, relPath, line)
					cache[relPath] = nil
					continue
				}
				lines = strings.Split(string(raw), "\n")
				cache[relPath] = lines
			}
			if lines == nil {
				continue
			}

			if line < 1 || line > len(lines) {
				t.Errorf("%s cites %s:%d, but the file has %d lines",
					field.where, relPath, line, len(lines))
				continue
			}

			text := strings.TrimSpace(lines[line-1])
			if text == "" {
				t.Errorf("%s cites %s:%d, which is a blank line. The sentence around it makes a "+
					"claim about code, and the code it named is not there any more.",
					field.where, relPath, line)
				continue
			}
			if _, dead := citationDeadEnds[text]; dead {
				t.Errorf("%s cites %s:%d, which is %q -- a line that closes a block rather than "+
					"doing anything. Cite the statement.", field.where, relPath, line, text)
			}
		}
	}

	if checked < 50 {
		t.Fatalf("only %d prose citations found across notes, revisit_when and retired risks; "+
			"the scan is broken and this gate would pass over a register whose prose had gone "+
			"stale everywhere", checked)
	}
	t.Logf("%d prose citations resolved across notes, revisit_when and retired risks", checked)
}
