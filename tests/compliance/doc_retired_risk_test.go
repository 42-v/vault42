package compliance

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A risk the register has retired must not still be listed as open in
// docs/COMPLIANCE.md.
//
// Three rows drifted this way at once. CR-15, CR-21 and CR-23 each sat in the
// open accepted-risk table under a body whose own first sentence said the risk
// was closed in the code -- "Closed in the code, still open in the register" --
// while the register had already moved all three into retired_risks. The
// document argued against its own table, and the closed-risks section two
// screens below listed six closures when there were eight.
//
// Nothing caught it because the existing count gate greps the document for the
// headline totals, which come from the requirements array and never mentioned
// the accepted-risk tables at all.
//
// The direction matters. This fails on a risk the register calls retired that
// the document still lists as open, and not the reverse: a row can legitimately
// stay open in the document while the owning stream decides, and the register is
// the authority on retirement, not the prose.
func TestComplianceDocDoesNotCarryARetiredRiskAsOpen(t *testing.T) {
	root := repoRoot(t)
	reg := loadRegister(t)

	retired := map[string]bool{}
	for id := range reg.RetiredRisks {
		retired[id] = true
	}
	if len(retired) == 0 {
		t.Fatal("the register declares no retired risks, so this gate would pass vacuously. " +
			"If retired_risks was renamed, move this check to whatever replaced it.")
	}

	raw, err := os.ReadFile(filepath.Join(root, "docs", "COMPLIANCE.md"))
	if err != nil {
		t.Fatalf("read docs/COMPLIANCE.md: %v", err)
	}
	doc := string(raw)

	// The closed-risks section is where a retired risk belongs, so only the text
	// above it is the "open" table.
	const closedHeading = "### Closed since this document was first written"
	cut := strings.Index(doc, closedHeading)
	if cut < 0 {
		t.Fatalf("docs/COMPLIANCE.md has no %q section. It is what tells an open row from a "+
			"closed one; without it this gate cannot tell them apart either.", closedHeading)
	}
	openPart := doc[:cut]

	row := regexp.MustCompile(`(?m)^\|\s*\*\*(CR-\d+)\*\*\s*\|`)
	for _, m := range row.FindAllStringSubmatch(openPart, -1) {
		id := m[1]
		if retired[id] {
			t.Errorf("docs/COMPLIANCE.md lists %s in the open accepted-risk table, but the "+
				"register carries it in retired_risks. Move the row into %q with what closed it "+
				"and the test that fired, rather than leaving a row that contradicts the "+
				"register a reader is told is authoritative.", id, closedHeading)
		}
	}
}
