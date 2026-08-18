package compliance

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// =============================================================================
// The compliance register gate.
//
// docs/compliance-register.json is the enumeration that docs/COMPLIANCE.md
// summarizes. Through 0.9.9 the report claimed 242 requirements met and listed
// none of them, and reported "94.2% weighted coverage" with no published
// weighting model and no denominator anyone could check. Both claims were
// unfalsifiable, which is the first thing a hostile reader finds.
//
// A register alone would only be a longer claim. What turns it into a control
// is this file: a Met row that names a test which does not exist fails the
// build, so the register cannot drift from the suite. That is the assertion the
// whole compliance posture rests on, and it is the reason the posture is
// stated as "every Met requirement names a passing CI check" rather than as a
// percentage.
//
// To run only this gate:
//
//	go test ./tests/compliance/ -run TestComplianceRegister
//
// =============================================================================

type registerFile struct {
	Meta struct {
		Product         string `json:"product"`
		Version         string `json:"version"`
		AssessmentType  string `json:"assessment_type"`
		ThirdPartyAudit bool   `json:"third_party_audit"`
		Scope           struct {
			InScope    []string `json:"in_scope"`
			OutOfScope []string `json:"out_of_scope"`
			ASVSLevel  string   `json:"asvs_level"`
		} `json:"scope"`
		Claim string `json:"claim"`
	} `json:"meta"`
	Standards []struct {
		Name      string `json:"name"`
		ShortName string `json:"short_name"`
		Revision  string `json:"revision"`
		Source    string `json:"source"`
		Verified  string `json:"verified"`
	} `json:"standards"`
	AcceptedRisks map[string]struct {
		Title               string `json:"title"`
		Severity            string `json:"severity"`
		AcceptedBy          string `json:"accepted_by"`
		AcceptedOn          string `json:"accepted_on"`
		Rationale           string `json:"rationale"`
		CompensatingControl string `json:"compensating_control"`
		ResidualRisk        string `json:"residual_risk"`
		RevisitWhen         string `json:"revisit_when"`
		CostOfClosing       string `json:"cost_of_closing"`
		SecurityMd          string `json:"security_md"`
	} `json:"accepted_risks"`
	// RetiredRisks records register identifiers that have closed. A reference to
	// one has to resolve to something, or "CR-16 has since closed" is a dangling
	// pointer wearing a status report's clothes.
	RetiredRisks map[string]string `json:"retired_risks"`
	Requirements []struct {
		Standard      string   `json:"standard"`
		Revision      string   `json:"revision"`
		RequirementID string   `json:"requirement_id"`
		Requirement   string   `json:"requirement"`
		Level         string   `json:"level"`
		Status        string   `json:"status"`
		Evidence      []string `json:"evidence"`
		Tests         []string `json:"tests"`
		Notes         string   `json:"notes"`
		AcceptedRisk  string   `json:"accepted_risk"`
		// NABasis names the kind of reason a Not Applicable row rests on. See
		// naBases in register_gates_test.go: leaving it unstated is how a claim
		// about the code came to read like a claim about scope.
		NABasis string `json:"na_basis"`
	} `json:"requirements"`
}

const (
	statusMet      = "Met"
	statusAccepted = "Accepted Risk"
	statusNA       = "Not Applicable"
)

func loadRegister(t *testing.T) registerFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "compliance-register.json"))
	if err != nil {
		t.Fatalf("read compliance register: %v", err)
	}
	var reg registerFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reg); err != nil {
		// Unknown fields are informative rather than fatal: the register may
		// carry per-row detail this gate does not read.
		if err := json.Unmarshal(raw, &reg); err != nil {
			t.Fatalf("parse compliance register: %v", err)
		}
	}
	if len(reg.Requirements) == 0 {
		t.Fatal("the compliance register contains no requirements")
	}
	return reg
}

// complianceTestNames returns every Test function declared in this package.
func complianceTestNames(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "tests", "compliance")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read tests/compliance: %v", err)
	}

	names := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			names[fn.Name.Name] = entry.Name()
		}
	}
	if len(names) < 50 {
		t.Fatalf("only %d test functions found in tests/compliance; the scan is broken", len(names))
	}
	return names
}

// --- The gate ---

// This is the check the compliance claim rests on. A Met row that names a test
// which does not exist is a claim with no evidence behind it, and it must break
// the build rather than sit in a document.
func TestComplianceRegister_EveryMetRequirementNamesAnExistingTest(t *testing.T) {
	reg := loadRegister(t)
	existing := complianceTestNames(t)

	met, named := 0, 0
	for _, r := range reg.Requirements {
		if r.Status != statusMet {
			continue
		}
		met++
		if len(r.Tests) == 0 {
			t.Errorf("%s %s is marked Met but names no test", r.Standard, r.RequirementID)
			continue
		}
		for _, name := range r.Tests {
			named++
			if _, ok := existing[name]; !ok {
				t.Errorf("%s %s is marked Met and names %s, which does not exist in tests/compliance/", r.Standard, r.RequirementID, name)
			}
		}
	}

	if met == 0 {
		t.Fatal("the register contains no Met requirements; the gate would be vacuous")
	}
	t.Logf("%d Met requirements checked, %d test references resolved", met, named)
}

// A test that is named as evidence and then skipped unconditionally proves
// nothing. Skips that depend on a runtime condition (no container runtime, a
// restructured code path) are legitimate and are not flagged.
func TestComplianceRegister_NamedTestsAreNotUnconditionallySkipped(t *testing.T) {
	reg := loadRegister(t)
	dir := filepath.Join(repoRoot(t), "tests", "compliance")

	cited := map[string]bool{}
	for _, r := range reg.Requirements {
		if r.Status == statusMet {
			for _, name := range r.Tests {
				cited[name] = true
			}
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read tests/compliance: %v", err)
	}
	// A directory listing that comes back short means the walk, not the suite,
	// changed. Every assertion below is inside the loop, so an empty listing
	// would report success for a scan that never ran.
	if len(entries) < 20 {
		t.Fatalf("only %d entries in tests/compliance; the listing is broken and this gate would pass vacuously", len(entries))
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !cited[fn.Name.Name] {
				continue
			}
			for _, stmt := range fn.Body.List {
				expr, ok := stmt.(*ast.ExprStmt)
				if !ok {
					break // the first non-call statement means the skip is conditional
				}
				call, ok := expr.X.(*ast.CallExpr)
				if !ok {
					break
				}
				if name := callName(call); name == "Skip" || name == "Skipf" || name == "SkipNow" {
					t.Errorf("%s (%s) is cited as evidence for a Met requirement but skips unconditionally", fn.Name.Name, entry.Name())
				}
				break
			}
		}
	}
}

// --- The claim shape ---

// The claim is that nothing is unclassified. That is only checkable if the
// status vocabulary is closed, so an unrecognized status is a failure rather
// than a pass-through. "Partial" in particular must never reappear: it names a
// finding with no owner, no rationale and no revisit date, which is what the
// register replaced.
func TestComplianceRegister_StatusVocabularyIsClosed(t *testing.T) {
	reg := loadRegister(t)
	allowed := map[string]bool{statusMet: true, statusAccepted: true, statusNA: true}

	counts := map[string]int{}
	for _, r := range reg.Requirements {
		if !allowed[r.Status] {
			t.Errorf("%s %s carries status %q, which is outside the {Met, Accepted Risk, Not Applicable} vocabulary", r.Standard, r.RequirementID, r.Status)
			continue
		}
		counts[r.Status]++
	}

	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%-16s %d", k, counts[k])
	}
	t.Logf("%-16s %d", "TOTAL", len(reg.Requirements))
}

// An accepted risk without an argument is an excuse. Each one has to name what
// is accepted, what compensates for it, what remains, when the decision is
// revisited, and who accepted it.
func TestComplianceRegister_AcceptedRisksAreFullyArgued(t *testing.T) {
	reg := loadRegister(t)

	referenced := map[string]bool{}
	for _, r := range reg.Requirements {
		if r.Status != statusAccepted {
			continue
		}
		if r.AcceptedRisk == "" {
			t.Errorf("%s %s is an Accepted Risk with no accepted_risk identifier", r.Standard, r.RequirementID)
			continue
		}
		if _, ok := reg.AcceptedRisks[r.AcceptedRisk]; !ok {
			t.Errorf("%s %s references %s, which is not defined in accepted_risks", r.Standard, r.RequirementID, r.AcceptedRisk)
			continue
		}
		if strings.TrimSpace(r.Notes) == "" {
			t.Errorf("%s %s is an Accepted Risk with no per-requirement rationale", r.Standard, r.RequirementID)
		}
		referenced[r.AcceptedRisk] = true
	}

	for id, ar := range reg.AcceptedRisks {
		for _, field := range []struct{ name, value string }{
			{"title", ar.Title},
			{"severity", ar.Severity},
			{"accepted_by", ar.AcceptedBy},
			{"accepted_on", ar.AcceptedOn},
			{"rationale", ar.Rationale},
			{"compensating_control", ar.CompensatingControl},
			{"residual_risk", ar.ResidualRisk},
			{"revisit_when", ar.RevisitWhen},
		} {
			if strings.TrimSpace(field.value) == "" {
				t.Errorf("%s has an empty %s; an accepted risk without one is an excuse, not a decision", id, field.name)
			}
		}
		if !referenced[id] {
			t.Errorf("%s is defined in accepted_risks but no requirement references it", id)
		}
	}

	if len(reg.AcceptedRisks) == 0 {
		t.Error("the register declares no accepted risks at all, which for a system of this scope means the assessment is not honest rather than that the system is perfect")
	}
}

// Every Not Applicable row has to say why. "Not applicable" with no reason is
// indistinguishable from "not assessed", and the difference is the whole point.
func TestComplianceRegister_NotApplicableRowsCarryAReason(t *testing.T) {
	reg := loadRegister(t)
	for _, r := range reg.Requirements {
		if r.Status != statusNA {
			continue
		}
		if len(strings.Fields(r.Notes)) < 5 {
			t.Errorf("%s %s is Not Applicable with no substantive reason: %q", r.Standard, r.RequirementID, r.Notes)
		}
	}
}

// Duplicate identifiers within a standard would let the same requirement be
// counted twice, or classified two different ways. Through 0.9.9 exactly that
// happened: the audit-integrity finding was filed as both AU-9 and GDPR-14.
func TestComplianceRegister_RequirementIDsAreUniquePerStandard(t *testing.T) {
	reg := loadRegister(t)
	seen := map[string]string{}
	for _, r := range reg.Requirements {
		key := r.Standard + "|" + r.RequirementID
		if prior, dup := seen[key]; dup {
			t.Errorf("%s %s appears more than once (%q and %q)", r.Standard, r.RequirementID, prior, r.Requirement)
		}
		seen[key] = r.Requirement
	}
}

// Every row must be traceable to a declared standard revision, and every
// declared revision must carry the note recording how it was verified. The
// report's previous NIST section cited the withdrawn revision's title while its
// tests linked the current revision's URL; recording the verification per
// standard is what makes that contradiction impossible to reintroduce silently.
func TestComplianceRegister_EveryRowBelongsToADeclaredStandard(t *testing.T) {
	reg := loadRegister(t)

	declared := map[string]bool{}
	for _, s := range reg.Standards {
		if strings.TrimSpace(s.Source) == "" {
			t.Errorf("standard %q declares no source URL", s.Name)
		}
		if strings.TrimSpace(s.Verified) == "" {
			t.Errorf("standard %q records no note on how its revision was verified", s.Name)
		}
		if strings.TrimSpace(s.ShortName) == "" {
			t.Errorf("standard %q declares no short_name, so no requirement row can key on it", s.Name)
			continue
		}
		declared[s.ShortName] = true
	}

	// Every row keys on a declared short name, so the two lists cannot drift.
	for _, r := range reg.Requirements {
		if !declared[r.Standard] {
			t.Errorf("requirement %s %s belongs to no declared standard", r.Standard, r.RequirementID)
		}
	}
}

// The scope boundary and the self-assessment disclosure are load-bearing: an
// assessment that does not say what it excluded, or that lets a reader infer a
// third-party audit, is worse than no assessment.
func TestComplianceRegister_ScopeAndSelfAssessmentAreDeclared(t *testing.T) {
	reg := loadRegister(t)

	if reg.Meta.AssessmentType != "self-assessment" {
		t.Errorf("assessment_type is %q; if this ever becomes a third-party assessment the evidence for that has to arrive with the change", reg.Meta.AssessmentType)
	}
	if reg.Meta.ThirdPartyAudit {
		t.Error("third_party_audit is true but no audit report is referenced")
	}
	if len(reg.Meta.Scope.InScope) == 0 {
		t.Error("the register declares no in-scope components")
	}
	if len(reg.Meta.Scope.OutOfScope) == 0 {
		t.Error("the register declares nothing out of scope, which for this repository is not credible: the frontend and the SDKs are separate deliverables")
	}
	if reg.Meta.Scope.ASVSLevel == "" {
		t.Error("the register declares no ASVS level, so the denominator for the ASVS rows is undefined")
	}
	if !strings.Contains(reg.Meta.Claim, "Met") || !strings.Contains(reg.Meta.Claim, "Accepted Risk") {
		t.Error("the published claim no longer describes the classification vocabulary")
	}
}

// docs/COMPLIANCE.md summarizes the register. If the two disagree on the
// counts, the document is the one a reader sees and the register is the one
// that is true, so the disagreement has to fail rather than be discovered.
func TestComplianceRegister_ComplianceDocumentCountsMatchTheRegister(t *testing.T) {
	reg := loadRegister(t)
	doc := readProductionSource(t, "docs/COMPLIANCE.md")

	counts := map[string]int{}
	for _, r := range reg.Requirements {
		counts[r.Status]++
	}

	for _, c := range []struct {
		label string
		count int
	}{
		{"Met", counts[statusMet]},
		{"Accepted Risk", counts[statusAccepted]},
		{"Not Applicable", counts[statusNA]},
	} {
		if !strings.Contains(doc, itoa(c.count)+" "+c.label) {
			t.Errorf("docs/COMPLIANCE.md does not state %q; the register and the report disagree", itoa(c.count)+" "+c.label)
		}
	}

	// A percentage is exactly the unfalsifiable claim shape the register
	// replaced, so its reappearance is a regression. The patterns are the claim
	// forms the 0.9.9 report used, not the word "coverage": the report is
	// allowed, and expected, to quote what it removed and say why.
	for _, banned := range []string{
		"Overall weighted coverage",
		"| Coverage % |",
		"**Coverage:",
	} {
		if strings.Contains(doc, banned) {
			t.Errorf("docs/COMPLIANCE.md has reintroduced the claim shape %q; the register publishes no weighting model, so a percentage would be unfalsifiable", banned)
		}
	}
	if strings.Contains(doc, "| Partial |") || strings.Contains(doc, "**Partial**") {
		t.Error("docs/COMPLIANCE.md has reintroduced the Partial status, which names a finding with no owner and no revisit date")
	}
}
