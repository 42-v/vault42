package compliance

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// =============================================================================
// Code evidence is anchored, not numbered.
//
// Every evidence reference in the register used to be `path:line`, and a line
// number is invalidated by any edit above it. Three separate citations broke
// that way in one working session: ASVS V9.1.2 drifted onto a bare `}` after
// internal/jwt/parse.go changed, V10.3.4 and OWASP API1:2023 drifted onto a `)`
// and a comment, and V5.1.1 landed on a blank line after docs/api.md was
// edited. Each one was re-derived by hand. Two gates catch the shapes that land
// somewhere obviously dead -- a blank line, a closing brace -- and neither
// catches the common case, where the citation lands on a real line belonging to
// something else entirely.
//
// .github/workflows solved this first, in register_workflow_citations_test.go:
// evidence there names a line rather than counting to it, and cannot drift by
// construction. This applies the same grammar to the other 98 cited paths.
//
//	path                       the whole file, no anchor
//	path#<substring>           the unique line containing <substring>
//	path#^<prefix>             the unique line starting with <prefix>
//	path#in:<decl>:<substring> the unique line containing <substring>, inside
//	                           the Go declaration named <decl>
//
// Two rules make the grammar worth having, and both are copied from the
// workflow gate rather than reinvented:
//
//   - An anchor matching more than one line is an error, not a first match. An
//     anchor that identifies four lines identifies none of them, and taking the
//     first is how a citation silently points at the wrong one of two identical
//     statements in two different functions.
//   - An anchor matching nothing names the requirement and the anchor, because
//     the thing it named is gone and a person has to decide what that means for
//     the row -- which is the whole reason to fail here rather than to guess.
//
// `in:` scopes to a Go declaration and only to a Go declaration. A repeated
// line in YAML has no equivalent named scope, so the fix there is to cite a line
// that identifies itself, and the gate's own error message says so. Three
// citations would have been served by a YAML scope; each of the three had a
// nearby line that identifies itself and says the same thing, which is a
// cheaper answer than a second scope language.
//
// The migration is complete, so `path:line` is rejected outright rather than
// accepted alongside the anchors. A gate that tolerates the old form for a
// while is a migration that never finishes.
// =============================================================================

// anchoredEvidence splits `path#anchor`. The path cannot contain a `#`, so the
// first one is the separator and every later one belongs to the anchor -- which
// matters, because a cited line of YAML or Markdown often carries one.
var anchoredEvidence = regexp.MustCompile(`^([^#]+)#(.*)$`)

// numberedEvidence matches the form this gate exists to reject.
var numberedEvidence = regexp.MustCompile(`^(.+):(\d+)$`)

// workflowEvidencePath is the prefix the workflow gate owns. Its anchors carry
// a `job:` form that only means something in a workflow, so the two gates split
// the register by path rather than both reporting on the same entry.
const workflowEvidencePath = ".github/workflows/"

// declSpan is one Go declaration's line range, 1-based and inclusive. The doc
// comment counts as part of the declaration: a citation onto the sentence that
// explains a function is a citation into that function, and treating it as
// unscoped would make `in:` useless for exactly the lines most worth citing.
type declSpan struct{ start, end int }

// anchorIndex caches file contents and declaration spans. The register carries
// 460 anchored references across 98 files and two gates resolve all of them, so
// each file is read once and parsed at most once.
type anchorIndex struct {
	root   string
	lines  map[string][]string
	spans  map[string]map[string][]declSpan
	parsed map[string]bool
}

func newAnchorIndex(root string) *anchorIndex {
	return &anchorIndex{
		root:   root,
		lines:  map[string][]string{},
		spans:  map[string]map[string][]declSpan{},
		parsed: map[string]bool{},
	}
}

func (ix *anchorIndex) file(relPath string) ([]string, error) {
	if lines, ok := ix.lines[relPath]; ok {
		if lines == nil {
			return nil, fmt.Errorf("%s does not exist", relPath)
		}
		return lines, nil
	}
	raw, err := os.ReadFile(filepath.Join(ix.root, filepath.FromSlash(relPath)))
	if err != nil {
		ix.lines[relPath] = nil
		return nil, fmt.Errorf("%s does not exist", relPath)
	}
	lines := strings.Split(string(raw), "\n")
	ix.lines[relPath] = lines
	return lines, nil
}

// declSpans indexes a Go file's top-level declarations by name. A method is
// keyed as (Receiver).Method, because two types in one file may each declare a
// Validate and a bare name would silently pick one of them.
func (ix *anchorIndex) declSpans(relPath string) map[string][]declSpan {
	if ix.parsed[relPath] {
		return ix.spans[relPath]
	}
	ix.parsed[relPath] = true
	spans := map[string][]declSpan{}
	ix.spans[relPath] = spans

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(ix.root, filepath.FromSlash(relPath)), nil, parser.ParseComments)
	if err != nil {
		// A file that does not parse cannot be scoped. The anchor forms that do
		// not need a scope still work, and `in:` reports the empty index.
		return spans
	}
	add := func(name string, start, end token.Pos, doc *ast.CommentGroup) {
		if name == "" || name == "_" {
			return
		}
		from := fset.Position(start).Line
		if doc != nil {
			from = fset.Position(doc.Pos()).Line
		}
		spans[name] = append(spans[name], declSpan{start: from, end: fset.Position(end).Line})
	}
	for _, d := range file.Decls {
		switch decl := d.(type) {
		case *ast.FuncDecl:
			add(funcSpanName(decl), decl.Pos(), decl.End(), decl.Doc)
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				doc := specDoc(spec)
				if len(decl.Specs) == 1 && doc == nil {
					doc = decl.Doc
				}
				for _, name := range specNames(spec) {
					add(name, spec.Pos(), spec.End(), doc)
				}
			}
		}
	}
	return spans
}

func funcSpanName(decl *ast.FuncDecl) string {
	if decl.Recv == nil || len(decl.Recv.List) != 1 {
		return decl.Name.Name
	}
	return "(" + receiverTypeName(decl.Recv.List[0].Type) + ")." + decl.Name.Name
}

// receiverTypeName renders the base type of a receiver, dropping the pointer
// and any type parameters: (*RefreshTokenRepo) and (Repo[T]) both key on the
// bare name, which is how a reader would write it.
func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.IndexExpr:
		return receiverTypeName(t.X)
	case *ast.IndexListExpr:
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}

func specNames(spec ast.Spec) []string {
	switch s := spec.(type) {
	case *ast.TypeSpec:
		return []string{s.Name.Name}
	case *ast.ValueSpec:
		out := make([]string, 0, len(s.Names))
		for _, n := range s.Names {
			out = append(out, n.Name)
		}
		return out
	}
	return nil
}

func specDoc(spec ast.Spec) *ast.CommentGroup {
	switch s := spec.(type) {
	case *ast.TypeSpec:
		return s.Doc
	case *ast.ValueSpec:
		return s.Doc
	}
	return nil
}

// resolve returns the 1-based line numbers an anchor matches.
func (ix *anchorIndex) resolve(relPath, anchor string) ([]int, error) {
	lines, err := ix.file(relPath)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(anchor) == "" {
		return nil, fmt.Errorf("the anchor is empty")
	}

	var hits []int
	switch {
	case strings.HasPrefix(anchor, "in:"):
		rest := strings.TrimPrefix(anchor, "in:")
		colon := strings.Index(rest, ":")
		if colon < 1 || colon == len(rest)-1 {
			return nil, fmt.Errorf("in: anchors are in:<declaration>:<substring>")
		}
		name, sub := rest[:colon], rest[colon+1:]
		if !strings.HasSuffix(relPath, ".go") {
			return nil, fmt.Errorf("in: scopes a Go declaration and %s is not Go. "+
				"Cite a line that identifies itself instead", relPath)
		}
		spans := ix.declSpans(relPath)[name]
		switch len(spans) {
		case 1:
		case 0:
			return nil, fmt.Errorf("no declaration named %q in this file. Methods are keyed "+
				"as (Receiver).Method", name)
		default:
			return nil, fmt.Errorf("%q is declared %d times in this file, so the scope names "+
				"none of them", name, len(spans))
		}
		for i := spans[0].start; i <= spans[0].end && i <= len(lines); i++ {
			if strings.Contains(lines[i-1], sub) {
				hits = append(hits, i)
			}
		}

	case strings.HasPrefix(anchor, "^"):
		prefix := strings.TrimPrefix(anchor, "^")
		for i, line := range lines {
			if strings.HasPrefix(line, prefix) {
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

// evidenceTarget resolves one evidence entry to the line it names.
//
// ok is false for a whole-file citation, for workflow evidence, and for an
// anchor that does not resolve to exactly one line -- the last because the gate
// below already reports it by name, and a second gate reporting the same entry
// through a different message teaches a reader that one of them is noise.
func evidenceTarget(ix *anchorIndex, ev string) (relPath string, line int, ok bool) {
	if strings.HasPrefix(ev, workflowEvidencePath) {
		return "", 0, false
	}
	if m := anchoredEvidence.FindStringSubmatch(ev); m != nil {
		hits, err := ix.resolve(m[1], m[2])
		if err != nil || len(hits) != 1 {
			return m[1], 0, false
		}
		return m[1], hits[0], true
	}
	// A line number is rejected by the gate below. It is still resolved here so
	// that the relevance gate keeps reporting on it rather than falling silent
	// on the one shape it was written for.
	if m := numberedEvidence.FindStringSubmatch(ev); m != nil {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			return "", 0, false
		}
		return m[1], n, true
	}
	return ev, 0, false
}

// TestComplianceRegister_EvidenceAnchorsResolveToExactlyOneLine is the gate.
func TestComplianceRegister_EvidenceAnchorsResolveToExactlyOneLine(t *testing.T) {
	reg := loadRegister(t)
	ix := newAnchorIndex(repoRoot(t))

	resolved, wholeFile := 0, 0
	for _, r := range reg.Requirements {
		for _, ev := range r.Evidence {
			// The workflow gate owns an anchored or numbered workflow citation,
			// under a grammar with a `job:` form this resolver does not have. It
			// does not own a workflow file cited whole, because its own regex
			// requires the separator -- three of those were checked by nobody
			// until this branch stopped skipping them.
			if strings.HasPrefix(ev, workflowEvidencePath) && strings.ContainsAny(ev, "#:") {
				continue
			}

			m := anchoredEvidence.FindStringSubmatch(ev)
			if m == nil {
				if numberedEvidence.MatchString(ev) {
					t.Errorf("%s %s cites %s by line number. Code evidence is an anchor, because a "+
						"line number is invalidated by any edit above it -- which broke three "+
						"citations in one working session, one of them landing on a bare closing "+
						"brace and one on a blank line. Write path#<something on the line> instead, "+
						"or run scripts/register-reanchor.py --apply to convert it.",
						r.Standard, r.RequirementID, ev)
					continue
				}
				// A whole-file citation names no line and cannot drift, but the
				// path still has to be there. Four rows cite a directory rather
				// than a file -- tests/fuzz, internal/ -- and a stat accepts
				// both, where reading the bytes would reject the directory.
				if _, err := os.Stat(filepath.Join(repoRoot(t), filepath.FromSlash(ev))); err != nil {
					t.Errorf("%s %s cites %s, which does not exist", r.Standard, r.RequirementID, ev)
					continue
				}
				wholeFile++
				continue
			}

			relPath, anchor := m[1], m[2]
			hits, err := ix.resolve(relPath, anchor)
			if err != nil {
				t.Errorf("%s %s cites %s: %v", r.Standard, r.RequirementID, ev, err)
				continue
			}

			switch len(hits) {
			case 1:
				resolved++
			case 0:
				t.Errorf("%s %s cites %s and nothing in %s matches the anchor %q. Either the "+
					"statement it named is gone -- in which case the row's evidence is gone with it "+
					"and the row needs re-examining, which is the whole point of failing here -- or "+
					"the line was reworded and the anchor needs the same edit.",
					r.Standard, r.RequirementID, ev, relPath, anchor)
			default:
				t.Errorf("%s %s cites %s, and the anchor %q matches %d lines (%v). An anchor that "+
					"matches more than one line identifies none of them: lengthen it, prefix it "+
					"with ^ to pin the indentation, or scope it to a Go declaration with "+
					"in:<declaration>:<substring>.",
					r.Standard, r.RequirementID, ev, anchor, len(hits), hits)
			}
		}
	}

	// A floor over the whole corpus. Every assertion above is inside the loop, so
	// a register whose evidence had all gone missing would report success for a
	// scan that never ran.
	if resolved < 400 {
		t.Fatalf("only %d code anchors resolved; the register carries over 400 and the scan is "+
			"broken", resolved)
	}
	t.Logf("%d code anchors resolved to exactly one line each, %d whole-file citations checked",
		resolved, wholeFile)
}

// TestComplianceRegister_AnchorsSurviveLineMovement is the property the whole
// grammar exists for, asserted rather than assumed.
//
// It re-resolves every anchor against a copy of its file with a comment block
// inserted at the top. Under `path:line` every one of those citations would now
// be off by the number of lines inserted; under an anchor the resolved line
// moves by exactly that much and still names the same text. A gate that only
// checked today's tree would pass just as happily over a scheme that drifts.
func TestComplianceRegister_AnchorsSurviveLineMovement(t *testing.T) {
	reg := loadRegister(t)
	root := repoRoot(t)
	ix := newAnchorIndex(root)

	const shift = 7
	padding := make([]string, shift)
	for i := range padding {
		padding[i] = "// inserted by TestComplianceRegister_AnchorsSurviveLineMovement"
	}

	checked := 0
	for _, r := range reg.Requirements {
		for _, ev := range r.Evidence {
			if strings.HasPrefix(ev, workflowEvidencePath) {
				continue
			}
			m := anchoredEvidence.FindStringSubmatch(ev)
			if m == nil {
				continue
			}
			relPath, anchor := m[1], m[2]
			before, err := ix.resolve(relPath, anchor)
			if err != nil || len(before) != 1 {
				continue // reported by the gate above
			}

			original, err := ix.file(relPath)
			if err != nil {
				continue
			}
			shifted := newAnchorIndex(root)
			shifted.lines[relPath] = append(append([]string{}, padding...), original...)
			// The declaration index comes from the file on disk, so it is moved by
			// hand here rather than reparsed: an `in:` anchor has to survive the
			// shift too, and skipping those would leave the scoped form untested.
			shifted.parsed[relPath] = true
			shifted.spans[relPath] = shiftSpans(ix.declSpans(relPath), shift)

			after, err := shifted.resolve(relPath, anchor)
			if err != nil {
				t.Errorf("%s %s: anchor %q stopped resolving once %d lines were inserted above it: %v",
					r.Standard, r.RequirementID, ev, shift, err)
				continue
			}
			if len(after) != 1 || after[0] != before[0]+shift {
				t.Errorf("%s %s: %s resolved to line %d, and to %v after %d lines were inserted at "+
					"the top of the file. An anchor has to name its line rather than count to it.",
					r.Standard, r.RequirementID, ev, before[0], after, shift)
				continue
			}
			checked++
		}
	}

	if checked < 400 {
		t.Fatalf("only %d anchors were re-resolved against a shifted file; the scan is broken", checked)
	}
	t.Logf("%d anchors resolved to the same statement after %d lines were inserted above them",
		checked, shift)
}

// shiftSpans moves every declaration span down by n lines.
func shiftSpans(spans map[string][]declSpan, n int) map[string][]declSpan {
	out := make(map[string][]declSpan, len(spans))
	for name, list := range spans {
		moved := make([]declSpan, 0, len(list))
		for _, s := range list {
			moved = append(moved, declSpan{start: s.start + n, end: s.end + n})
		}
		out[name] = moved
	}
	return out
}

// TestComplianceRegister_AnchorGrammarRejectsAmbiguity holds the resolver to the
// two properties the gate's usefulness rests on: an anchor matching several
// lines resolves to none of them, and a scope naming nothing is an error rather
// than an empty search that reports zero hits the same way a deleted statement
// does.
//
// These are asserted against a fixture rather than against the tree, because
// the tree is required to contain no such anchor -- so the gate above can never
// exercise the branch that would report one.
func TestComplianceRegister_AnchorGrammarRejectsAmbiguity(t *testing.T) {
	ix := newAnchorIndex(repoRoot(t))
	const fixture = "internal/fixture_for_anchor_grammar.go"
	ix.lines[fixture] = []string{
		"package fixture",
		"",
		"func First() {",
		"\tuse(shared)",
		"}",
		"",
		"func Second() {",
		"\tuse(shared)",
		"}",
	}
	// Spans are what the on-disk parse would produce for the lines above; the
	// fixture never touches the filesystem, so they are stated here.
	ix.parsed[fixture] = true
	ix.spans[fixture] = map[string][]declSpan{
		"First":  {{start: 3, end: 5}},
		"Second": {{start: 7, end: 9}},
		"Twice":  {{start: 3, end: 5}, {start: 7, end: 9}},
	}

	for _, tc := range []struct {
		name   string
		anchor string
		hits   []int
		errIs  string
	}{
		{name: "ambiguous substring", anchor: "use(shared)", hits: []int{4, 8}},
		{name: "scoped substring", anchor: "in:Second:use(shared)", hits: []int{8}},
		{name: "prefix pins the whole line", anchor: "^func Second() {", hits: []int{7}},
		{name: "missing statement", anchor: "use(gone)", hits: nil},
		{name: "unknown scope", anchor: "in:Third:use(shared)", errIs: "no declaration named"},
		{name: "duplicated scope", anchor: "in:Twice:use(shared)", errIs: "is declared 2 times"},
		{name: "malformed scope", anchor: "in:Second", errIs: "in:<declaration>:<substring>"},
		{name: "empty anchor", anchor: "  ", errIs: "the anchor is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits, err := ix.resolve(fixture, tc.anchor)
			if tc.errIs != "" {
				if err == nil {
					t.Fatalf("resolve(%q) returned %v and no error; the resolver has to say why a "+
						"scope cannot be used rather than report zero hits, which is what a deleted "+
						"statement looks like", tc.anchor, hits)
				}
				if !strings.Contains(err.Error(), tc.errIs) {
					t.Fatalf("resolve(%q) failed with %q, which does not mention %q", tc.anchor, err, tc.errIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve(%q): %v", tc.anchor, err)
			}
			if fmt.Sprint(hits) != fmt.Sprint(tc.hits) {
				t.Fatalf("resolve(%q) = %v, want %v", tc.anchor, hits, tc.hits)
			}
		})
	}

	// And the non-Go refusal, which is the reason a repeated line in YAML has to
	// be replaced by one that identifies itself rather than scoped.
	ix.lines["charts/vault/values.yaml"] = []string{"a: 1", "a: 1"}
	if _, err := ix.resolve("charts/vault/values.yaml", "in:a:1"); err == nil ||
		!strings.Contains(err.Error(), "not Go") {
		t.Errorf("in: on a YAML file returned %v; it has to say that the scope form is Go-only", err)
	}
}

// TestComplianceRegister_GoDeclarationScopesAreIndexed checks the scope index
// against this file, which is the one Go source the compliance package can read
// and predict at the same time. A method keyed on its bare name would make
// in:Validate:... pick whichever of two types the parser reached first.
func TestComplianceRegister_GoDeclarationScopesAreIndexed(t *testing.T) {
	ix := newAnchorIndex(repoRoot(t))
	spans := ix.declSpans("tests/compliance/register_anchors_test.go")
	if len(spans) < 10 {
		t.Fatalf("only %d declarations indexed in this file; the parse is broken", len(spans))
	}

	for _, name := range []string{
		"anchoredEvidence",      // a package-level var
		"workflowEvidencePath",  // a const
		"declSpan",              // a type
		"receiverTypeName",      // a function
		"(anchorIndex).resolve", // a method, keyed on its receiver
		"TestComplianceRegister_AnchorGrammarRejectsAmbiguity",
	} {
		if len(spans[name]) != 1 {
			t.Errorf("declaration %q is indexed %d times, want 1", name, len(spans[name]))
		}
	}
	if _, bare := spans["resolve"]; bare {
		t.Error("a method is indexed under its bare name as well as (Receiver).Method, so " +
			"in:resolve:... would pick whichever type the parser reached first")
	}

	// The doc comment belongs to the declaration it explains. Anchoring onto a
	// doc comment is common in this register -- sometimes the comment is what the
	// row's notes are quoting -- and a span that started at the `func` keyword
	// would leave those lines in no scope at all.
	span := spans["receiverTypeName"][0]
	lines, err := ix.file("tests/compliance/register_anchors_test.go")
	if err != nil {
		t.Fatalf("read this file: %v", err)
	}
	if !strings.HasPrefix(lines[span.start-1], "//") {
		t.Errorf("the span for receiverTypeName starts at line %d (%q), which is not its doc comment",
			span.start, lines[span.start-1])
	}

	names := make([]string, 0, len(spans))
	for name := range spans {
		names = append(names, name)
	}
	sort.Strings(names)
	t.Logf("%d declarations indexed, first %v", len(names), names[:3])
}
