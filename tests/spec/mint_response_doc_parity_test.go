// Mint response documentation parity gate.
//
// docs/spec.md makes docs/api.md authoritative for response bodies, so api.md is
// not a description of the mint response -- it is the description. A field that
// MintResponse marshals and api.md omits is an undocumented field on the one
// endpoint whose whole job is to hand an assertion to somebody else's platform.
//
// That is not hypothetical. The email claim shipped in MintResponse with the
// request table updated and the response example and response field table both
// left alone, so the authoritative description of the object was missing a field
// the server was already sending. Nothing could see it: every test that touches
// a mint response body asserts on the fields it names, and a field nobody names
// is a field nobody checks.
//
// This gate reads the struct tags out of the source rather than marshaling a
// response, because omitempty means a runtime body proves only which fields were
// populated by that one request. The question is which fields the type is
// capable of emitting at all.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

var (
	mintResponseSource = filepath.Join("internal", "handler", "mint.go")
	mintResponseDoc    = filepath.Join("docs", "api.md")
)

// mintResponseJSONNames returns every json name MintResponse can marshal, in
// declaration order, with omitempty and other options stripped.
func mintResponseJSONNames(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(repoRoot(t), mintResponseSource)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", mintResponseSource, err)
	}

	var names []string
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name == nil || ts.Name.Name != "MintResponse" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok || st.Fields == nil {
			return false
		}
		for _, f := range st.Fields.List {
			if f.Tag == nil {
				continue
			}
			raw, err := strconv.Unquote(f.Tag.Value)
			if err != nil {
				t.Fatalf("unquoting a struct tag on MintResponse: %v", err)
			}
			tag := reflect.StructTag(raw).Get("json")
			name, _, _ := strings.Cut(tag, ",")
			if name == "" || name == "-" {
				continue
			}
			names = append(names, name)
		}
		return false
	})

	// A gate that finds nothing passes for the wrong reason. If MintResponse is
	// renamed or moved, this has to fail rather than quietly stop looking.
	if len(names) == 0 {
		t.Fatalf("no json-tagged fields found on MintResponse in %s. If the type moved "+
			"or was renamed, move this gate with it: what it holds is that api.md "+
			"describes every field the mint response can carry.", mintResponseSource)
	}
	return names
}

// mintDocSection returns the POST /mint section of api.md, from its heading to
// the next heading at the same level or above.
func mintDocSection(t *testing.T) string {
	t.Helper()
	doc := readFileString(t, filepath.Join(repoRoot(t), mintResponseDoc))

	const heading = "#### POST /mint"
	start := strings.Index(doc, heading)
	if start < 0 {
		t.Fatalf("no %q heading in %s; if the section was renamed, rename it here too",
			heading, mintResponseDoc)
	}
	rest := doc[start+len(heading):]

	end := len(rest)
	for _, next := range []string{"\n#### ", "\n### ", "\n## ", "\n# "} {
		if i := strings.Index(rest, next); i >= 0 && i < end {
			end = i
		}
	}
	return rest[:end]
}

// TestTheMintResponseDocumentsEveryFieldItCanSend fails when MintResponse gains
// a json field that the POST /mint success example or its field table does not
// mention.
func TestTheMintResponseDocumentsEveryFieldItCanSend(t *testing.T) {
	names := mintResponseJSONNames(t)
	section := mintDocSection(t)

	// The success example and the field table are two independent renderings of
	// the same object, and the email field went missing from both. Checking them
	// separately means fixing one does not silence the other.
	exampleStart := strings.Index(section, "**Success response (200 OK):**")
	if exampleStart < 0 {
		t.Fatal("no success-response block in the POST /mint section of api.md")
	}
	example := section[exampleStart:]
	if fence := strings.Index(example, "```json"); fence >= 0 {
		example = example[fence:]
		if end := strings.Index(example[len("```json"):], "```"); end >= 0 {
			example = example[:len("```json")+end]
		}
	}

	tableStart := strings.Index(section, "| Field | Type | Description |")
	if tableStart < 0 {
		t.Fatal("no response field table in the POST /mint section of api.md")
	}
	table := section[tableStart:]
	if end := strings.Index(table, "\n\n"); end >= 0 {
		table = table[:end]
	}

	for _, name := range names {
		if !strings.Contains(example, `"`+name+`"`) {
			t.Errorf("MintResponse marshals %q but the POST /mint success example does not "+
				"show it. api.md is authoritative for response bodies, so an absent field "+
				"is an undocumented one.", name)
		}
		if !strings.Contains(table, "`"+name+"`") {
			t.Errorf("MintResponse marshals %q but the POST /mint response field table has "+
				"no row for it", name)
		}
	}
}
