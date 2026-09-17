package spec_test

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The TypeScript SDK's response types must name exactly the fields the server
// sends. No more, and no fewer.
//
// `Device` declared three the endpoint has never sent -- `trusted_until`,
// `first_seen_at` and `created_at`. Two of them were declared non-optional, so
// `device.created_at` type-checked and was `undefined` at runtime: the one
// combination TypeScript cannot warn about, because the type asserted the field
// was always there. `trusted_until` does exist on the underlying row and is
// deliberately not projected into the response, which is exactly how a field
// like that ends up in a hand-written type.
//
// `Session` had the opposite drift: the wire type sends `device_id` and the
// interface did not declare it, so a consumer could not reach a field that was
// on every response.
//
// Only field NAMES are compared. Optionality is deliberately out of scope: a
// non-pointer Go string with no omitempty still emits `""`, and a TypeScript
// consumer may reasonably want to treat that as absent, so `?` on the TS side
// is a judgement rather than a fact about the wire.

var (
	goJSONTag   = regexp.MustCompile("`json:\"([^\",]+)")
	tsFieldName = regexp.MustCompile(`(?m)^\s{2}([a-z_][A-Za-z0-9_]*)\??\s*:`)
)

// goStructJSONFields returns the json field names of a Go struct declaration.
func goStructJSONFields(t *testing.T, src, name string) []string {
	t.Helper()
	start := strings.Index(src, "type "+name+" struct {")
	if start < 0 {
		t.Fatalf("no `type %s struct` in the wire types. If it was renamed, move this gate with "+
			"it: what it holds is a hand-written SDK type against the response it describes.", name)
	}
	body := src[start:]
	end := strings.Index(body, "\n}")
	if end < 0 {
		t.Fatalf("could not find the end of `type %s struct`", name)
	}
	var out []string
	for _, m := range goJSONTag.FindAllStringSubmatch(body[:end], -1) {
		if m[1] != "-" {
			out = append(out, m[1])
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s has no json tags; the comparison would pass vacuously", name)
	}
	sort.Strings(out)
	return out
}

// tsInterfaceFields returns the field names of a TypeScript interface.
func tsInterfaceFields(t *testing.T, src, name string) []string {
	t.Helper()
	start := strings.Index(src, "export interface "+name+" {")
	if start < 0 {
		t.Fatalf("no `export interface %s` in packages/vue/src/types.ts", name)
	}
	body := src[start:]
	end := strings.Index(body, "\n}")
	if end < 0 {
		t.Fatalf("could not find the end of `export interface %s`", name)
	}
	matches := tsFieldName.FindAllStringSubmatch(body[:end], -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatalf("interface %s declares no fields; the comparison would pass vacuously", name)
	}
	sort.Strings(out)
	return out
}

func TestSDKResponseTypesNameExactlyTheFieldsTheServerSends(t *testing.T) {
	root := repoRoot(t)
	goSrc := readFileString(t, filepath.Join(root, "internal", "handler", "response_types.go"))
	tsSrc := readFileString(t, filepath.Join(root, "packages", "vue", "src", "types.ts"))

	for _, pair := range []struct{ goName, tsName string }{
		{"DeviceInfo", "Device"},
		{"SessionInfo", "Session"},
	} {
		t.Run(pair.tsName, func(t *testing.T) {
			wire := goStructJSONFields(t, goSrc, pair.goName)
			sdk := tsInterfaceFields(t, tsSrc, pair.tsName)

			inWire := map[string]bool{}
			for _, f := range wire {
				inWire[f] = true
			}
			inSDK := map[string]bool{}
			for _, f := range sdk {
				inSDK[f] = true
			}

			for _, f := range sdk {
				if !inWire[f] {
					t.Errorf("%s declares %q and %s does not send it. A field that is never sent "+
						"reads as `undefined` at runtime, and if it is declared non-optional "+
						"TypeScript will not say so at the call site.\n  wire: %v\n  sdk:  %v",
						pair.tsName, f, pair.goName, wire, sdk)
				}
			}
			for _, f := range wire {
				if !inSDK[f] {
					t.Errorf("%s sends %q and %s does not declare it, so a consumer cannot reach "+
						"a field that is on every response.\n  wire: %v\n  sdk:  %v",
						pair.goName, f, pair.tsName, wire, sdk)
				}
			}
		})
	}
}
