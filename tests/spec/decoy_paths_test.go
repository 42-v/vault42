// Honeypot decoy collision gate.
//
// The bridge answers a decoy path with a fake login page and flags the caller
// for BRIDGE_FLAG_TTL, after which every request from that address is served
// fabricated key, user, session and audit data with nothing indicating the
// switch. That is the right response to someone probing for /wp-admin. It is a
// self-inflicted outage when the prefix is one vault42 itself serves.
//
// `/admin` was in the decoy set. vault42 registers its admin SPA and roughly
// thirty documented API routes under `/admin/`, and IsDecoyPath matches by
// prefix, so an operator opening the admin console through a bridge was flagged
// for twenty-four hours and then shown a fabricated console. The first request
// they make is `POST /admin/auth/login`.
//
// Nothing connected the two facts, because cmd/bridge is deliberately
// standalone: it is stdlib-only and does not import internal/, so no compiler
// error and no test could see that its bait list overlapped the product's own
// routes. This gate is the connection, and it lives here rather than in
// cmd/bridge precisely because only this package is allowed to read both sides.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// decoySource holds the bait table.
var decoySource = filepath.Join("cmd", "bridge", "decoy.go")

// decoyPrefixes extracts the keys of the decoyPaths map literal with go/ast,
// rather than by regex, so a change in how the table is written is a parse
// failure here instead of a silently empty gate.
func decoyPrefixes(t *testing.T, root string) []string {
	t.Helper()

	path := filepath.Join(root, decoySource)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", decoySource, err)
	}

	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) == 0 || spec.Names[0].Name != "decoyPaths" {
			return true
		}
		for _, v := range spec.Values {
			lit, ok := v.(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.BasicLit)
				if !ok || key.Kind != token.STRING {
					continue
				}
				unquoted, err := strconv.Unquote(key.Value)
				if err != nil {
					t.Fatalf("unquoting decoy prefix %s: %v", key.Value, err)
				}
				out = append(out, unquoted)
			}
		}
		return false
	})

	if len(out) == 0 {
		t.Fatalf("found no decoy prefixes in %s; the table was renamed or restructured "+
			"and this gate has stopped seeing what it guards", decoySource)
	}
	sort.Strings(out)
	return out
}

// TestNoDecoyPathShadowsARealRoute fails when the honeypot claims a prefix the
// product serves.
//
// Matching mirrors IsDecoyPath: a route is shadowed when it equals a prefix or
// sits beneath it. Comparison is lowercase for the same reason IsDecoyPath
// lowercases, so a route registered with different casing cannot slip past.
func TestNoDecoyPathShadowsARealRoute(t *testing.T) {
	root := repoRoot(t)
	prefixes := decoyPrefixes(t, root)

	// parseAllRoutes is route_drift_test.go's parser over the same registration
	// files, so both gates always agree on what a route is. Both halves are
	// checked: the admin SPA and its static assets are non-API routes, and they
	// are exactly what `/admin` was shadowing.
	api, nonAPI, _ := parseAllRoutes(t, root)
	if len(api)+len(nonAPI) == 0 {
		t.Fatal("no routes parsed; this gate cannot prove anything against an empty set")
	}

	all := make(map[route]bool, len(api)+len(nonAPI))
	for r := range api {
		all[r] = true
	}
	for r := range nonAPI {
		all[r] = true
	}

	for r := range all {
		lower := strings.ToLower(r.path)
		for _, prefix := range prefixes {
			if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
				t.Errorf("decoy prefix %q shadows the registered route %s %s. "+
					"A caller reaching that route through a bridge is flagged for the full "+
					"BRIDGE_FLAG_TTL and then served fabricated data, so this aims the "+
					"honeypot at whoever legitimately uses the route.",
					prefix, r.method, r.path)
			}
		}
	}
}
