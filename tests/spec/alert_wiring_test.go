// Alerting wiring gate.
//
// The finding CR-15 recorded was not that vault42 had no alerting code. It had
// some: honeypot.Alerter, a webhook dispatcher with a rate limit and an audit
// trail of its own. What it did not have was that code on the path a production
// deployment runs -- cmd/vault/main.go built it only under
// config.ProfileHoneypot, so on every other profile the only outbound alert
// channel in the tree was never constructed. A control present, tested, and not
// on the path it claims to serve is the exact shape internal/crypto's unscraped
// argon2 accessors took, and the metrics wiring got a gate rather than a promise
// for it. So does this.
//
// The second gate here is over the severity table. The scale is only comparable
// across event classes if every class is on it, and an event type added without
// a score would read as notable by default -- which is safe, and is exactly the
// kind of safe default that stops anybody noticing for a release.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// alertWiringSource is where the process installs its detector.
var alertWiringSource = filepath.Join("cmd", "vault", "main.go")

// severitySource holds the table every event class is scored in.
var severitySource = filepath.Join("internal", "audit", "severity.go")

// auditVocabularySource declares the event classes.
var auditVocabularySource = filepath.Join("internal", "audit", "audit.go")

// severityTableName is the map the gate reads.
const severityTableName = "severityByEvent"

// detectorInstaller is the call that puts a detector on the audit logger.
const detectorInstaller = "SetDetector"

// TestAlertDetectorIsInstalledOnEveryProfile fails when the process installs its
// alert detector conditionally, which is how the honeypot webhook came to be the
// only alert channel in a tree that shipped four other profiles.
func TestAlertDetectorIsInstalledOnEveryProfile(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, alertWiringSource)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", alertWiringSource, err)
	}

	// Every SetDetector call, and whether any conditional statement encloses it.
	type installation struct {
		line        int
		conditional bool
	}
	var found []installation

	var conditionalDepth int
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			conditionalDepth++
			ast.Inspect(nodeBody(node), func(inner ast.Node) bool {
				if inner == nil {
					return false
				}
				return walk(inner)
			})
			conditionalDepth--
			return false
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == detectorInstaller {
				found = append(found, installation{
					line:        fset.Position(node.Pos()).Line,
					conditional: conditionalDepth > 0,
				})
			}
		}
		return true
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		return walk(n)
	})

	if len(found) == 0 {
		t.Fatalf("%s never calls %s. The audit logger records every security event and raises "+
			"nothing from any of them, which is the state CR-15 recorded.",
			alertWiringSource, detectorInstaller)
	}
	for _, in := range found {
		if in.conditional {
			t.Errorf("%s:%d installs the alert detector inside a conditional. The honeypot webhook "+
				"was gated on config.ProfileHoneypot exactly this way and was therefore never "+
				"constructed in production; a profile-gated detector reopens that finding.",
				alertWiringSource, in.line)
		}
	}
}

// TestTheInstalledSinkIsNotANoOp fails when the detector is wired to something
// that cannot reach an operator. A dispatcher installed on every profile and
// pointed at nothing is the same gap with a longer call graph.
func TestTheInstalledSinkIsNotANoOp(t *testing.T) {
	src := readFileString(t, filepath.Join(repoRoot(t), alertWiringSource))

	idx := strings.Index(src, detectorInstaller)
	if idx < 0 {
		t.Fatalf("%s no longer installs a detector; the sink assertion has nothing to read",
			alertWiringSource)
	}
	// The installation and its sink are one expression.
	stmt := src[idx:]
	if end := strings.Index(stmt, "\n"); end > 0 {
		stmt = stmt[:end]
	}
	if !strings.Contains(stmt, "alert.LogSink") {
		t.Errorf("the detector is installed with %q, which is not the log sink. A sink that reaches "+
			"no operator is the CR-15 gap wearing a dispatcher's clothes; if the delivery mechanism "+
			"has deliberately changed, change this gate and say why in the register.", strings.TrimSpace(stmt))
	}
}

// TestEveryAuditEventClassIsScored fails when a declared event type carries no
// severity. Severity falls back to notable for an unscored class, which is the
// right default and the wrong thing to rely on: risk_score >= 75 is only a
// meaningful question if every class has been asked it.
func TestEveryAuditEventClassIsScored(t *testing.T) {
	root := repoRoot(t)

	declared := auditEventConstants(t, filepath.Join(root, auditVocabularySource))
	if len(declared) < 20 {
		t.Fatalf("only %d event constants found in %s; the scan is broken and this gate would pass "+
			"vacuously", len(declared), auditVocabularySource)
	}

	scored := severityTableKeys(t, filepath.Join(root, severitySource))
	if len(scored) == 0 {
		t.Fatalf("%s declares no entries in %s; the scan is broken", severitySource, severityTableName)
	}

	for _, name := range declared {
		if _, ok := scored[name]; !ok {
			t.Errorf("audit.%s is a declared event class and %s does not score it. An unscored class "+
				"reads as notable, so it is neither filtered out of a review nor deliberately in it.",
				name, severityTableName)
		}
	}
	for name := range scored {
		if name == "AdminKillswitchTriggered" {
			// Declared outside the vocabulary block on purpose: the admin
			// gateway writes that row straight to the repository, so it must
			// not appear in the block the dead-vocabulary gate reads.
			continue
		}
		if !containsString(declared, name) {
			t.Errorf("%s scores %s, which is not a declared event class. A score for an event that "+
				"cannot happen is a row nobody will ever see.", severityTableName, name)
		}
	}
}

// auditEventConstants returns the names in the const group holding the event
// vocabulary, found by a constant it contains rather than by position.
func auditEventConstants(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		var names []string
		anchored := false
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, ident := range vs.Names {
				if ident.Name == auditEventAnchor {
					anchored = true
				}
				names = append(names, ident.Name)
			}
		}
		if anchored {
			return names
		}
	}
	t.Fatalf("no const group in %s contains %s", path, auditEventAnchor)
	return nil
}

// severityTableKeys returns the identifiers used as keys in the severity map.
func severityTableKeys(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	keys := map[string]struct{}{}
	ast.Inspect(file, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != severityTableName {
			return true
		}
		for _, value := range vs.Values {
			lit, ok := value.(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if ident, ok := kv.Key.(*ast.Ident); ok {
					keys[ident.Name] = struct{}{}
				}
			}
		}
		return false
	})
	return keys
}

// nodeBody returns the statement whose enclosed calls a conditional guards.
func nodeBody(n ast.Node) ast.Node {
	switch node := n.(type) {
	case *ast.IfStmt:
		return node.Body
	case *ast.SwitchStmt:
		return node.Body
	case *ast.TypeSwitchStmt:
		return node.Body
	case *ast.SelectStmt:
		return node.Body
	}
	return n
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
