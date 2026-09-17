// Classification gate for the admin plane.
//
// GET /admin/audit withholds the admin-plane rows from a caller who does not
// hold admins:manage, because those rows are the admin roster in historical
// form: admin_login carries every admin's id, source address, username and
// role, which is the reconnaissance GET /admin/sessions was raised to
// super_admin to deny. audit.IsAdminPlaneEvent decides which rows those are,
// and it decides by namespace -- admin_something and admin:something -- rather
// than by a list of classes.
//
// A namespace rule is only closed if the naming holds, and nothing in Go makes
// it hold. A new admin-plane event called operator_login would compile, would
// be scored, would be emitted, and would be served to a viewer-tier session
// with no test anywhere going red. These gates are what make the convention a
// rule: every Admin-named constant must resolve to a value the classifier
// accepts, no user-plane constant may accidentally land in the namespace, and
// every event type the admin gateway emits -- including the seven that were
// never given a constant at all -- must classify as admin-plane.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/audit"
)

// adminPlaneUserEvents are event types the admin gateway emits that are
// deliberately NOT admin-plane, each with the reason a viewer-tier auditor is
// entitled to see it.
//
// Empty, and it is meant to stay that way. An entry here is a row about the
// operator surface that a lower-tier caller is served, so it needs an argument
// about the row's content, not about the convenience of the call site.
var adminPlaneUserEvents = map[string]string{}

// TestAdminNamedEventsAreClassifiedAsAdminPlane is the declaration half.
func TestAdminNamedEventsAreClassifiedAsAdminPlane(t *testing.T) {
	declared, declaredAt := declaredAuditEvents(t, repoRoot(t))
	if len(declared) == 0 {
		t.Fatalf("parsed zero event constants out of %s; this gate has stopped seeing what it guards",
			auditEventSource)
	}

	var adminNamed int
	for _, name := range sortedNames(declared) {
		value := declared[name]
		named := strings.HasPrefix(name, adminEventPrefix)
		classified := audit.IsAdminPlaneEvent(value)

		if named {
			adminNamed++
			if !classified {
				t.Errorf("audit.%s (%q) is declared at %s as an admin-plane class and "+
					"audit.IsAdminPlaneEvent does not recognize it.\n"+
					"GET /admin/audit withholds rows by that function, so this class is served to "+
					"any caller holding audit:read -- the admin roster, with the role attached, out "+
					"of the endpoint beside the one raised to super_admin to deny it. Name the "+
					"constant's value into one of %v, or say here why the row is not roster material.",
					name, value, declaredAt[name], audit.AdminPlaneEventPrefixes())
			}
			continue
		}

		if classified {
			t.Errorf("audit.%s (%q) is declared at %s, is not an Admin-named class, and lands in "+
				"the admin namespace anyway.\n"+
				"It will be withheld from every caller without admins:manage, which takes a "+
				"user-plane row away from the auditor the viewer tier exists for. Rename the value "+
				"out of the namespace, or rename the constant to say what it is.",
				name, value, declaredAt[name])
		}
	}

	if adminNamed < 15 {
		t.Fatalf("only %d Admin-named event constants found; the vocabulary declares far more than "+
			"that, so the scan is broken and this gate would pass vacuously", adminNamed)
	}
}

// TestEveryAdminGatewayEventIsClassifiedAsAdminPlane is the emission half, and
// it is the one that reaches the classes with no constant.
//
// Seven event types the admin gateway writes were never added to the
// vocabulary: admin:role_create, admin:role_delete, admin:users_import and the
// four admin:email_* classes. They are in the store exactly like the declared
// ones, they name the acting admin, and a gate that only read the const block
// would have called the fix complete while the colon half of the namespace went
// on being served.
func TestEveryAdminGatewayEventIsClassifiedAsAdminPlane(t *testing.T) {
	root := repoRoot(t)
	declared, _ := declaredAuditEvents(t, root)
	files := productionFiles(t, root)
	forwarders := eventForwarders(files)

	var checked int
	for _, sf := range files {
		if filepath.Dir(sf.rel) != adminGatewayDir {
			continue
		}
		for _, e := range adminGatewayEmissions(t, sf, declared, forwarders) {
			checked++
			if audit.IsAdminPlaneEvent(e.value) {
				continue
			}
			if reason, exempt := adminPlaneUserEvents[e.value]; exempt {
				t.Logf("%s:%d emits %q as a user-plane row: %s", sf.rel, e.line, e.value, reason)
				continue
			}
			t.Errorf("%s:%d emits %q, which audit.IsAdminPlaneEvent does not classify as "+
				"admin-plane.\n"+
				"The row names the acting admin's id and source address and is written by the "+
				"operator surface, so a viewer-tier session reads the admin roster out of the audit "+
				"trail by asking for this event type. Give the row its own admin-namespaced class, "+
				"or record it in adminPlaneUserEvents with the argument for serving it.",
				sf.rel, e.line, e.value)
		}
	}

	if checked < 20 {
		t.Fatalf("found only %d event emissions in %s; the extractor is broken, not the gateway",
			checked, adminGatewayDir)
	}
}

// adminGatewayEmission is one event type reaching Logger.Log from the gateway.
type adminGatewayEmission struct {
	value string
	line  int
}

// adminGatewayEmissions returns the wire values one file sends towards
// Logger.Log.
//
// It resolves the two shapes the gateway actually writes: the vocabulary
// constant, and the bare string literal used by the seven classes that never
// got one. An argument that is neither -- a parameter forwarded by a per-file
// helper, which is the shape internal/handler uses and this package does not --
// is a Fatal rather than a skip, because a shape the extractor silently ignores
// is a hole in the gate that reads as a pass.
func adminGatewayEmissions(t *testing.T, sf sourceFile, declared map[string]string,
	forwarders map[string]map[int]bool,
) []adminGatewayEmission {
	t.Helper()

	var out []adminGatewayEmission
	ast.Inspect(sf.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee, ok := calleeName(call)
		if !ok {
			return true
		}
		for idx := range forwarders[callee] {
			if idx >= len(call.Args) {
				continue
			}
			line := sf.fset.Position(call.Lparen).Line
			switch arg := call.Args[idx].(type) {
			case *ast.BasicLit:
				if arg.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(arg.Value)
				if err != nil {
					continue
				}
				out = append(out, adminGatewayEmission{value: value, line: line})
			case *ast.SelectorExpr:
				name, isAudit := auditConst(arg, sf.pkg)
				if !isAudit {
					continue
				}
				value, known := declared[name]
				if !known {
					t.Fatalf("%s:%d emits audit.%s, which %s does not declare. The gate cannot "+
						"classify an event it cannot resolve, so it is failing rather than "+
						"reporting the emission as fine.", sf.rel, line, name, auditEventSource)
				}
				out = append(out, adminGatewayEmission{value: value, line: line})
			default:
				t.Fatalf("%s:%d passes an event type this gate cannot read. Teach it that shape: "+
					"an argument it skips is an admin-plane row nothing checks.", sf.rel, line)
			}
		}
		return true
	})
	return out
}
