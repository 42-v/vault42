// Dead-vocabulary gate for the audit log.
//
// internal/audit/audit.go declares the event vocabulary the audit trail speaks.
// Before 1.0.0 four of those words were never spoken on the user surface:
// 2fa_verify, device_trust and session_revoke had no call site anywhere, and
// 2fa_setup was emitted only by the admin gateway, never for a regular user. The
// four handlers that own those actions had no audit logger field at all.
//
// The cost is not a missing row. It is a wrong answer. An investigator filtering
// the trail for 2fa_setup after an account takeover gets an empty result and
// reads it as "the attacker did not enroll a factor", when what happened is that
// enrollment was never recorded. An attacker riding a stolen session can enroll
// their own TOTP secret, revoke the owner's sessions and lock the owner out, and
// the trail shows nothing between the last successful login and the silence.
//
// Nothing could see this. An unused exported constant is not a compile error and
// no linter reports it, so the vocabulary drifted away from the product one
// unwired handler at a time. These tests close that hole: every declared event
// type must have a production path that emits it, an event that is not an admin
// event must be emitted somewhere other than the admin gateway, and anything
// exempt from either rule must say why in the allow-list below.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// auditEventSource declares the event vocabulary.
var auditEventSource = filepath.Join("internal", "audit", "audit.go")

// auditEventAnchor identifies the const group that holds the vocabulary. The
// group is found by a constant it contains rather than by position or by doc
// text, so reordering the block or rewriting its comment does not blind the
// gate, while the unrelated single-constant declarations in the same file
// (blobEventPrefix, svcDocEventPrefix) stay out of the set.
const auditEventAnchor = "LoginSuccess"

// auditImportPath is the package whose selector expressions name an event.
const auditImportPath = "github.com/42-v/vault42/internal/audit"

// logMethod is the emission call. Everything the audit trail contains arrives
// through it, so an event type that never reaches its second argument never
// reaches the database.
const logMethod = "Log"

// eventArgIndex is the position of the event type in Logger.Log's argument list.
const eventArgIndex = 1

// adminEventPrefix marks the constants that describe an action only an operator
// can take. audit.go already follows this convention for every admin gateway
// event, so it is the existing signal for "the admin surface is the only place
// this can happen", not a rule invented here.
const adminEventPrefix = "Admin"

// adminGatewayDir is the operator surface. An event that only this package emits
// is recorded for admins and lost for users.
var adminGatewayDir = filepath.Join("internal", "adminapi")

// auditPkgDir is the declaration site, excluded from the emission scan because
// declaring a constant and switching on it in isCriticalEvent are not emissions.
var auditPkgDir = filepath.Join("internal", "audit")

// auditScanSkipDirs are not scanned for emissions.
//
// Test trees are excluded on purpose. A test that emits an event proves the
// plumbing works in a fixture, not that a production request path writes the
// row, and counting one would let a constant stay dead in the product while this
// gate reported it live.
var auditScanSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "tests": true,
	"tmp": true, "coverage": true, "web": true, "site": true, "packages": true,
}

// unemittedAuditEvents are the event types deliberately declared without any
// production call site. Every entry states why, and TestNoStaleAuditEventExemption
// fails as soon as one of them gains an emission, so an exemption cannot quietly
// outlive its reason.
//
// Both entries are debts, not designs. Each names the work that retires it.
var unemittedAuditEvents = map[string]string{
	// There is no remember-device flow. DeviceRepository.Trust exists and the
	// devices table carries trusted/trusted_until, but no production path calls
	// it: model.Device documents Trusted as reserved and every login writes
	// false. Wiring this event now would mean inventing a call site for an
	// action no user can perform. Emit it from the trust step when the
	// remember-device flow lands, or delete the constant along with the flow.
	"DeviceTrust": "no production path trusts a device; DeviceRepository.Trust has no non-test caller",
	// The CLI reaches the audit tables through repository.AuditRepository to
	// query and to purge, never through Logger, so cleanup-audit runs without
	// recording that it ran. A retention purge is exactly the action an
	// operator would later want evidence of, and admin_action is already
	// treated as critical in isCriticalEvent, so the gap is real. It belongs to
	// internal/cli.
	"AdminAction": "internal/cli mutates through AuditRepository directly and never logs its own actions",
}

// adminOnlyAuditEvents are non-Admin-prefixed events that legitimately have no
// emitter outside the admin gateway. Empty today, and it should stay that way:
// an entry here means one half of an action is auditable and the other half is
// not.
var adminOnlyAuditEvents = map[string]string{}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestEveryDeclaredAuditEventIsEmitted is the gate.
func TestEveryDeclaredAuditEventIsEmitted(t *testing.T) {
	root := repoRoot(t)
	declared, declaredAt := declaredAuditEvents(t, root)
	if len(declared) == 0 {
		t.Fatalf("parsed zero event constants out of %s: the const group anchored on %s moved or was "+
			"renamed, and this gate has stopped seeing what it guards", auditEventSource, auditEventAnchor)
	}

	emitted := emittedAuditEvents(t, root, declared)
	if len(emitted) == 0 {
		t.Fatal("parsed zero emissions from the source tree: the AST extractor is broken, not the product")
	}

	for _, name := range sortedNames(declared) {
		if _, ok := emitted[name]; ok {
			continue
		}
		if _, exempt := unemittedAuditEvents[name]; exempt {
			continue
		}
		t.Errorf("audit.%s (%q) is declared at %s and no production path emits it.\n"+
			"A declared event nothing writes is worse than no event at all: an investigator filtering "+
			"the trail for %q gets an empty result and reads it as \"this never happened\" when the truth "+
			"is \"this was never recorded\". Emit it where the action occurs, delete the constant so "+
			"nobody queries for it, or add it to unemittedAuditEvents with the reason it stays dark.",
			name, declared[name], declaredAt[name], declared[name])
	}
}

// TestUserActionsAreAuditedOutsideTheAdminGateway catches the half-wired case,
// which is the one that reads as working. audit.TwoFASetup had a call site all
// along, in internal/adminapi, so a search for the constant found something and
// the user-facing enrollment path stayed silent for a whole release.
func TestUserActionsAreAuditedOutsideTheAdminGateway(t *testing.T) {
	root := repoRoot(t)
	declared, declaredAt := declaredAuditEvents(t, root)
	emitted := emittedAuditEvents(t, root, declared)

	for _, name := range sortedNames(declared) {
		if strings.HasPrefix(name, adminEventPrefix) {
			continue
		}
		if _, exempt := adminOnlyAuditEvents[name]; exempt {
			continue
		}
		e, ok := emitted[name]
		if !ok || !e.onlyAdminGateway() {
			continue
		}
		t.Errorf("audit.%s (%q) is declared at %s and only %s emits it.\n"+
			"The action is recorded when an operator performs it and unrecorded when a user does, so "+
			"the trail answers a takeover investigation with silence exactly where the attacker acted. "+
			"Emit it from the user-facing path too, or record in adminOnlyAuditEvents why users cannot "+
			"reach this action at all.", name, declared[name], declaredAt[name], adminGatewayDir)
	}
}

// TestNoStaleAuditEventExemption keeps both allow-lists honest in both
// directions. An exemption for a constant that no longer exists, or for one that
// has since been wired up, is a comment nobody rereads; leave enough of them
// lying around and the next constant to go dark gets waved through by
// inspection.
func TestNoStaleAuditEventExemption(t *testing.T) {
	root := repoRoot(t)
	declared, _ := declaredAuditEvents(t, root)
	emitted := emittedAuditEvents(t, root, declared)

	for _, name := range sortedKeys(unemittedAuditEvents) {
		if _, ok := declared[name]; !ok {
			t.Errorf("unemittedAuditEvents exempts %q, which %s no longer declares. "+
				"Drop the entry, or fix the name if the constant was renamed.", name, auditEventSource)
			continue
		}
		if e, ok := emitted[name]; ok {
			t.Errorf("unemittedAuditEvents exempts audit.%s as %q, but it is emitted at %s. "+
				"Remove the exemption so the reason cannot outlive the fact.",
				name, unemittedAuditEvents[name], e.first)
		}
	}

	for _, name := range sortedKeys(adminOnlyAuditEvents) {
		if _, ok := declared[name]; !ok {
			t.Errorf("adminOnlyAuditEvents exempts %q, which %s no longer declares. "+
				"Drop the entry, or fix the name if the constant was renamed.", name, auditEventSource)
			continue
		}
		if e, ok := emitted[name]; ok && !e.onlyAdminGateway() {
			t.Errorf("adminOnlyAuditEvents exempts audit.%s as %q, but it is emitted at %s. "+
				"Remove the exemption so the reason cannot outlive the fact.",
				name, adminOnlyAuditEvents[name], e.first)
		}
	}
}

// TestEveryAuditableHandlerIsGivenTheLoggerAtWiringTime closes the other half
// of the same defect.
//
// The emission gate proves a call site exists in the handler. It cannot prove
// the handler was handed a logger, and a handler with a nil logger skips the
// write silently, which is exactly what a best-effort trail is supposed to do
// when auditing is switched off. So deleting one line from setupRoutes would
// put the product back where it started with every test still green.
//
// The property is mechanical: a handler that declares SetAuditLog can be
// audited, and one the server builds without calling it cannot. There is no
// case where building an auditable handler and withholding the logger is
// correct, so no allow-list is offered.
func TestEveryAuditableHandlerIsGivenTheLoggerAtWiringTime(t *testing.T) {
	root := repoRoot(t)

	ctors, auditable := auditableHandlers(t, root)
	if len(auditable) == 0 {
		t.Fatalf("no handler in %s declares %s: the setter was renamed and this gate has stopped "+
			"seeing what it guards", handlerPkgDir, auditSetter)
	}

	built, wired, at := wiredHandlers(t, root, ctors)
	if len(built) == 0 {
		t.Fatalf("parsed no handler construction out of %s: the extractor is broken, not the wiring",
			serverWiringSource)
	}

	var checked int
	for _, name := range sortedNames(built) {
		if !auditable[built[name]] {
			continue
		}
		checked++
		if !wired[name] {
			t.Errorf("%s builds %s as a %s at %s and never calls %s on it.\n"+
				"The handler then holds a nil logger and skips every write without complaint, so the "+
				"actions it owns leave no trace and nothing fails. Pass d.AuditLog at wiring time.",
				serverWiringSource, name, built[name], at[name], auditSetter)
		}
	}
	if checked == 0 {
		t.Fatalf("%s builds no auditable handler; either the wiring moved or the constructor-to-type "+
			"mapping broke", serverWiringSource)
	}
}

// ---------------------------------------------------------------------------
// Wiring side
// ---------------------------------------------------------------------------

// auditSetter is the method that hands a handler its logger after construction,
// following the SetMailer precedent in internal/handler/password.go. A setter
// rather than a constructor argument because the constructors are called from
// test trees this change does not own.
const auditSetter = "SetAuditLog"

// handlerPkgDir holds the handler types.
var handlerPkgDir = filepath.Join("internal", "handler")

// serverWiringSource builds and mounts them.
var serverWiringSource = filepath.Join("internal", "server", "server.go")

// auditableHandlers returns the constructor-to-type mapping for the handler
// package and the set of types that accept an audit logger.
func auditableHandlers(t *testing.T, root string) (ctors map[string]string, auditable map[string]bool) {
	t.Helper()

	ctors, auditable = map[string]string{}, map[string]bool{}
	for _, sf := range productionFiles(t, root) {
		if filepath.Dir(sf.rel) != handlerPkgDir {
			continue
		}
		for _, decl := range sf.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Recv == nil {
				if typ, ok := singlePointerResult(fn.Type); ok {
					ctors[fn.Name.Name] = typ
				}
				continue
			}
			if fn.Name.Name != auditSetter {
				continue
			}
			if typ, ok := receiverType(fn.Recv); ok {
				auditable[typ] = true
			}
		}
	}
	return ctors, auditable
}

// singlePointerResult returns the type name of a function returning exactly one
// pointer to a named type, which is the shape every handler constructor has.
func singlePointerResult(sig *ast.FuncType) (string, bool) {
	if sig.Results == nil || len(sig.Results.List) != 1 {
		return "", false
	}
	star, ok := sig.Results.List[0].Type.(*ast.StarExpr)
	if !ok {
		return "", false
	}
	id, ok := star.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}

// receiverType returns the named type a method is defined on.
func receiverType(recv *ast.FieldList) (string, bool) {
	if len(recv.List) != 1 {
		return "", false
	}
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	id, ok := expr.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}

// wiredHandlers reads the server's route setup: which local variables hold
// which handler type, which of them are given the audit logger, and where each
// was built.
func wiredHandlers(t *testing.T, root string, ctors map[string]string) (built map[string]string, wired map[string]bool, at map[string]string) {
	t.Helper()

	path := filepath.Join(root, serverWiringSource)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", serverWiringSource, err)
	}

	built, wired, at = map[string]string{}, map[string]bool{}, map[string]string{}
	note := func(name, typ string, pos token.Pos) {
		if name == "_" || typ == "" {
			return
		}
		if _, seen := built[name]; !seen {
			at[name] = fmt.Sprintf("%s:%d", serverWiringSource, fset.Position(pos).Line)
		}
		built[name] = typ
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		// x := handler.NewFoo(...), and the reassignment in the WebAuthn
		// branch where the variable is declared first and built in an if/else.
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || i >= len(node.Rhs) {
					continue
				}
				call, ok := node.Rhs[i].(*ast.CallExpr)
				if !ok {
					continue
				}
				if ctor, ok := calleeName(call); ok {
					note(id.Name, ctors[ctor], id.Pos())
				}
			}
		// var x *handler.Foo
		case *ast.ValueSpec:
			star, ok := node.Type.(*ast.StarExpr)
			if !ok {
				return true
			}
			sel, ok := star.X.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			for _, id := range node.Names {
				note(id.Name, sel.Sel.Name, id.Pos())
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != auditSetter {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok {
				wired[id.Name] = true
			}
		}
		return true
	})
	return built, wired, at
}

// ---------------------------------------------------------------------------
// Declaration side
// ---------------------------------------------------------------------------

// declaredAuditEvents returns the event vocabulary as name to wire value, plus
// the source position each was declared at.
func declaredAuditEvents(t *testing.T, root string) (events, at map[string]string) {
	t.Helper()

	path := filepath.Join(root, auditEventSource)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", auditEventSource, err)
	}

	events, at = map[string]string{}, map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST || !groupDeclares(gen, auditEventAnchor) {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			events[vs.Names[0].Name] = value
			at[vs.Names[0].Name] = fmt.Sprintf("%s:%d", auditEventSource, fset.Position(vs.Pos()).Line)
		}
	}
	return events, at
}

// groupDeclares reports whether a const group declares the named constant.
func groupDeclares(gen *ast.GenDecl, name string) bool {
	for _, spec := range gen.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, id := range vs.Names {
			if id.Name == name {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Emission side
// ---------------------------------------------------------------------------

// emission is where one event type reaches Logger.Log.
type emission struct {
	// first is the "path:line" of the first site found, for error messages
	// that point at a line rather than at a package.
	first string
	// dirs are the directories that emit this event, which is what separates
	// "audited everywhere" from "audited only for operators".
	dirs map[string]bool
}

// onlyAdminGateway reports whether the admin gateway is the sole emitter.
func (e emission) onlyAdminGateway() bool {
	return len(e.dirs) == 1 && e.dirs[adminGatewayDir]
}

// sourceFile is one parsed production file.
type sourceFile struct {
	// rel is the module-relative path, used in failure messages.
	rel  string
	fset *token.FileSet
	file *ast.File
	// pkg is the identifier this file calls the audit package by.
	pkg string
}

// emittedAuditEvents scans production Go source for event types that reach
// Logger.Log.
func emittedAuditEvents(t *testing.T, root string, declared map[string]string) map[string]emission {
	t.Helper()

	byValue := make(map[string]string, len(declared))
	for name, value := range declared {
		byValue[value] = name
	}

	files := productionFiles(t, root)
	forwarders := eventForwarders(files)

	out := map[string]emission{}
	for _, sf := range files {
		dir := filepath.Dir(sf.rel)
		for name, line := range fileEmissions(sf, byValue, forwarders) {
			e, seen := out[name]
			if !seen {
				e = emission{first: fmt.Sprintf("%s:%d", sf.rel, line), dirs: map[string]bool{}}
			}
			e.dirs[dir] = true
			out[name] = e
		}
	}
	return out
}

// productionFiles parses every non-test Go file that could contain an emission.
func productionFiles(t *testing.T, root string) []sourceFile {
	t.Helper()

	var out []sourceFile
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if d.IsDir() {
			if path != root && (auditScanSkipDirs[d.Name()] || rel == auditPkgDir) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", rel, parseErr)
		}
		out = append(out, sourceFile{rel: rel, fset: fset, file: file, pkg: auditPkgName(file)})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", root, walkErr)
	}
	return out
}

// eventForwarders maps a function name to the parameter positions an event type
// can travel through on its way to Logger.Log.
//
// Handlers do not all call Logger.Log with the constant in hand. Four of them
// pass it to a small per-handler helper that adds the request's IP and
// User-Agent, and a gate that only understood the direct shape would have
// declared every one of those events unemitted the moment the duplication was
// factored out. Refusing to follow the indirection would make the gate reward
// copy-paste, so it resolves the chain instead, to a fixed point, which also
// covers a helper that calls a helper.
func eventForwarders(files []sourceFile) map[string]map[int]bool {
	// Logger.Log itself is the root: its second argument is the event type.
	out := map[string]map[int]bool{logMethod: {eventArgIndex: true}}

	for changed := true; changed; {
		changed = false
		for _, sf := range files {
			for _, decl := range sf.file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				params := paramPositions(fn.Type)
				if len(params) == 0 {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					callee, ok := calleeName(call)
					if !ok {
						return true
					}
					for idx := range out[callee] {
						if idx >= len(call.Args) {
							continue
						}
						id, ok := call.Args[idx].(*ast.Ident)
						if !ok {
							continue
						}
						pos, ok := params[id.Name]
						if !ok {
							continue
						}
						if out[fn.Name.Name] == nil {
							out[fn.Name.Name] = map[int]bool{}
						}
						if !out[fn.Name.Name][pos] {
							out[fn.Name.Name][pos] = true
							changed = true
						}
					}
					return true
				})
			}
		}
	}
	return out
}

// paramPositions maps each parameter name to its argument position. Grouped
// declarations such as (event, userID string) contribute one entry each.
func paramPositions(sig *ast.FuncType) map[string]int {
	out := map[string]int{}
	if sig.Params == nil {
		return out
	}
	var i int
	for _, field := range sig.Params.List {
		if len(field.Names) == 0 {
			i++
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				out[name.Name] = i
			}
			i++
		}
	}
	return out
}

// calleeName returns the called function's own name, ignoring the receiver or
// package it is reached through.
func calleeName(call *ast.CallExpr) (string, bool) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name, true
	case *ast.SelectorExpr:
		return fn.Sel.Name, true
	}
	return "", false
}

// auditPkgName returns the identifier the file refers to the audit package by,
// or "" when the file does not import it. Reading the import rather than
// assuming "audit" means an aliased import still counts as an emission.
func auditPkgName(file *ast.File) string {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != auditImportPath {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return filepath.Base(path)
	}
	return ""
}

// fileEmissions returns the event constants this file sends towards Logger.Log,
// mapped to the line the call sits on.
//
// Three argument shapes are recognized: the constant itself, a string literal
// holding the wire value, so that an emission written without the constant still
// counts, and a local variable the file assigned a constant to, which is how
// internal/handler/identity.go picks between granted and withdrawn before
// logging. Variable resolution is file-scoped rather than function-scoped on
// purpose: the shape it has to see is one function choosing an event and then
// logging it, and widening the scope costs only precision on a name collision
// inside a single file.
func fileEmissions(sf sourceFile, byValue map[string]string, forwarders map[string]map[int]bool) map[string]int {
	// Constants parked in a variable before the call.
	viaVar := map[string][]string{}
	ast.Inspect(sf.file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || i >= len(assign.Rhs) {
				continue
			}
			if name, ok := auditConst(assign.Rhs[i], sf.pkg); ok {
				viaVar[id.Name] = append(viaVar[id.Name], name)
			}
		}
		return true
	})

	out := map[string]int{}
	record := func(name string, pos token.Pos) {
		if _, seen := out[name]; !seen {
			out[name] = sf.fset.Position(pos).Line
		}
	}

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
			switch arg := call.Args[idx].(type) {
			case *ast.SelectorExpr:
				if name, ok := auditConst(arg, sf.pkg); ok {
					record(name, call.Lparen)
				}
			case *ast.BasicLit:
				if arg.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(arg.Value)
				if err != nil {
					continue
				}
				if name, ok := byValue[value]; ok {
					record(name, call.Lparen)
				}
			case *ast.Ident:
				for _, name := range viaVar[arg.Name] {
					record(name, call.Lparen)
				}
			}
		}
		return true
	})
	return out
}

// auditConst reports whether expr is a selector on the audit package, returning
// the constant name.
func auditConst(expr ast.Expr, pkg string) (string, bool) {
	if pkg == "" {
		return "", false
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != pkg {
		return "", false
	}
	return sel.Sel.Name, true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sortedNames returns map keys in a stable order so failures read the same on
// every run and diff cleanly in CI logs.
func sortedNames(events map[string]string) []string {
	out := make([]string, 0, len(events))
	for name := range events {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// sortedKeys is sortedNames for the allow-lists.
func sortedKeys(m map[string]string) []string { return sortedNames(m) }
