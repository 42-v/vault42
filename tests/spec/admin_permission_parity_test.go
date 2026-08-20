// Admin route / documented permission parity gate.
//
// Three documents publish a table of the admin API's routes and the RBAC
// permission each one requires: docs/api.md, docs/spec.md and
// docs/admin-gateway.md. An operator reads one of them to decide which role to
// grant somebody, so a wrong cell there is a wrong grant, and a wrong grant is
// either an operator locked out of a route they were meant to have or an admin
// holding one they were not.
//
// Nothing checked those cells. `GET /admin/sessions` was published as
// `sessions:list` in all three while `internal/adminapi/router.go` gates it on
// `rbac.AdminsManage`, and the difference is a tier: `sessions:list` is
// viewer-grade and `admins:manage` is super_admin-grade, kept there on purpose
// because that route returns the live roster of who can administer the
// deployment, which is reconnaissance for an attacker holding a lower admin
// session. The prose beside it compounded the error by calling the result
// "active refresh families", which is user sessions -- the thing that route
// specifically does not return.
//
// One wrong cell in thirty-eight is exactly the density a person does not catch
// by reading, which is the argument for checking it here.
//
// The test is read-only. It never writes to the source tree.
package spec_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// adminRouteRE pulls the method, path and rbac constant out of a guarded mount.
var adminRouteRE = regexp.MustCompile(
	`mux\.Handle\("([A-Z]+) ([^"]+)",\s*withPerm\(sessionAuth,\s*rbac\.([A-Za-z]+)`)

// permConstRE maps an rbac constant to the string it carries, because the
// documents publish the string and the router names the constant.
var permConstRE = regexp.MustCompile(`([A-Za-z]+)\s+Permission = "([^"]+)"`)

// docRouteRE reads one row of a published route table. The tables differ in
// their middle columns, so the pattern anchors on the two cells that matter --
// the method-and-path pair and the backticked permission -- and tolerates
// whatever sits between them.
var docRouteRE = regexp.MustCompile(
	"\\|\\s*`([A-Z]+)`\\s*\\|\\s*`(/admin/[^`]*)`\\s*\\|[^|]*\\|\\s*`([a-z]+:[a-z-]+)`\\s*\\|")

// docsWithAdminRouteTables are the tracked files that publish one.
var docsWithAdminRouteTables = []string{
	"docs/api.md",
	"docs/spec.md",
	"docs/admin-gateway.md",
}

// The router mounts this many guarded admin routes today. The floor is here
// because every assertion below iterates what the regexes found, and a pattern
// that stops matching reports the same silence as a tree with nothing wrong.
const guardedAdminRouteFloor = 30

// TestAdminRoutePermissionsMatchTheDocumentedOnes fails when a published table
// names a permission the router does not require for that route.
func TestAdminRoutePermissionsMatchTheDocumentedOnes(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	perms := permissionValues(t, root)
	routes := guardedAdminRoutes(t, root, perms)

	if len(routes) < guardedAdminRouteFloor {
		t.Fatalf("only %d guarded admin route(s) parsed out of internal/adminapi/router.go, "+
			"expected at least %d. The mount shape changed and this gate is checking almost "+
			"nothing.", len(routes), guardedAdminRouteFloor)
	}

	var checked int
	for _, rel := range docsWithAdminRouteTables {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", rel, err)
		}

		for i, line := range strings.Split(string(body), "\n") {
			m := docRouteRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			method, path, documented := m[1], m[2], m[3]

			want, mounted := routes[method+" "+path]
			if !mounted {
				// A documented route the router does not guard is the route
				// inventory's finding, not this gate's: it may be mounted
				// without withPerm, or not mounted at all.
				continue
			}
			checked++
			if documented != want {
				t.Errorf("%s:%d publishes %s %s as requiring %q, and router.go gates it on %q. "+
					"An operator reads this table to decide which role to grant, so a wrong cell "+
					"here is a wrong grant.", rel, i+1, method, path, documented, want)
			}
		}
	}

	if checked < guardedAdminRouteFloor {
		t.Errorf("only %d documented admin route row(s) matched a guarded mount across %v. "+
			"Either the tables reformatted out of reach of this pattern, or they stopped "+
			"publishing the permission column, and in both cases the cells are unchecked again.",
			checked, docsWithAdminRouteTables)
	}
}

// permissionValues maps every rbac constant name to the string it carries.
func permissionValues(t *testing.T, root string) map[string]string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(root, "internal", "rbac", "rbac.go"))
	if err != nil {
		t.Fatalf("read internal/rbac/rbac.go: %v", err)
	}
	out := map[string]string{}
	for _, m := range permConstRE.FindAllStringSubmatch(string(raw), -1) {
		out[m[1]] = m[2]
	}
	if len(out) == 0 {
		t.Fatal("no Permission constants parsed out of internal/rbac/rbac.go; the declaration " +
			"shape changed and every comparison below would be against an empty map")
	}
	return out
}

// guardedAdminRoutes maps "METHOD /path" to the permission string its mount
// requires.
func guardedAdminRoutes(t *testing.T, root string, perms map[string]string) map[string]string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(root, "internal", "adminapi", "router.go"))
	if err != nil {
		t.Fatalf("read internal/adminapi/router.go: %v", err)
	}
	out := map[string]string{}
	for _, m := range adminRouteRE.FindAllStringSubmatch(string(raw), -1) {
		method, path, constName := m[1], m[2], m[3]
		value, known := perms[constName]
		if !known {
			t.Errorf("router.go gates %s %s on rbac.%s, which is not a Permission constant in "+
				"internal/rbac/rbac.go", method, path, constName)
			continue
		}
		out[fmt.Sprintf("%s %s", method, path)] = value
	}
	return out
}
