package rbac

import (
	"sort"
	"strings"
	"testing"
)

// The expected grant matrix, written out as literal permission strings rather
// than as the constants. Naming the constants would compare the package against
// itself: renaming KeysRevoke's value from "keys:revoke" to "keys:revoked"
// would keep such a test green while every route guarded by the old string
// silently stopped resolving. The strings below are the wire contract that
// internal/adminapi/router.go and the compliance suite both depend on.
var (
	viewerHolds = []string{
		"keys:list", "audit:read", "users:list", "users:read",
		"sessions:list", "config:read", "metrics:read", "roles:list", "email:read",
	}
	operatorAdds = []string{
		"keys:rotate", "users:lock", "users:unlock", "sessions:revoke",
		"clients:list", "clients:read",
	}
	superAdminAdds = []string{
		"keys:revoke", "users:delete", "users:import",
		"clients:create", "clients:revoke", "clients:rotate",
		"config:write", "admins:manage", "admins:create", "admins:revoke",
		"roles:create", "roles:delete", "email:write", "email:delete",
	}
)

func union(sets ...[]string) map[Permission]bool {
	out := make(map[Permission]bool)
	for _, set := range sets {
		for _, p := range set {
			out[Permission(p)] = true
		}
	}
	return out
}

func vocabulary() map[Permission]bool {
	return union(viewerHolds, operatorAdds, superAdminAdds)
}

// A role that holds one permission too many is a privilege escalation and a
// role that holds one too few is an outage, and both look identical from
// inside the package. Asserting the whole matrix against literal strings is
// what tells them apart: every cell is checked in both directions, so moving
// users:delete down a tier fails here rather than at the next incident.
func TestEachRoleHoldsExactlyItsOwnTierAndEveryTierBeneathIt(t *testing.T) {
	cases := []struct {
		role  Role
		holds map[Permission]bool
	}{
		{RoleViewer, union(viewerHolds)},
		{RoleOperator, union(viewerHolds, operatorAdds)},
		{RoleSuperAdmin, union(viewerHolds, operatorAdds, superAdminAdds)},
	}

	all := vocabulary()
	for _, tc := range cases {
		for perm := range all {
			want := tc.holds[perm]
			if got := HasPermission(tc.role, perm); got != want {
				t.Errorf("HasPermission(%q, %q) = %v, want %v", tc.role, perm, got, want)
			}
		}
	}
}

// Every path into the role column has to fail closed. An admin row written
// before a role was renamed, a struct built without its constructor, and a
// string an attacker got into the column all arrive here as a Role that
// matches no case, and any one of them resolving to a tier hands out the admin
// plane. The zero value matters most: model.AdminUser{} has Role "", so a
// handler that reads an admin it failed to load must authorize nothing.
func TestAnUnknownEmptyOrZeroValueRoleHoldsNoPermissionAtAll(t *testing.T) {
	var zero Role

	roles := []Role{
		zero, "", " ", "admin", "root", "*", "superadmin",
		"Viewer", "VIEWER", "Super_Admin", "SUPER_ADMIN",
		" super_admin", "super_admin ", "super_admin\n", "\tviewer",
		"viewer,super_admin", "operator;super_admin",
	}

	for _, role := range roles {
		for perm := range vocabulary() {
			if HasPermission(role, perm) {
				t.Errorf("unrecognized role %q was granted %q", role, perm)
			}
		}
		if IsValidRole(string(role)) {
			t.Errorf("IsValidRole(%q) = true, want false", role)
		}
		if perms := PermissionsForRole(role); perms != nil {
			t.Errorf("PermissionsForRole(%q) = %v, want nil", role, perms)
		}
	}
}

// The permission vocabulary is namespaced with a colon, which is exactly the
// shape that invites a prefix match. If "users:read" ever satisfied a check for
// "users:read:all", or "users" satisfied a check for "users:delete", then
// widening the vocabulary later would retroactively widen the viewer role. Map
// lookup gives exact matching for free today; this pins it so that a future
// rewrite into a matcher cannot quietly relax it.
func TestAPermissionIsMatchedExactlyAndNeverByPrefixSuffixCaseOrWildcard(t *testing.T) {
	nearMisses := []Permission{
		"", " ", "*", "users", "users:", "users:*", ":read",
		"users:read:all", "users:reads", "users:rea", "sers:read",
		"users:read ", " users:read", "users:read\n", "users :read",
		"USERS:READ", "Users:Read", "keys:LIST", "config:Write",
		"admins:create ", "*:*", "users:read|users:delete",
	}

	for _, role := range ValidRoles {
		for _, perm := range nearMisses {
			if HasPermission(role, perm) {
				t.Errorf("role %q was granted the non-vocabulary permission %q", role, perm)
			}
		}
	}
}

// The three tables are additive: HasPermission consults a tier and then falls
// through to the one below it. A permission listed in two tables would still
// resolve, so the duplicate would never show up as a failing authorization. It
// would show up as a permission that cannot be demoted, because deleting it
// from superAdminPerms would leave the copy in viewerPerms granting it to
// everyone.
func TestTheThreeTierTablesArePairwiseDisjoint(t *testing.T) {
	tiers := []struct {
		name  string
		perms map[Permission]bool
	}{
		{"viewer", viewerPerms},
		{"operator", operatorPerms},
		{"super_admin", superAdminPerms},
	}

	for i := range tiers {
		for j := i + 1; j < len(tiers); j++ {
			for perm := range tiers[i].perms {
				if tiers[j].perms[perm] {
					t.Errorf("%q appears in both %s and %s; a tier must add only what the tier below lacks",
						perm, tiers[i].name, tiers[j].name)
				}
			}
		}
	}
}

// PermissionsForRole iterates a hand-written literal, and every compliance
// assertion about this model reads the role's abilities through it:
// tests/compliance/owasp_access_control_test.go derives the viewer least-
// privilege check and the route-guard vocabulary from its output. A permission
// granted in a tier table but missing from that literal is therefore live in
// production and invisible to the audit that is supposed to catch it. The
// reverse, a name in the literal that no tier grants, is a route that would
// answer 403 to every role including super_admin.
func TestPermissionsForRoleEnumeratesEveryPermissionTheTierTablesGrant(t *testing.T) {
	granted := make(map[Permission]bool)
	for _, tier := range []map[Permission]bool{viewerPerms, operatorPerms, superAdminPerms} {
		for perm, ok := range tier {
			if ok {
				granted[perm] = true
			}
		}
	}

	enumerated := make(map[Permission]bool)
	for _, p := range PermissionsForRole(RoleSuperAdmin) {
		enumerated[p] = true
	}

	for perm := range granted {
		if !enumerated[perm] {
			t.Errorf("%q is granted by a tier table but is not in the list PermissionsForRole walks, so the compliance suite cannot see it", perm)
		}
	}
	for perm := range enumerated {
		if !granted[perm] {
			t.Errorf("%q is enumerated by PermissionsForRole but no tier grants it", perm)
		}
	}

	// And the union is the vocabulary this file states, so adding a permission
	// without deciding which tier owns it cannot pass unnoticed.
	for perm := range vocabulary() {
		if !granted[perm] {
			t.Errorf("%q is part of the documented vocabulary but no tier grants it", perm)
		}
	}
	if len(granted) != len(vocabulary()) {
		t.Errorf("tier tables grant %d permissions, the documented vocabulary has %d", len(granted), len(vocabulary()))
	}
}

// ValidRoles is ordered lowest tier first, and this pins that order against the
// permission sets themselves: each role must hold a strict superset of the one
// below it. That is a property of this package, provable from its own tables,
// which is why it survives even though nothing outside the package reads the
// order any more. internal/seed once took a role's index here as its privilege
// rank and now keeps its own map of the ranks the database holds.
func TestValidRolesIsOrderedByStrictlyIncreasingPrivilege(t *testing.T) {
	if len(ValidRoles) < 2 {
		t.Fatalf("ValidRoles has %d entries; there is no ordering left to check", len(ValidRoles))
	}

	seen := make(map[Role]bool, len(ValidRoles))
	for _, r := range ValidRoles {
		if seen[r] {
			t.Errorf("ValidRoles lists %q twice", r)
		}
		seen[r] = true
		if !IsValidRole(string(r)) {
			t.Errorf("ValidRoles contains %q, which IsValidRole rejects", r)
		}
	}
	for _, r := range []Role{RoleViewer, RoleOperator, RoleSuperAdmin} {
		if !seen[r] {
			t.Errorf("ValidRoles is missing %q, so internal/seed cannot rank an admin holding it", r)
		}
	}

	for i := 1; i < len(ValidRoles); i++ {
		lower, higher := ValidRoles[i-1], ValidRoles[i]
		lowerSet := make(map[Permission]bool)
		for _, p := range PermissionsForRole(lower) {
			lowerSet[p] = true
		}
		higherCount := 0
		for _, p := range PermissionsForRole(higher) {
			higherCount++
			delete(lowerSet, p)
		}
		if len(lowerSet) != 0 {
			missing := make([]string, 0, len(lowerSet))
			for p := range lowerSet {
				missing = append(missing, string(p))
			}
			sort.Strings(missing)
			t.Errorf("ValidRoles puts %q above %q, but %q lacks %s", higher, lower, higher, strings.Join(missing, ", "))
		}
		if higherCount <= len(PermissionsForRole(lower)) {
			t.Errorf("ValidRoles puts %q above %q, but %q holds no more permissions", higher, lower, higher)
		}
	}
}

// The literal permission values are the contract with the admin router and with
// the compliance suite, which reconstructs "resource:verb" from each constant's
// identifier. Pinning constant to value here means a rename that changes only
// one half of the pair fails in this package, next to the definition, instead of
// in a compliance test that reports it as an unguarded route.
func TestEveryPermissionConstantCarriesItsDocumentedValue(t *testing.T) {
	want := map[Permission]string{
		KeysList: "keys:list", KeysRotate: "keys:rotate", KeysRevoke: "keys:revoke",
		AuditRead: "audit:read",
		UsersList: "users:list", UsersRead: "users:read", UsersLock: "users:lock",
		UsersUnlock: "users:unlock", UsersDelete: "users:delete", UsersImport: "users:import",
		SessionsList: "sessions:list", SessionsRevoke: "sessions:revoke",
		ClientsList: "clients:list", ClientsRead: "clients:read", ClientsCreate: "clients:create",
		ClientsRevoke: "clients:revoke", ClientsRotate: "clients:rotate",
		ConfigRead: "config:read", ConfigWrite: "config:write", MetricsRead: "metrics:read",
		AdminsManage: "admins:manage", AdminsCreate: "admins:create", AdminsRevoke: "admins:revoke",
		RolesList: "roles:list", RolesCreate: "roles:create", RolesDelete: "roles:delete",
		EmailRead: "email:read", EmailWrite: "email:write", EmailDelete: "email:delete",
	}
	if len(want) != len(vocabulary()) {
		t.Fatalf("pinned %d constants against a vocabulary of %d", len(want), len(vocabulary()))
	}
	for constant, value := range want {
		if string(constant) != value {
			t.Errorf("permission constant holds %q, want %q", string(constant), value)
		}
	}

	roles := map[Role]string{RoleViewer: "viewer", RoleOperator: "operator", RoleSuperAdmin: "super_admin"}
	for constant, value := range roles {
		if string(constant) != value {
			t.Errorf("role constant holds %q, want %q; the value is the contract with auth.admin_users.role", string(constant), value)
		}
	}
}
