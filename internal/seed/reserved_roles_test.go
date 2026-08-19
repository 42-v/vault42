package seed_test

import (
	"testing"

	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/internal/seed"
)

// appRoleNamesSeededByMigration005 are the end-user role names migration 005
// writes into auth.app_roles as reserved core roles.
//
// Two of them collide with admin-plane tier names. That collision is why
// seed.ReservedAdminRoles cannot simply mirror rbac.ValidRoles: stripping
// 'viewer' or 'operator' from a user JWT would remove a role the user
// legitimately holds.
var appRoleNamesSeededByMigration005 = map[string]bool{
	"user":     true,
	"viewer":   true,
	"operator": true,
}

// TestReservedAdminRolesDecisionIsRevisitedWhenATierIsAdded fails when a new
// admin tier appears in rbac.ValidRoles without a decision about whether users
// may hold that name.
//
// The failure mode this exists for is silent. seed.ReservedAdminRoles is what
// stops a directly-inserted database row from putting an admin tier name into a
// user's JWT, and it is a hand-written list. Adding a tier to rbac.ValidRoles
// and not to this list leaves the new name grantable to ordinary users, and
// nothing anywhere would say so: no compiler error, no failing test, and no
// runtime error, because the name is valid in both vocabularies.
//
// A tier is allowed to be absent only when it is also a seeded app role, which
// is the deliberate exception for 'viewer' and 'operator'. Anything else has to
// be listed.
func TestReservedAdminRolesDecisionIsRevisitedWhenATierIsAdded(t *testing.T) {
	for _, role := range rbac.ValidRoles {
		name := string(role)

		if seed.ReservedAdminRoles[name] {
			continue
		}
		if appRoleNamesSeededByMigration005[name] {
			continue
		}

		t.Errorf("rbac.ValidRoles contains %q, which is neither in seed.ReservedAdminRoles nor a "+
			"seeded app role in migration 005.\n"+
			"That combination means a user row carrying %q keeps it through FilterUserRoles and "+
			"into a signed JWT, so a relying party is told the holder has an admin tier. Either "+
			"add it to ReservedAdminRoles, or, if it is meant to be an end-user role too, add it "+
			"to appRoleNamesSeededByMigration005 here and say why in that migration.", name, name)
	}
}

// TestTheReservedListIsNotMistakenForAnInventoryOfRealRoles pins the other
// direction, which is documentation rather than security.
//
// ReservedAdminRoles carries 'admin', a name rbac defines no tier for. Harmless,
// but it means the list cannot be read as the set of admin roles, and a reader
// who assumes it can will conclude the vocabulary has four tiers.
func TestTheReservedListIsNotMistakenForAnInventoryOfRealRoles(t *testing.T) {
	valid := map[string]bool{}
	for _, r := range rbac.ValidRoles {
		valid[string(r)] = true
	}

	var phantom []string
	for name := range seed.ReservedAdminRoles {
		if !valid[name] {
			phantom = append(phantom, name)
		}
	}

	// One phantom entry is the known, documented state. Asserting the count
	// rather than the absence keeps this from becoming a chore to silence while
	// still failing if the list grows more of them.
	if len(phantom) > 1 {
		t.Errorf("seed.ReservedAdminRoles holds %d names that are not rbac tiers (%v). One is the "+
			"documented legacy entry; more than that means the two vocabularies are drifting "+
			"and the comment on ReservedAdminRoles no longer describes the file.",
			len(phantom), phantom)
	}
}
