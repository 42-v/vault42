package seed

import (
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/rbac"
)

// TestValidateRejectsAnAdminRoleTheRBACPackageDefinesNoTierFor pins the seed
// validator to rbac's vocabulary instead of a hand-written copy of it.
//
// "admin" is the name that motivated this. It is not an admin tier: rbac
// resolves no permissions for it, auth.admin_users.role has a foreign key to
// auth.admin_roles which holds only the three real tiers, and migration 016
// refuses a role whose rank it cannot look up. So a seed file naming it fails
// closed either way.
//
// What breaks in production if this property fails is the diagnosis, not the
// authorization. The seed file is accepted, the clients and users ahead of the
// admins array are written, and the run then dies at INSERT with a foreign-key
// violation naming a constraint. The operator is told a constraint name where
// they need to be told which role is wrong and which ones are not, and the run
// has already half-applied.
func TestValidateRejectsAnAdminRoleTheRBACPackageDefinesNoTierFor(t *testing.T) {
	err := validate(&SeedFile{Admins: []AdminSeed{{
		Username: "root",
		Password: "fifteenCharsExactly!!",
		Role:     "admin",
	}}})
	if err == nil {
		t.Fatal(`validate accepted the admin role "admin". rbac defines no tier for it, so the ` +
			`row is refused later by the foreign key on auth.admin_users.role and by migration ` +
			`016, leaving the seed run half-applied and the operator holding a constraint name.`)
	}

	if !strings.Contains(err.Error(), `"admin"`) {
		t.Errorf("error must name the offending role so the operator can find it in the file, got: %v", err)
	}
	for _, r := range rbac.ValidRoles {
		if !strings.Contains(err.Error(), string(r)) {
			t.Errorf("error must list the valid role %q so the fix does not need the source, got: %v", r, err)
		}
	}
}

// TestTheAdminSeedVocabularyIsExactlyTheRBACTiers walks both directions so the
// validator cannot drift from rbac in either.
//
// Accepting a name rbac does not know defers the rejection to the database, as
// above. Rejecting a name rbac does know is the opposite failure and is worse
// on the day it happens: a new tier would be unseedable, and the only other way
// to create the first admin of that tier is EnsureFirstAdmin or hand-written
// SQL against the admin table.
func TestTheAdminSeedVocabularyIsExactlyTheRBACTiers(t *testing.T) {
	for _, r := range rbac.ValidRoles {
		t.Run("accepts "+string(r), func(t *testing.T) {
			err := validate(&SeedFile{Admins: []AdminSeed{{
				Username: "a", Password: "fifteenCharsExactly!!", Role: string(r),
			}}})
			if err != nil {
				t.Fatalf("validate rejected %q, which rbac.IsValidRole accepts: %v", r, err)
			}
		})
	}

	// Every entry here is a name some caller has plausibly written: the legacy
	// tier, the end-user default role, and the case and whitespace variants that
	// rbac rejects literally.
	notTiers := []string{"admin", "user", "root", "Viewer", "SUPER_ADMIN", " super_admin", "operator ", ""}
	for _, name := range notTiers {
		t.Run("rejects "+name, func(t *testing.T) {
			if rbac.IsValidRole(name) {
				t.Fatalf("test fixture is wrong: rbac.IsValidRole(%q) is true", name)
			}
			err := validate(&SeedFile{Admins: []AdminSeed{{
				Username: "a", Password: "fifteenCharsExactly!!", Role: name,
			}}})
			if err == nil {
				t.Fatalf("validate accepted %q, which rbac.IsValidRole rejects", name)
			}
		})
	}
}
