package seed

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"testing"

	"github.com/42-v/vault42/internal/rbac"
)

// TestTheAdminTierRanksMirrorTheRanksMigration001Seeds pins seed's idea of
// privilege rank to the database's.
//
// seedAdminCreator attributes a seeded admin row to the highest-ranked existing
// account, and that account becomes the created_by that migration 016's INSERT
// trigger measures the new role against. The trigger reads
// auth.admin_roles.rank. If the two rankings disagree, seed names the wrong
// account and the trigger refuses the row: seeding a super_admin into a
// populated deployment fails with "cannot create super_admin above creator
// viewer", and the seed run has already written the clients and users ahead of
// it. Nothing before the INSERT would report the disagreement, because both
// rankings are individually self-consistent.
func TestTheAdminTierRanksMirrorTheRanksMigration001Seeds(t *testing.T) {
	dbRanks := adminRolesRankedByMigration001(t)

	for _, r := range rbac.ValidRoles {
		want, ok := dbRanks[string(r)]
		if !ok {
			t.Errorf("rbac tier %q has no row in migration 001's auth.admin_roles seed, so "+
				"auth.admin_users.role cannot hold it: the foreign key refuses the INSERT and "+
				"migration 016 refuses the role it cannot rank", r)
			continue
		}
		if got := adminRoleRank(string(r)); got != want {
			t.Errorf("adminRoleRank(%q) = %d, migration 001 ranks it %d. What seedAdminCreator "+
				"needs is the same ordering, not the same number, but adminTierRanks claims to be "+
				"the rank column and equality is the form of that claim a test can check without "+
				"reasoning about which reorderings happen to preserve the order.",
				r, got, want)
		}
	}

	for role := range dbRanks {
		if !rbac.IsValidRole(role) {
			t.Errorf("migration 001 seeds admin role %q, which rbac.IsValidRole rejects. An admin "+
				"holding it is authorized by rbac.HasPermission, which resolves no permissions for "+
				"an unrecognized role, so the account silently holds nothing.", role)
		}
	}
}

// TestAdminRoleRankIgnoresTheOrderOfRbacValidRoles states the property that
// keeps the ranking correct when something else in the process reorders that
// slice.
//
// rbac.ValidRoles is exported and is a slice, so any importer can sort it in
// place. A role picker presenting the strongest tier first is the realistic way
// that happens, and it is not a change to rbac at all, so no test in rbac would
// see it. If rank were the position in that slice, the sort would invert every
// rank in this package at runtime: seedAdminCreator would attribute a seeded
// admin to the weakest existing account, and migration 016 would refuse every
// seeded row above it.
func TestAdminRoleRankIgnoresTheOrderOfRbacValidRoles(t *testing.T) {
	original := append([]rbac.Role(nil), rbac.ValidRoles...)
	t.Cleanup(func() { rbac.ValidRoles = original })

	// Strongest tier first, which is the order a picker would want.
	reversed := make([]rbac.Role, 0, len(original))
	for i := len(original) - 1; i >= 0; i-- {
		reversed = append(reversed, original[i])
	}
	rbac.ValidRoles = reversed

	viewer, operator, super := adminRoleRank("viewer"), adminRoleRank("operator"), adminRoleRank("super_admin")
	if !(viewer < operator && operator < super) {
		t.Fatalf("with rbac.ValidRoles reordered to %v the ranks are viewer=%d operator=%d "+
			"super_admin=%d, which is not the tier order. seedAdminCreator would name the "+
			"weakest admin as created_by and migration 016 would refuse the seeded row.",
			reversed, viewer, operator, super)
	}
}

// TestAnUnknownAdminRoleRanksBelowEveryTier covers the account seedAdminCreator
// must never pick.
//
// A row whose role is not a tier can exist: the role column is a foreign key to
// auth.admin_roles, so a role added there by hand satisfies the database while
// rbac grants it nothing. Ranking such a row above a real tier would name it as
// created_by, and migration 016 would then refuse anything above whatever rank
// the database happens to have given it.
func TestAnUnknownAdminRoleRanksBelowEveryTier(t *testing.T) {
	for _, unknown := range []string{"admin", "root", "", "Viewer", "super_admin "} {
		for _, tier := range rbac.ValidRoles {
			if got, floor := adminRoleRank(unknown), adminRoleRank(string(tier)); got >= floor {
				t.Errorf("adminRoleRank(%q) = %d, which is not below the %q rank %d",
					unknown, got, tier, floor)
			}
		}
	}
}

// adminRolesRankedByMigration001 reads the ranks out of the migration rather
// than restating them here. A copy in the test would drift with the copy in the
// source and agree with it while both were wrong.
func adminRolesRankedByMigration001(t *testing.T) map[string]int {
	t.Helper()

	path := filepath.Join("..", "..", "migrations", "001_initial_schema.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	// Matches one VALUES row of the auth.admin_roles seed:
	//     ('viewer', 'Read-only access to ...', 1),
	row := regexp.MustCompile(`(?m)^\s*\('([a-z_]+)',\s*'[^']*',\s*(\d+)\)[,;]`)

	insert := regexp.MustCompile(`INSERT INTO auth\.admin_roles[^;]*;`).Find(raw)
	if insert == nil {
		t.Fatalf("no INSERT INTO auth.admin_roles found in %s: the ranks this package mirrors are "+
			"no longer where this gate looks for them, so the gate would pass on anything", path)
	}

	ranks := make(map[string]int)
	for _, m := range row.FindAllStringSubmatch(string(insert), -1) {
		rank, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("rank %q of role %q is not a number: %v", m[2], m[1], err)
		}
		ranks[m[1]] = rank
	}

	if len(ranks) == 0 {
		t.Fatalf("parsed no roles out of the auth.admin_roles seed in %s", path)
	}
	if len(ranks) != len(rbac.ValidRoles) {
		names := make([]string, 0, len(ranks))
		for name := range ranks {
			names = append(names, name)
		}
		sort.Strings(names)
		t.Fatalf("migration 001 seeds %d admin roles %v but rbac has %d tiers %v. The two "+
			"vocabularies are the same vocabulary: a role in one and not the other is either an "+
			"unseedable tier or a database role that authorizes nothing.",
			len(ranks), names, len(rbac.ValidRoles), rbac.ValidRoles)
	}
	return ranks
}
