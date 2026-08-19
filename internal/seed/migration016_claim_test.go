package seed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMigration016DoesNotCreditGoWithEnforcingTheRankRule guards the one claim
// in that migration's header that a reader acts on.
//
// The rank rule has exactly one implementation, the trigger 016 installs.
// adminapi.CreateAdmin is gated on the admins:create permission and validates
// the requested role, and then records the acting admin in created_by; it
// compares no ranks. A header that says Go already enforces the rule reads as
// the trigger being a second copy of a check that exists, which is the reading
// that makes the next grant change look safe: moving admins:create down to
// operator would then be widening what operator may create, and instead it is
// escalation to super_admin, because an operator holding it could create one and
// log in as it. The header is where that is decided, since the permission tables
// themselves carry no rank.
//
// The check is on the prose because the defect is in the prose. Nothing about
// the SQL or the Go changed when the claim became false.
func TestMigration016DoesNotCreditGoWithEnforcingTheRankRule(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "016_admin_insert_escalation_guard.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	header := strings.ToLower(string(raw))

	for _, claim := range []string{
		"the go rbac layer already enforces",
		"already enforces at the handler",
	} {
		if strings.Contains(header, claim) {
			t.Errorf("migration 016 says %q. No Go path compares an admin's rank to its creator's: "+
				"adminapi.CreateAdmin checks the admins:create permission and rbac.IsValidRole and "+
				"nothing else.", claim)
		}
	}

	if !strings.Contains(header, "admins:create") {
		t.Error("migration 016 does not name admins:create. That the permission belongs to " +
			"super_admin alone is the whole reason a creator cannot be outranked above the " +
			"database, so a header that omits it leaves the trigger looking redundant.")
	}
}
