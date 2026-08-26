package integration_test

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/repository/postgres"
)

// TestRevokeReachesAnAdminWhoCreatedAnother proves the containment lever works
// on the account it is most likely to be aimed at.
//
// auth.admin_users.created_by referenced the same table with no ON DELETE
// clause, so the default NO ACTION applied and deleting a row another row still
// named raised 23503. AdminUserRepo.Revoke is a bare DELETE, so the statement
// failed, the account stayed, and its live sessions stayed with it --
// admin_sessions cascades, but only if the parent delete succeeds.
//
// created_by is set on every create and migration 016 raises when it is null
// once any admin exists, so the admin graph is a tree: the bootstrap
// super_admin becomes unrevokable the moment it opens one other account, which
// is the first thing an operator does. And revoke is the only lever there is --
// the admin surface is list, create, revoke, with no update, no lock and no
// per-admin-session revoke.
//
// The existing repo test passes because it only ever revokes a leaf. This one
// revokes upward, which is the case that failed.
func TestRevokeReachesAnAdminWhoCreatedAnother(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()
	repo := postgres.NewAdminUserRepo(&postgres.DB{Pool: adminPool})

	creator := makeAdmin("creator-"+randomID()[:8], "super_admin")
	if err := repo.Create(ctx, creator); err != nil {
		t.Fatalf("create creator: %v", err)
	}
	child := makeAdmin("child-"+randomID()[:8], "viewer")
	child.CreatedBy = creator.ID
	if err := repo.Create(ctx, child); err != nil {
		t.Fatalf("create child: %v", err)
	}

	// A live session on the account being revoked: cascading it is the whole
	// point of deleting the admin row first, and it cascades only if that
	// delete succeeds.
	var sessions int
	if _, err := adminPool.Exec(ctx,
		`INSERT INTO auth.admin_sessions (id, admin_id, token_hash, ip, created_at, expires_at)
		 VALUES (gen_random_uuid(), $1, 'hash', '203.0.113.9', NOW(), NOW() + INTERVAL '1 hour')`,
		creator.ID); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	if err := repo.Revoke(ctx, creator.ID); err != nil {
		t.Fatalf("revoking an admin who created another failed: %v\n"+
			"This is the only containment lever there is: an admin whose credentials "+
			"are known to be compromised cannot be stopped by any other route.", err)
	}

	if got, _ := repo.GetByID(ctx, creator.ID); got != nil {
		t.Fatal("the creator is still present after Revoke")
	}

	if err := adminPool.QueryRow(ctx,
		`SELECT COUNT(*) FROM auth.admin_sessions WHERE admin_id = $1`, creator.ID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("%d live sessions survived the revoke; the cascade only runs when the "+
			"parent delete succeeds", sessions)
	}

	// SET NULL, not CASCADE. The child must survive: cascading would delete the
	// revoked admin's entire created subtree, so revoking one compromised
	// account would silently remove every account it had ever opened.
	got, err := repo.GetByID(ctx, child.ID)
	if err != nil {
		t.Fatalf("read child: %v", err)
	}
	if got == nil {
		t.Fatal("the child account was deleted with its creator. The constraint must be " +
			"ON DELETE SET NULL; CASCADE here turns one revoke into a purge.")
	}
	if got.CreatedBy != "" {
		t.Fatalf("child created_by = %q, want it cleared by SET NULL", got.CreatedBy)
	}
}
