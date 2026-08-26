package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// TestErasedUserProfileWriteIsRefused proves the Article 17 tombstone survives
// the access token that was valid when the erasure ran.
//
// The middleware validates a token's signature, issuer, audience and type and
// never reads the database, so nothing on an authenticated route knows the
// account was erased. DELETE /user/account revokes the refresh families, which
// stops renewal, but an access token already issued keeps working for the rest
// of its TTL. PUT /user/profile then merged the submitted fields onto the row it
// had just read and wrote them back, so the erased user -- or anyone holding
// that token -- could put a display name and an avatar back onto a row the
// erasure had scrubbed. The erasure reported success and did not stick.
//
// This is the same invariant insertRefreshRowSQL already carries for
// auth.refresh_tokens, under a comment headed "SECURITY INVARIANT (erasure
// completeness)". auth.users is the other table the erasure scrubs and it had no
// guard at all. Stating it in Go alone would not be enough: the handler decides
// from a row it read a moment earlier, and the statement below is what actually
// writes.
//
// Driven through the real vault_app role rather than the owner pool, because the
// column privileges are part of the claim: 015 revoked UPDATE (email, deleted,
// deleted_at) but left display_name, avatar_url, locale and mfa_required
// granted, which is exactly why the write went through.
func TestErasedUserProfileWriteIsRefused(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	applyRealGrants(t, adminPool)
	appPool := appRolePool(t, adminPool)
	ctx := context.Background()

	repo := postgres.NewUserRepo(&postgres.DB{Pool: appPool})

	liveID, erasedID := randomID(), randomID()
	for _, u := range []struct {
		id, email string
	}{
		{liveID, "live-" + liveID + "@example.com"},
		{erasedID, "victim-" + erasedID + "@example.com"},
	} {
		if _, err := adminPool.Exec(ctx,
			`INSERT INTO auth.users (id, email, display_name, created_at)
			 VALUES ($1, $2, $3, $4)`,
			u.id, u.email, "Real Name", time.Now()); err != nil {
			t.Fatalf("seed %s: %v", u.id, err)
		}
	}

	// Erase one of them the way the product does, through the function that is
	// the tombstone's only legitimate writer.
	if _, err := adminPool.Exec(ctx,
		`SELECT auth.erase_user_identity($1, $2)`,
		erasedID, "deleted-"+erasedID+"@deleted.invalid"); err != nil {
		t.Fatalf("erase: %v", err)
	}

	t.Run("an erased row refuses the write", func(t *testing.T) {
		err := repo.Update(ctx, &model.User{
			ID:          erasedID,
			DisplayName: "Victim Real Name",
			AvatarURL:   "https://example.com/victim.png",
			Locale:      "en",
		})
		if !errors.Is(err, repository.ErrUserNotUpdatable) {
			t.Fatalf("Update on an erased row returned %v, want ErrUserNotUpdatable. "+
				"A nil here is the defect: UPDATE ... WHERE matching nothing is not an "+
				"error to PostgreSQL, so the caller answers 200 for a write that did not "+
				"happen -- or, before the WHERE clause, for one that did.", err)
		}

		var name string
		if err := adminPool.QueryRow(ctx,
			`SELECT COALESCE(display_name, '') FROM auth.users WHERE id = $1`, erasedID).Scan(&name); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if name != "" {
			t.Fatalf("display_name on the erased row is %q; the scrub was undone", name)
		}
	})

	t.Run("a live row still writes", func(t *testing.T) {
		if err := repo.Update(ctx, &model.User{
			ID:          liveID,
			DisplayName: "Alice",
			AvatarURL:   "https://example.com/a.png",
			Locale:      "en",
		}); err != nil {
			t.Fatalf("Update on a live row was refused: %v. The guard is the tombstone, "+
				"not the statement.", err)
		}
		var name string
		if err := adminPool.QueryRow(ctx,
			`SELECT display_name FROM auth.users WHERE id = $1`, liveID).Scan(&name); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if name != "Alice" {
			t.Fatalf("display_name = %q, want Alice", name)
		}
	})

	t.Run("an id that never existed is refused the same way", func(t *testing.T) {
		err := repo.Update(ctx, &model.User{ID: randomID(), DisplayName: "Nobody"})
		if !errors.Is(err, repository.ErrUserNotUpdatable) {
			t.Fatalf("Update on an absent id returned %v, want ErrUserNotUpdatable", err)
		}
	})
}
