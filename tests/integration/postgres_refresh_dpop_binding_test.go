package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// Migration 038 puts the DPoP sender constraint in the schema rather than only
// in Go. The Go check (AuthService.enforceDPoPBinding) refuses the rotation; the
// statement shape here makes the re-binding impossible even if that check were
// bypassed, removed, or reached from a path that does not run it — which is the
// failure mode this whole release exists for, a control that is present and not
// on the path it claims to protect.
//
// Two properties, and they are not the same one:
//
//   - a family that HAS a binding keeps it, whatever the insert is handed;
//   - a family that has NO binding does not acquire one, which COALESCE cannot
//     express because NULL is a meaningful value in this column.
func TestRefreshFamilyDPoPBindingIsInheritedNotSupplied(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	userRepo := postgres.NewUserRepo(db)
	repo := postgres.NewRefreshTokenRepo(db)
	ctx := context.Background()

	user := makeUser("rt-dpop@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	row := func(hash, familyID, jkt string) *model.RefreshToken {
		now := time.Now().UTC().Truncate(time.Microsecond)
		return &model.RefreshToken{
			ID: randomID(), UserID: user.ID, TokenHash: hash,
			FamilyID: familyID, DPoPJKT: jkt,
			ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
		}
	}
	readBack := func(t *testing.T, hash string) *model.RefreshToken {
		t.Helper()
		got, err := repo.GetByTokenHash(ctx, hash)
		if err != nil {
			t.Fatalf("GetByTokenHash(%s): %v", hash, err)
		}
		if got == nil {
			t.Fatalf("row %s was not inserted", hash)
		}
		return got
	}

	t.Run("the first row of a family establishes the binding", func(t *testing.T) {
		fam := randomID()
		if err := repo.Create(ctx, row("dpop-first", fam, "VICTIM-JKT")); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if got := readBack(t, "dpop-first").DPoPJKT; got != "VICTIM-JKT" {
			t.Errorf("DPoPJKT = %q, want VICTIM-JKT; a login's proof did not establish the binding", got)
		}
	})

	t.Run("a successor cannot re-bind the family", func(t *testing.T) {
		fam := randomID()
		if err := repo.Create(ctx, row("dpop-rebind-1", fam, "VICTIM-JKT")); err != nil {
			t.Fatalf("Create first: %v", err)
		}
		// The attacker's value, handed to the insert as if the Go guard had been
		// removed. The statement must discard it.
		if err := repo.Create(ctx, row("dpop-rebind-2", fam, "ATTACKER-JKT")); err != nil {
			t.Fatalf("Create successor: %v", err)
		}
		if got := readBack(t, "dpop-rebind-2").DPoPJKT; got != "VICTIM-JKT" {
			t.Errorf("the successor row carries %q; a rotation re-bound the family to the key the "+
				"caller named, which is the whole attack", got)
		}
	})

	t.Run("a successor cannot upgrade an unbound family", func(t *testing.T) {
		fam := randomID()
		if err := repo.Create(ctx, row("dpop-upgrade-1", fam, "")); err != nil {
			t.Fatalf("Create first: %v", err)
		}
		if err := repo.Create(ctx, row("dpop-upgrade-2", fam, "ATTACKER-JKT")); err != nil {
			t.Fatalf("Create successor: %v", err)
		}
		if got := readBack(t, "dpop-upgrade-2").DPoPJKT; got != "" {
			t.Errorf("an unbound family acquired the binding %q from a caller; \"bound\" would then "+
				"mean \"bound to whoever asked last\"", got)
		}
	})

	t.Run("CreateWithinCap inherits identically", func(t *testing.T) {
		// The cap path is a second insert site sharing insertRefreshRowSQL. If it
		// ever stops sharing it, this is what notices.
		fam := randomID()
		if err := repo.CreateWithinCap(ctx, row("dpop-cap-1", fam, "VICTIM-JKT"), 10); err != nil {
			t.Fatalf("CreateWithinCap first: %v", err)
		}
		if err := repo.CreateWithinCap(ctx, row("dpop-cap-2", fam, "ATTACKER-JKT"), 10); err != nil {
			t.Fatalf("CreateWithinCap successor: %v", err)
		}
		if got := readBack(t, "dpop-cap-2").DPoPJKT; got != "VICTIM-JKT" {
			t.Errorf("the capped insert path carries %q, want VICTIM-JKT", got)
		}
	})

	t.Run("an unbound family stays readable as empty, not as an error", func(t *testing.T) {
		fam := randomID()
		if err := repo.Create(ctx, row("dpop-null", fam, "")); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got := readBack(t, "dpop-null")
		if got.DPoPJKT != "" {
			t.Errorf("DPoPJKT = %q, want empty for a bearer family", got.DPoPJKT)
		}
	})
}

// Migration 038 narrows vault_app from table-level UPDATE on auth.refresh_tokens
// to UPDATE (used, revoked).
//
// It is written as REVOKE-then-GRANT rather than as the column REVOKE migration
// 029 uses, because 001 grants this table at TABLE level and a column-level
// REVOKE against a table-level grant removes nothing while reporting success.
// The first subtest is the one that would have caught that: it asserts the write
// is actually refused, not that a REVOKE statement exists.
func TestVaultAppCannotRewriteADPoPBinding(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	applyRealGrants(t, adminPool)
	appPool := appRolePool(t, adminPool)

	seedRepo := postgres.NewRefreshTokenRepo(&postgres.DB{Pool: adminPool})
	userRepo := postgres.NewUserRepo(&postgres.DB{Pool: adminPool})
	user := makeUser("rt-dpop-grant@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	tok := &model.RefreshToken{
		ID: randomID(), UserID: user.ID, TokenHash: "grant-dpop", FamilyID: randomID(),
		DPoPJKT: "VICTIM-JKT", ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}
	if err := seedRepo.Create(ctx, tok); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	denied := func(err error) bool {
		return err != nil && (strings.Contains(err.Error(), "42501") ||
			strings.Contains(err.Error(), "permission denied"))
	}

	t.Run("rewriting dpop_jkt is refused", func(t *testing.T) {
		_, err := appPool.Exec(ctx,
			`UPDATE auth.refresh_tokens SET dpop_jkt = $1 WHERE id = $2`, "ATTACKER-JKT", tok.ID)
		if !denied(err) {
			t.Fatalf("vault_app rewrote a family's DPoP binding (err=%v); the web-facing role can "+
				"re-bind any session to any key with one statement", err)
		}
		var jkt string
		if err := adminPool.QueryRow(ctx,
			`SELECT COALESCE(dpop_jkt, '') FROM auth.refresh_tokens WHERE id = $1`, tok.ID).Scan(&jkt); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if jkt != "VICTIM-JKT" {
			t.Errorf("dpop_jkt = %q, want VICTIM-JKT", jkt)
		}
	})

	t.Run("moving family_created_at is refused", func(t *testing.T) {
		// Not the target of 038, but the same narrowing covers it, and 013's
		// absolute session lifetime stops resting on one statement's shape.
		_, err := appPool.Exec(ctx,
			`UPDATE auth.refresh_tokens SET family_created_at = NOW() WHERE id = $1`, tok.ID)
		if !denied(err) {
			t.Errorf("vault_app moved a family's birth date (err=%v); the absolute session "+
				"lifetime can be reset from the application role", err)
		}
	})

	t.Run("the two writes the product really makes are still permitted", func(t *testing.T) {
		appRepo := postgres.NewRefreshTokenRepo(&postgres.DB{Pool: appPool})
		// MarkUsed and RevokeFamily are the only UPDATEs in the product, and
		// RevokeFamily takes a FOR UPDATE row lock first — which needs UPDATE on
		// the relation. A column-level grant satisfies that; if it did not, the
		// narrowing would break logout and refresh rather than fail in review.
		ok, err := appRepo.MarkUsed(ctx, tok.ID)
		if err != nil || !ok {
			t.Fatalf("MarkUsed as vault_app: ok=%v err=%v", ok, err)
		}
		if err := appRepo.RevokeFamily(ctx, tok.FamilyID); err != nil {
			t.Fatalf("RevokeFamily as vault_app (this takes SELECT ... FOR UPDATE): %v", err)
		}
	})

	t.Run("inserting a new family with a binding is still permitted", func(t *testing.T) {
		// INSERT stays at table level, so a login can still establish a binding.
		appRepo := postgres.NewRefreshTokenRepo(&postgres.DB{Pool: appPool})
		fresh := &model.RefreshToken{
			ID: randomID(), UserID: user.ID, TokenHash: "grant-dpop-insert", FamilyID: randomID(),
			DPoPJKT: "NEW-JKT", ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
		}
		if err := appRepo.Create(ctx, fresh); err != nil {
			t.Fatalf("vault_app cannot open a bound session: %v", err)
		}
		got, err := appRepo.GetByTokenHash(ctx, "grant-dpop-insert")
		if err != nil || got == nil {
			t.Fatalf("read back: %v", err)
		}
		if got.DPoPJKT != "NEW-JKT" {
			t.Errorf("DPoPJKT = %q, want NEW-JKT", got.DPoPJKT)
		}
	})
}
