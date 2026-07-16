package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// TestPostgresBulkDeleteOps covers the "delete all for user/pseudonym" and
// bulk-revoke methods that the account-erasure and session-management paths use.
// These are otherwise-uncovered repository methods.
func TestPostgresBulkDeleteOps(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	db := &postgres.DB{Pool: pool}
	ctx := context.Background()

	userRepo := postgres.NewUserRepo(db)
	user := makeUser("erase-ops@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	t.Run("DeviceRepo.DeleteAllForUser", func(t *testing.T) {
		repo := postgres.NewDeviceRepo(db)
		now := time.Now().UTC().Truncate(time.Microsecond)
		for i := 0; i < 2; i++ {
			d := &model.Device{
				ID: randomID(), UserID: user.ID, FingerprintHash: randomID(),
				FriendlyName: "dev", IP: "203.0.113.1", UserAgent: "ua",
				FirstSeenAt: now, CreatedAt: now,
			}
			if err := repo.Create(ctx, d); err != nil {
				t.Fatalf("create device: %v", err)
			}
		}
		if err := repo.DeleteAllForUser(ctx, user.ID); err != nil {
			t.Fatalf("DeleteAllForUser: %v", err)
		}
		list, err := repo.ListByUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}
		if len(list) != 0 {
			t.Errorf("devices remain after DeleteAllForUser: %d", len(list))
		}
	})

	t.Run("PasswordHistoryRepo.DeleteAllForUser", func(t *testing.T) {
		repo := postgres.NewPasswordHistoryRepo(db)
		e := &model.PasswordHistory{ID: randomID(), UserID: user.ID, PasswordHash: "$argon2id$hash", CreatedAt: time.Now().UTC()}
		if err := repo.Create(ctx, e); err != nil {
			t.Fatalf("create pw history: %v", err)
		}
		if err := repo.DeleteAllForUser(ctx, user.ID); err != nil {
			t.Fatalf("DeleteAllForUser: %v", err)
		}
	})

	t.Run("SocialAccountRepo.DeleteAllForUser", func(t *testing.T) {
		repo := postgres.NewSocialAccountRepo(db)
		a := &model.SocialAccount{
			ID: randomID(), UserID: user.ID, Provider: "github",
			ProviderUserID: "gh-123", Email: "erase-ops@test.com", CreatedAt: time.Now().UTC(),
		}
		if err := repo.Create(ctx, a); err != nil {
			t.Fatalf("create social: %v", err)
		}
		if err := repo.DeleteAllForUser(ctx, user.ID); err != nil {
			t.Fatalf("DeleteAllForUser: %v", err)
		}
		list, err := repo.ListByUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}
		if len(list) != 0 {
			t.Error("social account remains after DeleteAllForUser")
		}
	})

	// The MFA authenticators are the ones that used to survive erasure. Their FKs
	// carry ON DELETE CASCADE, but erasure scrubs the user row with an UPDATE, so
	// the cascade never fires — these deletes have to be explicit. Asserted here
	// against a real Postgres, not a mock, because the bug was precisely that the
	// schema looked like it handled this and did not.
	t.Run("WebAuthnRepo.DeleteAllForUser", func(t *testing.T) {
		repo := postgres.NewWebAuthnRepo(db)
		now := time.Now().UTC()
		for i := 0; i < 2; i++ {
			c := &model.WebAuthnCredential{
				ID: randomID(), UserID: user.ID,
				CredentialID: []byte(randomID()), PublicKey: []byte("pubkey"),
				FriendlyName: "key", CreatedAt: now,
			}
			if err := repo.Create(ctx, c); err != nil {
				t.Fatalf("create webauthn credential: %v", err)
			}
		}
		if err := repo.DeleteAllForUser(ctx, user.ID); err != nil {
			t.Fatalf("DeleteAllForUser: %v", err)
		}
		list, err := repo.ListByUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}
		if len(list) != 0 {
			t.Errorf("WebAuthn credentials survived erasure: %d remain", len(list))
		}
	})

	// The bug this exists to prevent: BackupCodeRepo.DeleteAllForUser is named like
	// a delete but runs `UPDATE ... SET used=true` (the regeneration path). Erasure
	// used it, so the code hashes and their user_id survived the erasure while both
	// the code and docs/PRIVACY.md claimed they were removed. A mock asserting "the
	// method was called" passes either way — only a real row count catches it.
	t.Run("BackupCodeRepo.PurgeAllForUser removes the rows", func(t *testing.T) {
		repo := postgres.NewBackupCodeRepo(db)
		codes := []*model.BackupCode{
			{ID: randomID(), UserID: user.ID, CodeHash: "$argon2id$hash1", CreatedAt: time.Now().UTC()},
			{ID: randomID(), UserID: user.ID, CodeHash: "$argon2id$hash2", CreatedAt: time.Now().UTC()},
		}
		if err := repo.CreateBatch(ctx, codes); err != nil {
			t.Fatalf("create backup codes: %v", err)
		}

		// DeleteAllForUser only marks them used — the rows, and the hashes, remain.
		if err := repo.DeleteAllForUser(ctx, user.ID); err != nil {
			t.Fatalf("DeleteAllForUser: %v", err)
		}
		var remaining int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM auth.backup_codes WHERE user_id=$1`, user.ID).Scan(&remaining); err != nil {
			t.Fatalf("count: %v", err)
		}
		if remaining != 2 {
			t.Fatalf("precondition: DeleteAllForUser should invalidate but keep rows, got %d", remaining)
		}

		// PurgeAllForUser is what erasure uses, and it must actually remove them.
		if err := repo.PurgeAllForUser(ctx, user.ID); err != nil {
			t.Fatalf("PurgeAllForUser: %v", err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM auth.backup_codes WHERE user_id=$1`, user.ID).Scan(&remaining); err != nil {
			t.Fatalf("count: %v", err)
		}
		if remaining != 0 {
			t.Errorf("backup code hashes survived erasure: %d rows remain", remaining)
		}
	})

	t.Run("RefreshTokenRepo.DeleteAllForUser", func(t *testing.T) {
		repo := postgres.NewRefreshTokenRepo(db)
		now := time.Now().UTC()
		hash := randomID()
		tok := &model.RefreshToken{
			ID: randomID(), UserID: user.ID, TokenHash: hash,
			FamilyID: randomID(), FingerprintHash: randomID(),
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}
		if err := repo.Create(ctx, tok); err != nil {
			t.Fatalf("create refresh token: %v", err)
		}
		if err := repo.DeleteAllForUser(ctx, user.ID); err != nil {
			t.Fatalf("DeleteAllForUser: %v", err)
		}
		// Revoking would leave the row (and its fingerprint hash) behind; erasure
		// deletes it, so the lookup must find nothing at all.
		got, err := repo.GetByTokenHash(ctx, hash)
		if err == nil && got != nil {
			t.Error("refresh token row survived erasure — revoked is not deleted")
		}
	})

	t.Run("UserRepo.SetLastLogin and SoftDeleteScrub", func(t *testing.T) {
		if err := userRepo.SetLastLogin(ctx, user.ID); err != nil {
			t.Fatalf("SetLastLogin: %v", err)
		}
		got, err := userRepo.GetByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.LastLoginAt == nil {
			t.Error("SetLastLogin did not stamp last_login_at")
		}

		tombstone := "deleted-" + user.ID + "@tombstone.invalid"
		if err := userRepo.SoftDeleteScrub(ctx, user.ID, tombstone); err != nil {
			t.Fatalf("SoftDeleteScrub: %v", err)
		}
		scrubbed, err := userRepo.GetByEmail(ctx, tombstone)
		if err != nil {
			t.Fatalf("GetByEmail(tombstone): %v", err)
		}
		if scrubbed == nil {
			t.Fatal("scrubbed user not found under tombstone email")
		}
		if !scrubbed.Deleted {
			t.Error("SoftDeleteScrub did not set deleted flag")
		}
	})
}

// TestPostgresRefreshTokenBulkOps covers RevokeByDeviceID / RevokeAll /
// CountActiveFamilies on the refresh-token repo.
func TestPostgresRefreshTokenBulkOps(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	db := &postgres.DB{Pool: pool}
	ctx := context.Background()

	userRepo := postgres.NewUserRepo(db)
	repo := postgres.NewRefreshTokenRepo(db)
	user := makeUser("rt-bulk@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	// family_id and device_id are UUID columns.
	dev1, dev2 := randomID(), randomID()
	mk := func(hash, family, device string) *model.RefreshToken {
		now := time.Now().UTC().Truncate(time.Microsecond)
		return &model.RefreshToken{
			ID: randomID(), UserID: user.ID, TokenHash: hash, FamilyID: family,
			DeviceID: device, ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
		}
	}

	t.Run("CountActiveFamilies", func(t *testing.T) {
		if err := repo.Create(ctx, mk("h1", randomID(), dev1)); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := repo.Create(ctx, mk("h2", randomID(), dev2)); err != nil {
			t.Fatalf("create: %v", err)
		}
		n, err := repo.CountActiveFamilies(ctx, user.ID)
		if err != nil {
			t.Fatalf("CountActiveFamilies: %v", err)
		}
		if n != 2 {
			t.Errorf("CountActiveFamilies = %d, want 2", n)
		}
	})

	t.Run("RevokeByDeviceID", func(t *testing.T) {
		if err := repo.RevokeByDeviceID(ctx, dev1); err != nil {
			t.Fatalf("RevokeByDeviceID: %v", err)
		}
		got, err := repo.GetByTokenHash(ctx, "h1")
		if err != nil {
			t.Fatalf("GetByTokenHash: %v", err)
		}
		if got == nil || !got.Revoked {
			t.Errorf("token for dev1 not revoked: %+v", got)
		}
	})

	t.Run("RevokeAll", func(t *testing.T) {
		if err := repo.RevokeAll(ctx); err != nil {
			t.Fatalf("RevokeAll: %v", err)
		}
		got, err := repo.GetByTokenHash(ctx, "h2")
		if err != nil {
			t.Fatalf("GetByTokenHash: %v", err)
		}
		if got == nil || !got.Revoked {
			t.Error("RevokeAll did not revoke remaining token")
		}
	})
}

// TestPostgresBlobPseudonymOps covers the ref-hash lookup and bulk-delete blob
// methods used by named-blob access and erasure.
func TestPostgresBlobPseudonymOps(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	db := &postgres.DB{Pool: pool}
	ctx := context.Background()
	repo := postgres.NewBlobRepo(db)

	pseudonym := randomID()
	mk := func(ref string) *model.Blob {
		return &model.Blob{
			ID: randomID(), PseudonymID: pseudonym, RefHash: ref,
			LabelEnc: []byte("l"), DataEnc: []byte("d"), SizeBytes: 4, StoredBytes: 8,
			Checksum: "sha256:" + randomID(), CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		}
	}

	if err := repo.Create(ctx, mk("ref-a")); err != nil {
		t.Fatalf("create ref-a: %v", err)
	}
	if err := repo.Create(ctx, mk("ref-b")); err != nil {
		t.Fatalf("create ref-b: %v", err)
	}

	t.Run("GetByRefAndPseudonym", func(t *testing.T) {
		got, err := repo.GetByRefAndPseudonym(ctx, "ref-a", pseudonym)
		if err != nil {
			t.Fatalf("GetByRefAndPseudonym: %v", err)
		}
		if got == nil || got.RefHash != "ref-a" {
			t.Fatalf("GetByRefAndPseudonym = %+v, want ref-a", got)
		}
		// Wrong pseudonym must not leak the blob.
		other, err := repo.GetByRefAndPseudonym(ctx, "ref-a", randomID())
		if err != nil {
			t.Fatalf("GetByRefAndPseudonym(other): %v", err)
		}
		if other != nil {
			t.Error("blob leaked across pseudonyms")
		}
	})

	t.Run("DeleteByRefAndPseudonym", func(t *testing.T) {
		if err := repo.DeleteByRefAndPseudonym(ctx, "ref-a", pseudonym); err != nil {
			t.Fatalf("DeleteByRefAndPseudonym: %v", err)
		}
		got, _ := repo.GetByRefAndPseudonym(ctx, "ref-a", pseudonym)
		if got != nil {
			t.Error("ref-a not deleted")
		}
	})

	t.Run("DeleteByRefAndPseudonym missing ref errors", func(t *testing.T) {
		if err := repo.DeleteByRefAndPseudonym(ctx, "no-such-ref", pseudonym); err == nil {
			t.Error("deleting a missing ref reported success")
		}
	})

	t.Run("DeleteAllForPseudonym", func(t *testing.T) {
		if err := repo.DeleteAllForPseudonym(ctx, pseudonym); err != nil {
			t.Fatalf("DeleteAllForPseudonym: %v", err)
		}
		list, err := repo.ListByPseudonym(ctx, pseudonym)
		if err != nil {
			t.Fatalf("ListByPseudonym: %v", err)
		}
		if len(list) != 0 {
			t.Errorf("blobs remain after DeleteAllForPseudonym: %d", len(list))
		}
	})
}

// TestPostgresMiscUncovered covers AdminConfig.List, AppRole.ListNames,
// Audit.Cleanup, and AdminSession.RevokeAll.
func TestPostgresMiscUncovered(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	db := &postgres.DB{Pool: pool}
	ctx := context.Background()

	t.Run("AdminConfigRepo.List", func(t *testing.T) {
		repo := postgres.NewAdminConfigRepo(db)
		if err := repo.Set(ctx, "feature.x", "on"); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if err := repo.Set(ctx, "feature.y", "off"); err != nil {
			t.Fatalf("Set: %v", err)
		}
		all, err := repo.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if all["feature.x"] != "on" || all["feature.y"] != "off" {
			t.Errorf("List = %v, missing set keys", all)
		}
	})

	t.Run("AppRoleRepo.ListNames", func(t *testing.T) {
		repo := postgres.NewAppRoleRepo(db)
		// A freshly-created role plus the migration-seeded catalog must all appear.
		if err := repo.Create(ctx, &model.AppRole{Name: "coverage_role", Namespace: "legacy"}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		names, err := repo.ListNames(ctx)
		if err != nil {
			t.Fatalf("ListNames: %v", err)
		}
		set := map[string]bool{}
		for _, n := range names {
			set[n] = true
		}
		if !set["coverage_role"] || !set["moderator"] {
			t.Errorf("ListNames = %v, want it to contain coverage_role and the seeded moderator", names)
		}
	})

	t.Run("AuditRepo.Cleanup", func(t *testing.T) {
		repo := postgres.NewAuditRepo(db)
		old := &model.AuditEntry{
			ID: randomID(), Timestamp: time.Now().Add(-90 * 24 * time.Hour).UTC(),
			EventType: "login_success", UserID: randomID(), IP: "203.0.113.9",
		}
		if err := repo.Insert(ctx, old); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		n, err := repo.Cleanup(ctx, time.Now().Add(-24*time.Hour))
		if err != nil {
			t.Fatalf("Cleanup: %v", err)
		}
		if n < 1 {
			t.Errorf("Cleanup removed %d rows, want >= 1", n)
		}
	})

	t.Run("AdminSessionRepo.RevokeAll", func(t *testing.T) {
		adminRepo := postgres.NewAdminUserRepo(db)
		sessRepo := postgres.NewAdminSessionRepo(db)
		admin := makeAdmin("revoke-all-admin", "operator")
		if err := adminRepo.Create(ctx, admin); err != nil {
			t.Fatalf("create admin: %v", err)
		}
		s := &model.AdminSession{
			ID: randomID(), AdminID: admin.ID, TokenHash: "revoke-all-h",
			IP: "203.0.113.5", ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := sessRepo.Create(ctx, s); err != nil {
			t.Fatalf("create session: %v", err)
		}
		if err := sessRepo.RevokeAll(ctx); err != nil {
			t.Fatalf("RevokeAll: %v", err)
		}
		active, err := sessRepo.ListActive(ctx)
		if err != nil {
			t.Fatalf("ListActive: %v", err)
		}
		if len(active) != 0 {
			t.Errorf("RevokeAll left %d active sessions", len(active))
		}
	})
}
