package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestPostgresRefreshTokenRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	userRepo := postgres.NewUserRepo(db)
	repo := postgres.NewRefreshTokenRepo(db)
	ctx := context.Background()

	// Create a user for FK references
	user := makeUser("rt-owner@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	makeToken := func(hash, familyID string) *model.RefreshToken {
		now := time.Now().UTC().Truncate(time.Microsecond)
		return &model.RefreshToken{
			ID:        randomID(),
			UserID:    user.ID,
			TokenHash: hash,
			FamilyID:  familyID,
			ExpiresAt: now.Add(24 * time.Hour),
			CreatedAt: now,
		}
	}

	t.Run("Create and GetByTokenHash", func(t *testing.T) {
		familyID := randomID()
		tok := makeToken("hash-create-get", familyID)
		if err := repo.Create(ctx, tok); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByTokenHash(ctx, "hash-create-get")
		if err != nil {
			t.Fatalf("GetByTokenHash: %v", err)
		}
		if got == nil {
			t.Fatal("GetByTokenHash returned nil")
		}
		if got.ID != tok.ID {
			t.Errorf("ID = %q, want %q", got.ID, tok.ID)
		}
		if got.UserID != user.ID {
			t.Errorf("UserID = %q, want %q", got.UserID, user.ID)
		}
		if got.TokenHash != "hash-create-get" {
			t.Errorf("TokenHash = %q, want %q", got.TokenHash, "hash-create-get")
		}
		if got.FamilyID != familyID {
			t.Errorf("FamilyID = %q, want %q", got.FamilyID, familyID)
		}
		if got.Used {
			t.Error("Used = true, want false")
		}
		if got.Revoked {
			t.Error("Revoked = true, want false")
		}
	})

	t.Run("GetByTokenHash not found returns nil", func(t *testing.T) {
		got, err := repo.GetByTokenHash(ctx, "nonexistent-hash")
		if err != nil {
			t.Fatalf("GetByTokenHash: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("MarkUsed returns true on first use", func(t *testing.T) {
		tok := makeToken("hash-markused-1", randomID())
		if err := repo.Create(ctx, tok); err != nil {
			t.Fatalf("Create: %v", err)
		}
		ok, err := repo.MarkUsed(ctx, tok.ID)
		if err != nil {
			t.Fatalf("MarkUsed: %v", err)
		}
		if !ok {
			t.Error("MarkUsed returned false, want true on first use")
		}

		// Verify it's actually marked used
		got, _ := repo.GetByTokenHash(ctx, "hash-markused-1")
		if !got.Used {
			t.Error("Used = false after MarkUsed")
		}
	})

	t.Run("MarkUsed returns false on replay", func(t *testing.T) {
		tok := makeToken("hash-markused-2", randomID())
		if err := repo.Create(ctx, tok); err != nil {
			t.Fatalf("Create: %v", err)
		}
		_, _ = repo.MarkUsed(ctx, tok.ID) // first use
		ok, err := repo.MarkUsed(ctx, tok.ID)
		if err != nil {
			t.Fatalf("MarkUsed second: %v", err)
		}
		if ok {
			t.Error("MarkUsed returned true on second call, want false (replay detection)")
		}
	})

	t.Run("MarkUsed nonexistent returns false", func(t *testing.T) {
		ok, err := repo.MarkUsed(ctx, randomID())
		if err != nil {
			t.Fatalf("MarkUsed: %v", err)
		}
		if ok {
			t.Error("MarkUsed returned true for nonexistent token")
		}
	})

	t.Run("RevokeByID", func(t *testing.T) {
		tok := makeToken("hash-revokebyid", randomID())
		if err := repo.Create(ctx, tok); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.RevokeByID(ctx, tok.ID); err != nil {
			t.Fatalf("RevokeByID: %v", err)
		}
		got, _ := repo.GetByTokenHash(ctx, "hash-revokebyid")
		if !got.Revoked {
			t.Error("Revoked = false after RevokeByID")
		}
	})

	t.Run("RevokeFamily", func(t *testing.T) {
		familyID := randomID()
		tok1 := makeToken("hash-family-1", familyID)
		tok2 := makeToken("hash-family-2", familyID)
		tok3 := makeToken("hash-family-other", randomID()) // different family

		for _, tok := range []*model.RefreshToken{tok1, tok2, tok3} {
			if err := repo.Create(ctx, tok); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}

		if err := repo.RevokeFamily(ctx, familyID); err != nil {
			t.Fatalf("RevokeFamily: %v", err)
		}

		got1, _ := repo.GetByTokenHash(ctx, "hash-family-1")
		got2, _ := repo.GetByTokenHash(ctx, "hash-family-2")
		got3, _ := repo.GetByTokenHash(ctx, "hash-family-other")

		if !got1.Revoked {
			t.Error("tok1 should be revoked")
		}
		if !got2.Revoked {
			t.Error("tok2 should be revoked")
		}
		if got3.Revoked {
			t.Error("tok3 should NOT be revoked (different family)")
		}
	})

	t.Run("RevokeAllForUser", func(t *testing.T) {
		user2 := makeUser("rt-owner2@test.com")
		if err := userRepo.Create(ctx, user2); err != nil {
			t.Fatalf("create user2: %v", err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		tok1 := &model.RefreshToken{
			ID: randomID(), UserID: user2.ID, TokenHash: "hash-revokeall-1",
			FamilyID: randomID(), ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}
		tok2 := &model.RefreshToken{
			ID: randomID(), UserID: user2.ID, TokenHash: "hash-revokeall-2",
			FamilyID: randomID(), ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}
		for _, tok := range []*model.RefreshToken{tok1, tok2} {
			if err := repo.Create(ctx, tok); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}

		if err := repo.RevokeAllForUser(ctx, user2.ID); err != nil {
			t.Fatalf("RevokeAllForUser: %v", err)
		}

		got1, _ := repo.GetByTokenHash(ctx, "hash-revokeall-1")
		got2, _ := repo.GetByTokenHash(ctx, "hash-revokeall-2")
		if !got1.Revoked {
			t.Error("tok1 should be revoked")
		}
		if !got2.Revoked {
			t.Error("tok2 should be revoked")
		}
	})

	t.Run("DeleteExpired removes used+expired tokens", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		// Expired + used (should be deleted)
		tok1 := &model.RefreshToken{
			ID: randomID(), UserID: user.ID, TokenHash: "hash-expired-used",
			FamilyID: randomID(), ExpiresAt: now.Add(-1 * time.Hour), CreatedAt: now.Add(-2 * time.Hour),
		}
		// Expired + revoked (should be deleted)
		tok2 := &model.RefreshToken{
			ID: randomID(), UserID: user.ID, TokenHash: "hash-expired-revoked",
			FamilyID: randomID(), ExpiresAt: now.Add(-1 * time.Hour), CreatedAt: now.Add(-2 * time.Hour),
		}
		// Expired but not used/revoked (should NOT be deleted)
		tok3 := &model.RefreshToken{
			ID: randomID(), UserID: user.ID, TokenHash: "hash-expired-fresh",
			FamilyID: randomID(), ExpiresAt: now.Add(-1 * time.Hour), CreatedAt: now.Add(-2 * time.Hour),
		}
		// Not expired (should NOT be deleted)
		tok4 := &model.RefreshToken{
			ID: randomID(), UserID: user.ID, TokenHash: "hash-notexpired",
			FamilyID: randomID(), ExpiresAt: now.Add(1 * time.Hour), CreatedAt: now,
		}

		for _, tok := range []*model.RefreshToken{tok1, tok2, tok3, tok4} {
			if err := repo.Create(ctx, tok); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}
		repo.MarkUsed(ctx, tok1.ID)
		repo.RevokeByID(ctx, tok2.ID)

		deleted, err := repo.DeleteExpired(ctx)
		if err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}
		if deleted < 2 {
			t.Errorf("DeleteExpired = %d, want >= 2", deleted)
		}

		// tok3 should still exist (expired but not used/revoked)
		got3, _ := repo.GetByTokenHash(ctx, "hash-expired-fresh")
		if got3 == nil {
			t.Error("expired but fresh token should still exist")
		}

		// tok4 should still exist
		got4, _ := repo.GetByTokenHash(ctx, "hash-notexpired")
		if got4 == nil {
			t.Error("non-expired token should still exist")
		}
	})

	t.Run("Create with optional fields", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		tok := &model.RefreshToken{
			ID:              randomID(),
			UserID:          user.ID,
			TokenHash:       "hash-with-optionals",
			FamilyID:        randomID(),
			DeviceID:        randomID(),
			FingerprintHash: "somefingerprintsha256",
			ExpiresAt:       now.Add(time.Hour),
			CreatedAt:       now,
		}
		if err := repo.Create(ctx, tok); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, _ := repo.GetByTokenHash(ctx, "hash-with-optionals")
		if got == nil {
			t.Fatal("GetByTokenHash returned nil")
		}
		if got.DeviceID != tok.DeviceID {
			t.Errorf("DeviceID = %q, want %q", got.DeviceID, tok.DeviceID)
		}
		if got.FingerprintHash != tok.FingerprintHash {
			t.Errorf("FingerprintHash = %q, want %q", got.FingerprintHash, tok.FingerprintHash)
		}
	})

	t.Run("RevokeAllForUser skips already revoked", func(t *testing.T) {
		user3 := makeUser("rt-owner3@test.com")
		if err := userRepo.Create(ctx, user3); err != nil {
			t.Fatalf("create user3: %v", err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		tok := &model.RefreshToken{
			ID: randomID(), UserID: user3.ID, TokenHash: "hash-already-revoked",
			FamilyID: randomID(), ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}
		if err := repo.Create(ctx, tok); err != nil {
			t.Fatalf("Create: %v", err)
		}
		// Revoke individually first
		repo.RevokeByID(ctx, tok.ID)

		// RevokeAllForUser should not error
		if err := repo.RevokeAllForUser(ctx, user3.ID); err != nil {
			t.Fatalf("RevokeAllForUser: %v", err)
		}
	})
}
