package integration_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestPostgresIdentityRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewIdentityRepo(db)
	ctx := context.Background()

	t.Run("Upsert and GetByPseudonym", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		profile := &model.IdentityProfile{
			PseudonymID: randomID(),
			DataEnc:     []byte("encrypted-data"),
			Version:     1,
			UpdatedAt:   now,
			CreatedAt:   now,
		}
		if err := repo.Upsert(ctx, profile); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		got, err := repo.GetByPseudonym(ctx, profile.PseudonymID)
		if err != nil {
			t.Fatalf("GetByPseudonym: %v", err)
		}
		if got == nil {
			t.Fatal("GetByPseudonym returned nil")
		}
		if got.PseudonymID != profile.PseudonymID {
			t.Errorf("PseudonymID = %q, want %q", got.PseudonymID, profile.PseudonymID)
		}
		if !bytes.Equal(got.DataEnc, profile.DataEnc) {
			t.Errorf("DataEnc = %q, want %q", got.DataEnc, profile.DataEnc)
		}
		if got.Version != 1 {
			t.Errorf("Version = %d, want 1", got.Version)
		}
		if !got.UpdatedAt.Equal(now) {
			t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, now)
		}
		if !got.CreatedAt.Equal(now) {
			t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, now)
		}
	})

	t.Run("Upsert overwrites", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		pseudonymID := randomID()
		profile := &model.IdentityProfile{
			PseudonymID: pseudonymID,
			DataEnc:     []byte("original-data"),
			Version:     1,
			UpdatedAt:   now,
			CreatedAt:   now,
		}
		if err := repo.Upsert(ctx, profile); err != nil {
			t.Fatalf("Upsert first: %v", err)
		}

		later := now.Add(time.Second)
		profile2 := &model.IdentityProfile{
			PseudonymID: pseudonymID,
			DataEnc:     []byte("updated-data"),
			Version:     2,
			UpdatedAt:   later,
			CreatedAt:   now,
		}
		if err := repo.Upsert(ctx, profile2); err != nil {
			t.Fatalf("Upsert second: %v", err)
		}

		got, err := repo.GetByPseudonym(ctx, pseudonymID)
		if err != nil {
			t.Fatalf("GetByPseudonym: %v", err)
		}
		if got == nil {
			t.Fatal("GetByPseudonym returned nil")
		}
		if !bytes.Equal(got.DataEnc, []byte("updated-data")) {
			t.Errorf("DataEnc = %q, want %q", got.DataEnc, "updated-data")
		}
		if got.Version != 2 {
			t.Errorf("Version = %d, want 2", got.Version)
		}
		if !got.UpdatedAt.Equal(later) {
			t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, later)
		}
	})

	t.Run("GetByPseudonym not found returns nil", func(t *testing.T) {
		got, err := repo.GetByPseudonym(ctx, randomID())
		if err != nil {
			t.Fatalf("GetByPseudonym: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		profile := &model.IdentityProfile{
			PseudonymID: randomID(),
			DataEnc:     []byte("to-delete"),
			Version:     1,
			UpdatedAt:   now,
			CreatedAt:   now,
		}
		if err := repo.Upsert(ctx, profile); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if err := repo.Delete(ctx, profile.PseudonymID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got, err := repo.GetByPseudonym(ctx, profile.PseudonymID)
		if err != nil {
			t.Fatalf("GetByPseudonym: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil after delete, got %+v", got)
		}
	})

	t.Run("Delete non-existent is no-op", func(t *testing.T) {
		err := repo.Delete(ctx, randomID())
		if err != nil {
			t.Fatalf("Delete non-existent: %v", err)
		}
	})
}
