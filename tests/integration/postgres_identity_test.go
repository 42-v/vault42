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

	t.Run("UpsertCAS zero time inserts a fresh profile", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		pseudonymID := randomID()
		profile := &model.IdentityProfile{
			PseudonymID: pseudonymID,
			DataEnc:     []byte("cas-insert"),
			Version:     1,
			UpdatedAt:   now,
			CreatedAt:   now,
		}
		won, err := repo.UpsertCAS(ctx, profile, time.Time{})
		if err != nil {
			t.Fatalf("UpsertCAS insert: %v", err)
		}
		if !won {
			t.Fatal("UpsertCAS returned false for a fresh pseudonym")
		}
		got, err := repo.GetByPseudonym(ctx, pseudonymID)
		if err != nil {
			t.Fatalf("GetByPseudonym: %v", err)
		}
		if got == nil {
			t.Fatal("GetByPseudonym returned nil after CAS insert")
		}
		if !bytes.Equal(got.DataEnc, []byte("cas-insert")) {
			t.Errorf("DataEnc = %q, want %q", got.DataEnc, "cas-insert")
		}
	})

	t.Run("UpsertCAS zero time must not overwrite an existing row", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		pseudonymID := randomID()
		first := &model.IdentityProfile{
			PseudonymID: pseudonymID,
			DataEnc:     []byte("first-writer"),
			Version:     1,
			UpdatedAt:   now,
			CreatedAt:   now,
		}
		won, err := repo.UpsertCAS(ctx, first, time.Time{})
		if err != nil || !won {
			t.Fatalf("UpsertCAS first insert: won=%v err=%v", won, err)
		}

		second := &model.IdentityProfile{
			PseudonymID: pseudonymID,
			DataEnc:     []byte("second-writer"),
			Version:     1,
			UpdatedAt:   now.Add(time.Second),
			CreatedAt:   now,
		}
		won, err = repo.UpsertCAS(ctx, second, time.Time{})
		if err != nil {
			t.Fatalf("UpsertCAS second insert: %v", err)
		}
		if won {
			t.Fatal("UpsertCAS reported a win for a pseudonym that already exists")
		}
		got, err := repo.GetByPseudonym(ctx, pseudonymID)
		if err != nil {
			t.Fatalf("GetByPseudonym: %v", err)
		}
		if !bytes.Equal(got.DataEnc, []byte("first-writer")) {
			t.Errorf("DataEnc = %q, the losing insert overwrote the first writer", got.DataEnc)
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
