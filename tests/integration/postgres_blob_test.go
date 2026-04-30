package integration_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestPostgresBlobRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewBlobRepo(db)
	ctx := context.Background()

	makeBlob := func(pseudonymID string, sizeBytes, storedBytes int) *model.Blob {
		now := time.Now().UTC().Truncate(time.Microsecond)
		return &model.Blob{
			ID:          randomID(),
			PseudonymID: pseudonymID,
			LabelEnc:    []byte("encrypted-label"),
			DataEnc:     []byte("encrypted-data"),
			SizeBytes:   sizeBytes,
			StoredBytes: storedBytes,
			Checksum:    "sha256:" + randomID(),
			CreatedAt:   now,
		}
	}

	t.Run("Create and GetByIDAndPseudonym", func(t *testing.T) {
		pseudonymID := randomID()
		blob := makeBlob(pseudonymID, 1024, 2048)
		if err := repo.Create(ctx, blob); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByIDAndPseudonym(ctx, blob.ID, pseudonymID)
		if err != nil {
			t.Fatalf("GetByIDAndPseudonym: %v", err)
		}
		if got == nil {
			t.Fatal("GetByIDAndPseudonym returned nil")
		}
		if got.ID != blob.ID {
			t.Errorf("ID = %q, want %q", got.ID, blob.ID)
		}
		if got.PseudonymID != pseudonymID {
			t.Errorf("PseudonymID = %q, want %q", got.PseudonymID, pseudonymID)
		}
		if !bytes.Equal(got.LabelEnc, blob.LabelEnc) {
			t.Errorf("LabelEnc = %q, want %q", got.LabelEnc, blob.LabelEnc)
		}
		if !bytes.Equal(got.DataEnc, blob.DataEnc) {
			t.Errorf("DataEnc = %q, want %q", got.DataEnc, blob.DataEnc)
		}
		if got.SizeBytes != 1024 {
			t.Errorf("SizeBytes = %d, want 1024", got.SizeBytes)
		}
		if got.StoredBytes != 2048 {
			t.Errorf("StoredBytes = %d, want 2048", got.StoredBytes)
		}
		if got.Checksum != blob.Checksum {
			t.Errorf("Checksum = %q, want %q", got.Checksum, blob.Checksum)
		}
		if !got.CreatedAt.Equal(blob.CreatedAt) {
			t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, blob.CreatedAt)
		}
	})

	t.Run("GetByIDAndPseudonym wrong pseudonym returns nil", func(t *testing.T) {
		pseudonymID := randomID()
		blob := makeBlob(pseudonymID, 100, 200)
		if err := repo.Create(ctx, blob); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByIDAndPseudonym(ctx, blob.ID, randomID())
		if err != nil {
			t.Fatalf("GetByIDAndPseudonym: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil for wrong pseudonym, got %+v", got)
		}
	})

	t.Run("GetByIDAndPseudonym not found returns nil", func(t *testing.T) {
		got, err := repo.GetByIDAndPseudonym(ctx, randomID(), randomID())
		if err != nil {
			t.Fatalf("GetByIDAndPseudonym: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("ListByPseudonym", func(t *testing.T) {
		pseudonymID := randomID()
		b1 := makeBlob(pseudonymID, 100, 200)
		if err := repo.Create(ctx, b1); err != nil {
			t.Fatalf("Create b1: %v", err)
		}
		time.Sleep(time.Millisecond)
		b2 := makeBlob(pseudonymID, 200, 400)
		if err := repo.Create(ctx, b2); err != nil {
			t.Fatalf("Create b2: %v", err)
		}
		time.Sleep(time.Millisecond)
		b3 := makeBlob(pseudonymID, 300, 600)
		if err := repo.Create(ctx, b3); err != nil {
			t.Fatalf("Create b3: %v", err)
		}

		blobs, err := repo.ListByPseudonym(ctx, pseudonymID)
		if err != nil {
			t.Fatalf("ListByPseudonym: %v", err)
		}
		if len(blobs) != 3 {
			t.Fatalf("len = %d, want 3", len(blobs))
		}
		// Verify DESC order (newest first)
		if blobs[0].ID != b3.ID {
			t.Errorf("first blob ID = %q, want %q (newest)", blobs[0].ID, b3.ID)
		}
		if blobs[2].ID != b1.ID {
			t.Errorf("last blob ID = %q, want %q (oldest)", blobs[2].ID, b1.ID)
		}
		// Verify data_enc is nil (not selected)
		for i, b := range blobs {
			if b.DataEnc != nil {
				t.Errorf("blobs[%d].DataEnc = %q, want nil", i, b.DataEnc)
			}
		}
	})

	t.Run("ListByPseudonym empty", func(t *testing.T) {
		blobs, err := repo.ListByPseudonym(ctx, randomID())
		if err != nil {
			t.Fatalf("ListByPseudonym: %v", err)
		}
		if len(blobs) != 0 {
			t.Errorf("len = %d, want 0", len(blobs))
		}
	})

	t.Run("GetQuota", func(t *testing.T) {
		pseudonymID := randomID()
		b1 := makeBlob(pseudonymID, 100, 500)
		b2 := makeBlob(pseudonymID, 200, 700)
		if err := repo.Create(ctx, b1); err != nil {
			t.Fatalf("Create b1: %v", err)
		}
		if err := repo.Create(ctx, b2); err != nil {
			t.Fatalf("Create b2: %v", err)
		}
		quota, err := repo.GetQuota(ctx, pseudonymID)
		if err != nil {
			t.Fatalf("GetQuota: %v", err)
		}
		if quota.UsedCount != 2 {
			t.Errorf("UsedCount = %d, want 2", quota.UsedCount)
		}
		if quota.UsedBytes != 1200 {
			t.Errorf("UsedBytes = %d, want 1200", quota.UsedBytes)
		}
	})

	t.Run("GetQuota empty", func(t *testing.T) {
		quota, err := repo.GetQuota(ctx, randomID())
		if err != nil {
			t.Fatalf("GetQuota: %v", err)
		}
		if quota.UsedCount != 0 {
			t.Errorf("UsedCount = %d, want 0", quota.UsedCount)
		}
		if quota.UsedBytes != 0 {
			t.Errorf("UsedBytes = %d, want 0", quota.UsedBytes)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		pseudonymID := randomID()
		blob := makeBlob(pseudonymID, 100, 200)
		if err := repo.Create(ctx, blob); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.Delete(ctx, blob.ID, pseudonymID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got, err := repo.GetByIDAndPseudonym(ctx, blob.ID, pseudonymID)
		if err != nil {
			t.Fatalf("GetByIDAndPseudonym: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil after delete, got %+v", got)
		}
	})

	t.Run("Delete wrong pseudonym", func(t *testing.T) {
		pseudonymID := randomID()
		blob := makeBlob(pseudonymID, 100, 200)
		if err := repo.Create(ctx, blob); err != nil {
			t.Fatalf("Create: %v", err)
		}
		err := repo.Delete(ctx, blob.ID, randomID())
		if err == nil {
			t.Fatal("expected error for delete with wrong pseudonym, got nil")
		}
	})

	t.Run("Delete non-existent", func(t *testing.T) {
		err := repo.Delete(ctx, randomID(), randomID())
		if err == nil {
			t.Fatal("expected error for delete non-existent, got nil")
		}
	})
}
