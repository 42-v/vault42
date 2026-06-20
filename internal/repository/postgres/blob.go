package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
)

// BlobRepo implements repository.BlobRepository.
type BlobRepo struct {
	db *DB
}

// NewBlobRepo creates a new PostgreSQL-backed blob repository.
func NewBlobRepo(db *DB) *BlobRepo {
	return &BlobRepo{db: db}
}

// Create inserts a new blob record.
func (r *BlobRepo) Create(ctx context.Context, blob *model.Blob) error {
	var refHash any
	if blob.RefHash != "" {
		refHash = blob.RefHash
	}
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO objects.blobs (id, pseudonym_id, ref_hash, label_enc, data_enc, size_bytes, stored_bytes, checksum, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		blob.ID, blob.PseudonymID, refHash, blob.LabelEnc, blob.DataEnc,
		blob.SizeBytes, blob.StoredBytes, blob.Checksum, blob.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert blob: %w", err)
	}
	return nil
}

// GetByIDAndPseudonym retrieves a blob by ID, only if it belongs to the given pseudonym.
func (r *BlobRepo) GetByIDAndPseudonym(ctx context.Context, id, pseudonymID string) (*model.Blob, error) {
	var b model.Blob
	var refHash *string
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, pseudonym_id, ref_hash, label_enc, data_enc, size_bytes, stored_bytes, checksum, created_at
		FROM objects.blobs WHERE id = $1 AND pseudonym_id = $2`, id, pseudonymID,
	).Scan(&b.ID, &b.PseudonymID, &refHash, &b.LabelEnc, &b.DataEnc, &b.SizeBytes, &b.StoredBytes, &b.Checksum, &b.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get blob: %w", err)
	}
	if refHash != nil {
		b.RefHash = *refHash
	}
	return &b, nil
}

// GetByRefAndPseudonym retrieves a blob by ref_hash, only if it belongs to the given pseudonym.
func (r *BlobRepo) GetByRefAndPseudonym(ctx context.Context, refHash, pseudonymID string) (*model.Blob, error) {
	var b model.Blob
	var rh *string
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, pseudonym_id, ref_hash, label_enc, data_enc, size_bytes, stored_bytes, checksum, created_at
		FROM objects.blobs WHERE ref_hash = $1 AND pseudonym_id = $2`, refHash, pseudonymID,
	).Scan(&b.ID, &b.PseudonymID, &rh, &b.LabelEnc, &b.DataEnc, &b.SizeBytes, &b.StoredBytes, &b.Checksum, &b.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get blob by ref: %w", err)
	}
	if rh != nil {
		b.RefHash = *rh
	}
	return &b, nil
}

// DeleteByRefAndPseudonym removes a blob by ref_hash, only if it belongs to the given pseudonym.
func (r *BlobRepo) DeleteByRefAndPseudonym(ctx context.Context, refHash, pseudonymID string) error {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM objects.blobs WHERE ref_hash = $1 AND pseudonym_id = $2`, refHash, pseudonymID)
	if err != nil {
		return fmt.Errorf("delete blob by ref: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("blob not found")
	}
	return nil
}

// ListByPseudonym returns all blob metadata (without data_enc) for a pseudonym.
func (r *BlobRepo) ListByPseudonym(ctx context.Context, pseudonymID string) ([]*model.Blob, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT id, pseudonym_id, ref_hash, label_enc, size_bytes, stored_bytes, checksum, created_at
		FROM objects.blobs WHERE pseudonym_id = $1 ORDER BY created_at DESC`, pseudonymID)
	if err != nil {
		return nil, fmt.Errorf("list blobs: %w", err)
	}
	defer rows.Close()

	var blobs []*model.Blob
	for rows.Next() {
		var b model.Blob
		var refHash *string
		if err := rows.Scan(&b.ID, &b.PseudonymID, &refHash, &b.LabelEnc, &b.SizeBytes, &b.StoredBytes, &b.Checksum, &b.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan blob: %w", err)
		}
		if refHash != nil {
			b.RefHash = *refHash
		}
		blobs = append(blobs, &b)
	}
	return blobs, rows.Err()
}

// GetQuota returns the blob count and total stored bytes for a pseudonym.
func (r *BlobRepo) GetQuota(ctx context.Context, pseudonymID string) (*model.BlobQuota, error) {
	var q model.BlobQuota
	err := r.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(COUNT(*), 0), COALESCE(SUM(stored_bytes), 0)
		FROM objects.blobs WHERE pseudonym_id = $1`, pseudonymID,
	).Scan(&q.UsedCount, &q.UsedBytes)
	if err != nil {
		return nil, fmt.Errorf("get quota: %w", err)
	}
	return &q, nil
}

// Delete removes a blob by ID, only if it belongs to the given pseudonym.
func (r *BlobRepo) Delete(ctx context.Context, id, pseudonymID string) error {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM objects.blobs WHERE id = $1 AND pseudonym_id = $2`, id, pseudonymID)
	if err != nil {
		return fmt.Errorf("delete blob: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("blob not found")
	}
	return nil
}

// DeleteAllForPseudonym removes every blob owned by a pseudonym. Unlike Delete it
// does not error when there is nothing to remove — account erasure must succeed
// for users who never stored a blob.
func (r *BlobRepo) DeleteAllForPseudonym(ctx context.Context, pseudonymID string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM objects.blobs WHERE pseudonym_id = $1`, pseudonymID)
	if err != nil {
		return fmt.Errorf("delete all blobs: %w", err)
	}
	return nil
}
