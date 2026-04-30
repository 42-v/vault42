package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
)

// IdentityRepo implements repository.IdentityRepository.
type IdentityRepo struct {
	db *DB
}

// NewIdentityRepo creates a new PostgreSQL-backed identity repository.
func NewIdentityRepo(db *DB) *IdentityRepo {
	return &IdentityRepo{db: db}
}

// Upsert creates or updates an identity profile by pseudonym ID.
func (r *IdentityRepo) Upsert(ctx context.Context, profile *model.IdentityProfile) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO identity.profiles (pseudonym_id, data_enc, version, updated_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (pseudonym_id) DO UPDATE SET
			data_enc = EXCLUDED.data_enc,
			version = EXCLUDED.version,
			updated_at = EXCLUDED.updated_at`,
		profile.PseudonymID, profile.DataEnc, profile.Version, profile.UpdatedAt, profile.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert identity: %w", err)
	}
	return nil
}

// GetByPseudonym retrieves an identity profile. Returns nil, nil if not found.
func (r *IdentityRepo) GetByPseudonym(ctx context.Context, pseudonymID string) (*model.IdentityProfile, error) {
	var p model.IdentityProfile
	err := r.db.Pool.QueryRow(ctx, `
		SELECT pseudonym_id, data_enc, version, updated_at, created_at
		FROM identity.profiles WHERE pseudonym_id = $1`, pseudonymID,
	).Scan(&p.PseudonymID, &p.DataEnc, &p.Version, &p.UpdatedAt, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get identity: %w", err)
	}
	return &p, nil
}

// Delete removes an identity profile by pseudonym ID.
func (r *IdentityRepo) Delete(ctx context.Context, pseudonymID string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM identity.profiles WHERE pseudonym_id = $1`, pseudonymID)
	if err != nil {
		return fmt.Errorf("delete identity: %w", err)
	}
	return nil
}
