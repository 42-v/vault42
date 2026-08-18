package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

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

// UpsertCAS writes a profile only if the stored row still matches expectedUpdatedAt,
// returning false when it does not. The profile is a single encrypted blob, so a
// read-modify-write (decrypt, change one field, re-encrypt) cannot be expressed as
// a partial UPDATE: without a compare-and-set, two concurrent writers each encrypt
// their own view of the profile and the loser's changes vanish — a withdrawal of
// consent among them.
//
// A zero expectedUpdatedAt means "the profile did not exist when I read it", which
// is an insert that must not overwrite a row created in the meantime.
func (r *IdentityRepo) UpsertCAS(ctx context.Context, profile *model.IdentityProfile, expectedUpdatedAt time.Time) (bool, error) {
	if expectedUpdatedAt.IsZero() {
		tag, err := r.db.Pool.Exec(ctx, `
			INSERT INTO identity.profiles (pseudonym_id, data_enc, version, updated_at, created_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (pseudonym_id) DO NOTHING`,
			profile.PseudonymID, profile.DataEnc, profile.Version, profile.UpdatedAt, profile.CreatedAt,
		)
		if err != nil {
			return false, fmt.Errorf("insert identity (cas): %w", err)
		}
		return tag.RowsAffected() > 0, nil
	}

	tag, err := r.db.Pool.Exec(ctx, `
		UPDATE identity.profiles
		SET data_enc = $2, version = $3, updated_at = $4
		WHERE pseudonym_id = $1 AND updated_at = $5`,
		profile.PseudonymID, profile.DataEnc, profile.Version, profile.UpdatedAt, expectedUpdatedAt,
	)
	if err != nil {
		return false, fmt.Errorf("update identity (cas): %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// Upsert creates or updates an identity profile by pseudonym ID, last write
// wins. Callers that read the profile first must use UpsertCAS instead: this
// one cannot tell a concurrent writer's row from the one it read, so it would
// silently discard the other writer's changes.
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
