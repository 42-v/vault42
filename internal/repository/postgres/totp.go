package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// TOTPRepo implements repository.TOTPRepository.
type TOTPRepo struct{ db *DB }

// NewTOTPRepo creates a new PostgreSQL-backed TOTP repository.
func NewTOTPRepo(db *DB) repository.TOTPRepository { return &TOTPRepo{db: db} }

// Create inserts a new TOTP secret into the auth.totp_secrets table.
func (r *TOTPRepo) Create(ctx context.Context, s *model.TOTPSecret) error {
	_, err := r.db.Pool.Exec(ctx,
		`INSERT INTO auth.totp_secrets (id, user_id, secret_enc, verified, created_at) VALUES ($1,$2,$3,$4,$5)`,
		s.ID, s.UserID, s.SecretEnc, s.Verified, s.CreatedAt)
	if err != nil {
		return fmt.Errorf("create totp: %w", err)
	}
	return nil
}

// GetByUserID retrieves the TOTP secret for a user. Returns an error if not found.
func (r *TOTPRepo) GetByUserID(ctx context.Context, userID string) (*model.TOTPSecret, error) {
	row := r.db.Pool.QueryRow(ctx,
		`SELECT id, user_id, secret_enc, verified, created_at FROM auth.totp_secrets WHERE user_id=$1`, userID)
	s := &model.TOTPSecret{}
	err := row.Scan(&s.ID, &s.UserID, &s.SecretEnc, &s.Verified, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get totp: %w", err)
	}
	return s, nil
}

// MarkVerified sets the verified flag to true after the user confirms TOTP setup.
func (r *TOTPRepo) MarkVerified(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.totp_secrets SET verified=true WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("mark totp verified: %w", err)
	}
	return nil
}

// DeleteByUserID removes the TOTP secret for a user, disabling TOTP-based 2FA.
func (r *TOTPRepo) DeleteByUserID(ctx context.Context, userID string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.totp_secrets WHERE user_id=$1`, userID)
	if err != nil {
		return fmt.Errorf("delete totp: %w", err)
	}
	return nil
}
