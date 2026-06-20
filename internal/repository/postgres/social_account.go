package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// SocialAccountRepo implements repository.SocialAccountRepository.
type SocialAccountRepo struct{ db *DB }

// NewSocialAccountRepo creates a new PostgreSQL-backed social account repository.
func NewSocialAccountRepo(db *DB) repository.SocialAccountRepository {
	return &SocialAccountRepo{db: db}
}

// Create inserts a new social account link into the auth.social_accounts table.
func (r *SocialAccountRepo) Create(ctx context.Context, a *model.SocialAccount) error {
	_, err := r.db.Pool.Exec(ctx,
		`INSERT INTO auth.social_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		a.ID, a.UserID, a.Provider, a.ProviderUserID, a.AccessTokenEnc, a.RefreshTokenEnc, a.CreatedAt)
	if err != nil {
		return fmt.Errorf("create social account: %w", err)
	}
	return nil
}

// GetByProviderAndID retrieves a social account by provider name and provider-side user ID.
func (r *SocialAccountRepo) GetByProviderAndID(ctx context.Context, provider, providerUserID string) (*model.SocialAccount, error) {
	row := r.db.Pool.QueryRow(ctx,
		`SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at
		 FROM auth.social_accounts WHERE provider=$1 AND provider_user_id=$2`, provider, providerUserID)
	a := &model.SocialAccount{}
	err := row.Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderUserID, &a.AccessTokenEnc, &a.RefreshTokenEnc, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get social account: %w", err)
	}
	return a, nil
}

// ListByUser returns all linked social accounts for a user, ordered by creation time.
func (r *SocialAccountRepo) ListByUser(ctx context.Context, userID string) ([]*model.SocialAccount, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at
		 FROM auth.social_accounts WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("list social accounts: %w", err)
	}
	defer rows.Close()
	var accounts []*model.SocialAccount
	for rows.Next() {
		a := &model.SocialAccount{}
		if err := rows.Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderUserID, &a.AccessTokenEnc, &a.RefreshTokenEnc, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan social account: %w", err)
		}
		accounts = append(accounts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan social accounts: %w", err)
	}
	return accounts, nil
}

// Delete removes a social account link by ID with ownership verification.
func (r *SocialAccountRepo) Delete(ctx context.Context, id, userID string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.social_accounts WHERE id=$1 AND user_id=$2`, id, userID)
	if err != nil {
		return fmt.Errorf("delete social account: %w", err)
	}
	return nil
}

// DeleteAllForUser removes every social account link for a user (account erasure).
func (r *SocialAccountRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.social_accounts WHERE user_id=$1`, userID)
	if err != nil {
		return fmt.Errorf("delete all social accounts: %w", err)
	}
	return nil
}
