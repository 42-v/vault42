package postgres

import (
	"context"
	"fmt"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// PasswordHistoryRepo implements repository.PasswordHistoryRepository.
type PasswordHistoryRepo struct{ db *DB }

// NewPasswordHistoryRepo creates a new PostgreSQL-backed password history repository.
func NewPasswordHistoryRepo(db *DB) repository.PasswordHistoryRepository {
	return &PasswordHistoryRepo{db: db}
}

// Create inserts a password hash into the auth.password_history table for reuse prevention.
func (r *PasswordHistoryRepo) Create(ctx context.Context, entry *model.PasswordHistory) error {
	_, err := r.db.Pool.Exec(ctx,
		`INSERT INTO auth.password_history (id, user_id, password_hash, created_at) VALUES ($1,$2,$3,$4)`,
		entry.ID, entry.UserID, entry.PasswordHash, entry.CreatedAt)
	if err != nil {
		return fmt.Errorf("create password history: %w", err)
	}
	return nil
}

// GetRecentByUser returns the most recent password hashes for a user, ordered newest first.
func (r *PasswordHistoryRepo) GetRecentByUser(ctx context.Context, userID string, limit int) ([]*model.PasswordHistory, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT id, user_id, password_hash, created_at FROM auth.password_history
		 WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("get recent passwords: %w", err)
	}
	defer rows.Close()
	var entries []*model.PasswordHistory
	for rows.Next() {
		e := &model.PasswordHistory{}
		if err := rows.Scan(&e.ID, &e.UserID, &e.PasswordHash, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan password history: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan password history: %w", err)
	}
	return entries, nil
}

// DeleteAllForUser removes a user's entire password history (account erasure).
func (r *PasswordHistoryRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.password_history WHERE user_id=$1`, userID)
	if err != nil {
		return fmt.Errorf("delete all password history: %w", err)
	}
	return nil
}
