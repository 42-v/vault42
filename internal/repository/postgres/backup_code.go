package postgres

import (
	"context"
	"fmt"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// BackupCodeRepo implements repository.BackupCodeRepository.
type BackupCodeRepo struct{ db *DB }

// NewBackupCodeRepo creates a new PostgreSQL-backed backup code repository.
func NewBackupCodeRepo(db *DB) repository.BackupCodeRepository { return &BackupCodeRepo{db: db} }

// CreateBatch inserts a set of backup codes into the auth.backup_codes table
// within a single transaction, ensuring all-or-nothing insertion.
func (r *BackupCodeRepo) CreateBatch(ctx context.Context, codes []*model.BackupCode) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("create backup codes: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after commit

	for _, c := range codes {
		_, err := tx.Exec(ctx,
			`INSERT INTO auth.backup_codes (id, user_id, code_hash, used, created_at) VALUES ($1,$2,$3,$4,$5)`,
			c.ID, c.UserID, c.CodeHash, false, c.CreatedAt)
		if err != nil {
			return fmt.Errorf("create backup codes: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("create backup codes: %w", err)
	}
	return nil
}

// ListUnusedByUser returns all unused backup codes for a user, ordered by creation time.
func (r *BackupCodeRepo) ListUnusedByUser(ctx context.Context, userID string) ([]*model.BackupCode, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT id, user_id, code_hash, used, used_at, created_at FROM auth.backup_codes
		 WHERE user_id=$1 AND used=false ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("list unused codes: %w", err)
	}
	defer rows.Close()
	var codes []*model.BackupCode
	for rows.Next() {
		c := &model.BackupCode{}
		if err := rows.Scan(&c.ID, &c.UserID, &c.CodeHash, &c.Used, &c.UsedAt, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan backup code: %w", err)
		}
		codes = append(codes, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan backup codes: %w", err)
	}
	return codes, nil
}

// MarkUsed atomically marks a backup code as consumed. Returns true if the
// code was unused and is now marked (CAS: prevents double-spend).
func (r *BackupCodeRepo) MarkUsed(ctx context.Context, id string) (bool, error) {
	tag, err := r.db.Pool.Exec(ctx, `UPDATE auth.backup_codes SET used=true, used_at=NOW() WHERE id=$1 AND used=false`, id)
	if err != nil {
		return false, fmt.Errorf("mark code used: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteAllForUser invalidates all backup codes for a user by marking them used.
//
// This is the regeneration path: the rows are kept so a used/spent code cannot be
// replayed and the history stays visible. It does NOT remove the code hashes, so
// it is not sufficient for erasure — see PurgeAllForUser.
func (r *BackupCodeRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE auth.backup_codes SET used=true, used_at=NOW() WHERE user_id=$1 AND used=false`, userID)
	if err != nil {
		return fmt.Errorf("invalidate backup codes: %w", err)
	}
	return nil
}

// PurgeAllForUser hard-deletes every backup code row for a user (account erasure).
//
// Marking a code used leaves its hash and user_id in the table, so erasure cannot
// use DeleteAllForUser: the codes would outlive the account. vault_app does hold
// DELETE on auth.backup_codes (migrations/001_initial_schema.sql), despite an
// older comment here that claimed otherwise.
func (r *BackupCodeRepo) PurgeAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.backup_codes WHERE user_id=$1`, userID)
	if err != nil {
		return fmt.Errorf("purge backup codes: %w", err)
	}
	return nil
}
