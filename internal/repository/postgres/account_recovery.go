package postgres

import (
	"context"
	"fmt"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// AccountRecoveryRepo implements repository.AccountRecoveryRepository against the
// append-only auth.account_recovery table.
type AccountRecoveryRepo struct {
	db *DB
}

// NewAccountRecoveryRepo creates a new PostgreSQL-backed account-recovery repository.
func NewAccountRecoveryRepo(db *DB) *AccountRecoveryRepo {
	return &AccountRecoveryRepo{db: db}
}

// Append writes one encrypted recovery record. The table grants the app role
// INSERT only (no UPDATE/DELETE), so the escrow history cannot be rewritten.
func (r *AccountRecoveryRepo) Append(ctx context.Context, rec *model.AccountRecovery) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.account_recovery (id, pseudonym, payload, deleted_at, deleted_by, reason)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		rec.ID, rec.Pseudonym, rec.Payload, rec.DeletedAt,
		nullStr(rec.DeletedBy), nullStr(rec.Reason),
	)
	if err != nil {
		return fmt.Errorf("insert account recovery: %w", err)
	}
	return nil
}

// List returns recovery records ordered by deleted_at descending.
func (r *AccountRecoveryRepo) List(ctx context.Context, limit, offset int) ([]model.AccountRecovery, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT id, pseudonym, payload, deleted_at, deleted_by, reason
		FROM auth.account_recovery
		ORDER BY deleted_at DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list account recovery: %w", err)
	}
	defer rows.Close()

	var recs []model.AccountRecovery
	for rows.Next() {
		var rec model.AccountRecovery
		var deletedBy, reason *string
		if err := rows.Scan(&rec.ID, &rec.Pseudonym, &rec.Payload, &rec.DeletedAt, &deletedBy, &reason); err != nil {
			return nil, fmt.Errorf("scan account recovery: %w", err)
		}
		rec.DeletedBy = deref(deletedBy)
		rec.Reason = deref(reason)
		recs = append(recs, rec)
	}
	return recs, rows.Err()
}

var _ repository.AccountRecoveryRepository = (*AccountRecoveryRepo)(nil)
