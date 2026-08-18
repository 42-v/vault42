package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/42-v/vault42/internal/repository"
)

// recoveryRetentionLockKey is the advisory-lock key the escrow prune serializes
// on. Arbitrary but fixed, and distinct from the audit sweeper's key: the two
// sweeps touch different tables and must not block each other.
const recoveryRetentionLockKey int64 = 4243

// PruneLocked runs Prune under a transaction-scoped advisory lock, and reports
// acquired=false when another replica is already sweeping.
//
// auth.cleanup_old_recovery() does ALTER TABLE ... DISABLE TRIGGER, which takes
// an ACCESS EXCLUSIVE lock on auth.account_recovery and briefly drops the
// append-only guard. Every replica running that on its own timer would pile up
// on the lock and widen the window in which escrow rows can be deleted. One
// sweeper at a time is enough: the work is idempotent, so a replica that loses
// the lock simply skips this round.
func (r *AccountRecoveryRepo) PruneLocked(ctx context.Context, olderThan time.Time) (deleted int64, acquired bool, err error) {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return 0, false, fmt.Errorf("prune account recovery: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", recoveryRetentionLockKey).Scan(&acquired); err != nil {
		return 0, false, fmt.Errorf("prune account recovery: lock: %w", err)
	}
	if !acquired {
		return 0, false, nil
	}

	if err := tx.QueryRow(ctx,
		"SELECT auth.cleanup_old_recovery($1::interval)",
		recoveryInterval(olderThan),
	).Scan(&deleted); err != nil {
		return 0, true, fmt.Errorf("prune account recovery: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, true, fmt.Errorf("prune account recovery: commit: %w", err)
	}
	return deleted, true, nil
}

// Prune removes escrow records older than the given time using the
// auth.cleanup_old_recovery() SECURITY DEFINER function. It is what
// `vault cleanup-recovery` calls: a one-shot operator purge with no advisory
// lock, since there is no fleet of them competing.
func (r *AccountRecoveryRepo) Prune(ctx context.Context, olderThan time.Time) (int64, error) {
	var deleted int64
	err := r.db.Pool.QueryRow(ctx,
		"SELECT auth.cleanup_old_recovery($1::interval)",
		recoveryInterval(olderThan),
	).Scan(&deleted)
	if err != nil {
		return 0, fmt.Errorf("prune account recovery: %w", err)
	}
	return deleted, nil
}

// recoveryInterval renders the cutoff as an interval the SQL function can apply
// relative to NOW(), matching how the audit cleanup is called.
func recoveryInterval(olderThan time.Time) string {
	return fmt.Sprintf("%d seconds", int(time.Since(olderThan).Seconds()))
}

var _ repository.AccountRecoveryPruner = (*AccountRecoveryRepo)(nil)
