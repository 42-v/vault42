package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// AuditRepo implements repository.AuditRepository using PostgreSQL's append-only audit schema.
type AuditRepo struct {
	db *DB
}

// NewAuditRepo creates a new PostgreSQL-backed audit log repository.
func NewAuditRepo(db *DB) *AuditRepo {
	return &AuditRepo{db: db}
}

// Insert writes a single entry to the audit.audit_log table.
func (r *AuditRepo) Insert(ctx context.Context, entry *model.AuditEntry) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO audit.audit_log (id, timestamp, event_type, user_id, client_id, ip, user_agent, fingerprint_hash, device_id, metadata, risk_score)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		entry.ID, entry.Timestamp, entry.EventType,
		nullStr(entry.UserID), nullStr(entry.ClientID),
		nullStr(entry.IP), nullStr(entry.UserAgent),
		nullStr(entry.FingerprintHash), nullStr(entry.DeviceID),
		entry.Metadata, entry.RiskScore,
	)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// InsertBatch writes multiple entries to the audit log within a single transaction.
func (r *AuditRepo) InsertBatch(ctx context.Context, entries []*model.AuditEntry) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin audit batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // rollback after commit is a no-op

	for _, e := range entries {
		_, err := tx.Exec(ctx, `
			INSERT INTO audit.audit_log (id, timestamp, event_type, user_id, client_id, ip, user_agent, fingerprint_hash, device_id, metadata, risk_score)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			e.ID, e.Timestamp, e.EventType,
			nullStr(e.UserID), nullStr(e.ClientID),
			nullStr(e.IP), nullStr(e.UserAgent),
			nullStr(e.FingerprintHash), nullStr(e.DeviceID),
			e.Metadata, e.RiskScore,
		)
		if err != nil {
			return fmt.Errorf("insert audit batch entry: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit audit batch tx: %w", err)
	}
	return nil
}

// Query retrieves audit log entries matching the given filter. Results are ordered by timestamp descending
// and capped at 1000 entries to prevent memory exhaustion.
func (r *AuditRepo) Query(ctx context.Context, filter repository.AuditFilter) ([]*model.AuditEntry, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	if filter.UserID != "" {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, filter.UserID)
		argIdx++
	}
	if filter.EventType != "" {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argIdx))
		args = append(args, filter.EventType)
		argIdx++
	}
	if filter.Since != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, *filter.Since)
		argIdx++
	}
	if filter.Until != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, *filter.Until)
		argIdx++
	}

	query := "SELECT id, timestamp, event_type, COALESCE(user_id::text,''), COALESCE(client_id::text,''), COALESCE(ip,''), COALESCE(user_agent,''), COALESCE(fingerprint_hash,''), COALESCE(device_id::text,''), metadata, risk_score FROM audit.audit_log"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY timestamp DESC"

	// Cap LIMIT to prevent memory exhaustion; use parameterized values
	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query += fmt.Sprintf(" LIMIT $%d", argIdx)
	args = append(args, limit)
	argIdx++

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
		// argIdx not read after this point; intentional terminal append.
	}

	rows, err := r.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit: %w", err)
	}
	defer rows.Close()

	var entries []*model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.EventType, &e.UserID, &e.ClientID,
			&e.IP, &e.UserAgent, &e.FingerprintHash, &e.DeviceID, &e.Metadata, &e.RiskScore); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		entries = append(entries, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan audit entries: %w", err)
	}
	return entries, nil
}

// auditRetentionLockKey is the advisory-lock key the retention sweep serialises
// on. Arbitrary but fixed: every replica must pick the same number.
const auditRetentionLockKey int64 = 4242

// CleanupLocked runs Cleanup under a transaction-scoped advisory lock, and
// reports acquired=false when another replica is already sweeping.
//
// audit.cleanup_old_entries() does ALTER TABLE ... DISABLE TRIGGER, which takes
// an ACCESS EXCLUSIVE lock on audit.audit_log and briefly drops the append-only
// guard. Every replica running that on its own timer would pile up on the lock,
// stall audit inserts across the fleet, and widen the window in which the
// append-only trigger is off. One sweeper at a time is enough — the work is
// idempotent, so a replica that loses the lock simply skips this round.
func (r *AuditRepo) CleanupLocked(ctx context.Context, olderThan time.Time) (deleted int64, acquired bool, err error) {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return 0, false, fmt.Errorf("cleanup audit entries: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", auditRetentionLockKey).Scan(&acquired); err != nil {
		return 0, false, fmt.Errorf("cleanup audit entries: lock: %w", err)
	}
	if !acquired {
		return 0, false, nil
	}

	interval := time.Since(olderThan)
	if err := tx.QueryRow(ctx,
		"SELECT audit.cleanup_old_entries($1::interval)",
		fmt.Sprintf("%d seconds", int(interval.Seconds())),
	).Scan(&deleted); err != nil {
		return 0, true, fmt.Errorf("cleanup audit entries: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, true, fmt.Errorf("cleanup audit entries: commit: %w", err)
	}
	return deleted, true, nil
}

// Cleanup removes audit entries older than the given time using the
// audit.cleanup_old_entries() SECURITY DEFINER function.
func (r *AuditRepo) Cleanup(ctx context.Context, olderThan time.Time) (int64, error) {
	interval := time.Since(olderThan)
	var deleted int64
	err := r.db.Pool.QueryRow(ctx,
		"SELECT audit.cleanup_old_entries($1::interval)",
		fmt.Sprintf("%d seconds", int(interval.Seconds())),
	).Scan(&deleted)
	if err != nil {
		return 0, fmt.Errorf("cleanup audit entries: %w", err)
	}
	return deleted, nil
}
