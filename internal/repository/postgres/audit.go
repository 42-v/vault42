package postgres

import (
	"context"
	"fmt"
	"regexp"
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

// actorHex matches a uuid with its punctuation already removed. The columns
// render canonically -- 8-4-4-4-12, lower case -- but that is not what the type
// accepts on input, and the difference is the whole point of this file.
//
// PostgreSQL 8.12 accepts upper case, the canonical form wrapped in braces, and
// hyphens omitted or added after any group of four digits, and normalises every
// one of them to the same sixteen bytes. So `Guid.ToString("N")` -- .NET's
// dashless rendering, and therefore the one a .NET relying party is most likely
// to send -- is a uuid the column already holds, indexes and returns dashed.
// Testing the caller's *shape* would refuse a value the database accepts.
var actorHex = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

// canonicalActorUUID renders an id the uuid type would accept in the form the
// column returns, and reports false for one it would not.
//
// It accepts a little more than PostgreSQL does, because it emits the canonical
// form rather than the caller's string: a hyphen in a place the server would
// refuse still leaves 32 hex digits naming a uuid, and what reaches the column
// is the canonical rendering of it either way. Over-acceptance here cannot
// produce a value the column rejects, whereas under-acceptance silently detaches
// a row from its subject, which is the defect this file exists to fix.
func canonicalActorUUID(id string) (string, bool) {
	t := strings.TrimSpace(id)
	if len(t) > 1 && t[0] == '{' && t[len(t)-1] == '}' {
		t = t[1 : len(t)-1]
	}
	t = strings.ToLower(strings.ReplaceAll(t, "-", ""))
	if !actorHex.MatchString(t) {
		return "", false
	}
	return t[0:8] + "-" + t[8:12] + "-" + t[12:16] + "-" + t[16:20] + "-" + t[20:32], true
}

// Keys a rejected actor id is kept under. Prefixed so they cannot collide with
// a key a call site already uses, and named for what they hold.
const (
	rawUserIDKey   = "actor_user_id_raw"
	rawClientIDKey = "actor_client_id_raw"
)

// actorColumns returns the values the actor columns should carry, moving an id
// the uuid type cannot hold into metadata instead of losing the whole row.
//
// user_id and client_id are UUID in the schema (001) and string in the model,
// and three call sites pass a value the caller chose: the submitted client_id
// on a failed client auth, and the asserted subject on /mint and on a service
// document. A non-UUID there does not produce a row with an odd value in it --
// there is no row at all. pgx is not what refuses it: chooseParameterFormatCode
// returns TextFormatCode for any string before the oid is consulted, so the
// value goes out as text and the server's parser is the acceptor. The caller
// then discards the error, correctly, because auditing must never block
// authentication. So
// the events most worth having are the ones most likely to vanish: a credential
// spray sends client_id=admin, not a UUID, which is exactly the case the
// comment above auditClientAuthFailure says the audit exists to catch.
//
// This belongs here rather than in audit.Logger. The constraint is the column's,
// and only this package knows the column. Normalising in the logger would change
// the shape of every AuditEntry in the process to satisfy a rule that applies at
// one boundary, and every mock repository in the test suite would keep accepting
// what the real one rejects -- which is how this survived in the first place.
//
// The claimed value is not discarded. It moves into metadata, which is JSONB and
// takes any string, so the row still records who the caller said they were.
func actorColumns(e *model.AuditEntry) (userID, clientID string, metadata map[string]interface{}) {
	userID, clientID, metadata = e.UserID, e.ClientID, e.Metadata

	userOK, clientOK := true, true
	if userID != "" {
		userID, userOK = canonicalActorUUID(userID)
	}
	if clientID != "" {
		clientID, clientOK = canonicalActorUUID(clientID)
	}
	if userOK && clientOK {
		return userID, clientID, metadata
	}

	// Copied, never mutated: the entry belongs to the caller, and a batch retry
	// must not accumulate keys.
	out := make(map[string]interface{}, len(metadata)+2)
	for k, v := range metadata {
		out[k] = v
	}
	// The claim is kept as the caller wrote it, not as anything normalised it:
	// the point of the key is to record what was asserted.
	if !userOK {
		out[rawUserIDKey] = e.UserID
		userID = ""
	}
	if !clientOK {
		out[rawClientIDKey] = e.ClientID
		clientID = ""
	}
	return userID, clientID, out
}

// Insert writes a single entry to the audit.audit_log table.
func (r *AuditRepo) Insert(ctx context.Context, entry *model.AuditEntry) error {
	auditUserID, auditClientID, auditMetadata := actorColumns(entry)
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO audit.audit_log (id, timestamp, event_type, user_id, client_id, ip, user_agent, fingerprint_hash, device_id, metadata, risk_score)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		entry.ID, entry.Timestamp, entry.EventType,
		nullStr(auditUserID), nullStr(auditClientID),
		nullStr(entry.IP), nullStr(clampUserAgent(entry.UserAgent)),
		nullStr(entry.FingerprintHash), nullStr(entry.DeviceID),
		auditMetadata, entry.RiskScore,
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
		batchUserID, batchClientID, batchMetadata := actorColumns(e)
		_, err := tx.Exec(ctx, `
			INSERT INTO audit.audit_log (id, timestamp, event_type, user_id, client_id, ip, user_agent, fingerprint_hash, device_id, metadata, risk_score)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			e.ID, e.Timestamp, e.EventType,
			nullStr(batchUserID), nullStr(batchClientID),
			nullStr(e.IP), nullStr(clampUserAgent(e.UserAgent)),
			nullStr(e.FingerprintHash), nullStr(e.DeviceID),
			batchMetadata, e.RiskScore,
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
	// Zero is absence, matching the field's contract: risk_score >= 0 is every
	// row, so emitting the predicate for an unset filter would put a clause in
	// the plan that selects nothing out and reads as though it did.
	if filter.MinRiskScore > 0 {
		conditions = append(conditions, fmt.Sprintf("risk_score >= $%d", argIdx))
		args = append(args, filter.MinRiskScore)
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

// CountByUser returns the total number of audit entries held for a user,
// unaffected by the LIMIT that Query applies.
func (r *AuditRepo) CountByUser(ctx context.Context, userID string) (int, error) {
	var count int
	if err := r.db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM audit.audit_log WHERE user_id = $1", userID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count audit entries for user: %w", err)
	}
	return count, nil
}

// auditRetentionLockKey is the advisory-lock key the retention sweep serializes
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
		"SELECT audit.cleanup_old_entries($1::interval, $2)",
		fmt.Sprintf("%d seconds", int(interval.Seconds())), auditCleanupBatch,
	).Scan(&deleted); err != nil {
		return 0, true, fmt.Errorf("cleanup audit entries: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, true, fmt.Errorf("cleanup audit entries: commit: %w", err)
	}
	return deleted, true, nil
}

// auditCleanupBatch is the shared bound, declared on the repository interface so
// the sweeper that loops over this call agrees with it.
const auditCleanupBatch = repository.AuditCleanupBatch

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
