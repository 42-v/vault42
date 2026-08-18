// Package migrate provides a minimal SQL migration runner that applies .sql files in order.
package migrate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// LockKey is the advisory-lock key the migration runner serializes on.
//
// Arbitrary but fixed, and distinct from the three keys already in use against
// this database: 4242 is the audit retention sweep, 4243 the account-recovery
// prune, 4244 signing-key rotation. Two runners that picked different keys would
// serialize against nothing.
const LockKey int64 = 4245

// Run executes all pending SQL migrations in order.
// Uses the vault_mig role. Creates schema_migrations tracking table if needed.
//
// One runner at a time, cluster-wide. The chart ships replicaCount 3 with
// VAULT_AUTO_MIGRATE true, so on a fresh install three pods call this against
// one database within milliseconds of each other, and cmd/vault treats any error
// here as log.Fatalf. Measured on a real PostgreSQL, three concurrent runners
// with no lock:
//
//   - fresh database: two of three fail with `create schema_migrations:
//     duplicate key value violates unique constraint
//     "pg_type_typname_nsp_index"`, because CREATE TABLE IF NOT EXISTS is not
//     atomic against concurrent DDL;
//   - database staged one release behind: two of three fail on
//     `pg_proc_proname_args_nsp_index`, because the CREATE OR REPLACE FUNCTION
//     in the pending migration races the same way.
//
// Neither corrupts anything -- each migration commits with its own
// schema_migrations row inside one transaction, and a re-run converges -- but
// each loser is a CrashLoopBackOff, and on a database where a migration takes
// minutes rather than milliseconds the losers keep restarting for as long as it
// runs.
//
// The lock is session-scoped rather than transaction-scoped because the run is
// not one transaction: it is one transaction per file, and the tracking table is
// created outside all of them. It is taken before that CREATE, which is the
// statement the fresh-install race is on, and released on every path out.
func Run(ctx context.Context, conn *pgx.Conn, migrationsDir string) error {
	// Blocking, not pg_try_advisory_lock: a replica that loses the race has to
	// wait, then find the schema already at its own version. A runner that
	// skipped instead would return success to a caller that is about to serve
	// against a schema nobody has migrated yet.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", LockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// WithoutCancel so a canceled ctx still releases the lock. Closing the
		// connection releases it too, and cmd/vault does close it, but a caller
		// that keeps its connection would otherwise hold the lock for the life
		// of that session and block every other runner in the fleet.
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", LockKey)
	}()

	// Create tracking table
	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS public.schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	// Get applied migrations
	rows, err := conn.Query(ctx, "SELECT version FROM public.schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("query applied: %w", err)
	}
	applied := make(map[string]bool)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return fmt.Errorf("scan version: %w", err)
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate migrations: %w", err)
	}

	// Read migration files
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	// Apply pending migrations
	for _, f := range files {
		if applied[f] {
			continue
		}

		sql, err := os.ReadFile(filepath.Join(migrationsDir, f)) // #nosec G304 -- migrationsDir is admin-configured, not user input; filenames are from os.ReadDir
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx for %s: %w", f, err)
		}

		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("execute %s: %w", f, err)
		}

		if _, err := tx.Exec(ctx, "INSERT INTO public.schema_migrations (version) VALUES ($1)", f); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record %s: %w", f, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", f, err)
		}
	}

	return nil
}
