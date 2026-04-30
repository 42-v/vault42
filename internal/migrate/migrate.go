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

// Run executes all pending SQL migrations in order.
// Uses the vault_mig role. Creates schema_migrations tracking table if needed.
func Run(ctx context.Context, conn *pgx.Conn, migrationsDir string) error {
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
