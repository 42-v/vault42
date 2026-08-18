package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/42-v/vault42/internal/migrate"
)

// setupRawPostgres starts a clean PostgreSQL container without running any migrations.
func setupRawPostgres(t *testing.T) (*pgx.Conn, func()) {
	t.Helper()
	skipIfNoDocker(t)
	ctx := context.Background()

	pgContainer, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("vault_mig_test"),
		tcpostgres.WithUsername("vault_test"),
		tcpostgres.WithPassword("vault_test"),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(120*time.Second),
				wait.ForListeningPort("5432/tcp").
					WithStartupTimeout(120*time.Second),
			),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		pgContainer.Terminate(ctx)
		t.Fatalf("get connection string: %v", err)
	}

	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		pgContainer.Terminate(ctx)
		t.Fatalf("connect: %v", err)
	}

	cleanup := func() {
		conn.Close(ctx)
		pgContainer.Terminate(ctx)
	}

	return conn, cleanup
}

func TestMigrateRun(t *testing.T) {
	t.Run("Run with real migrations directory", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		// The migration directory relative to this test file
		migrationsDir := "../../migrations"

		// Strip GRANT/REVOKE from the migration file for the test environment
		// We need to create a temp directory with cleaned migrations
		tmpDir := t.TempDir()
		originalSQL, err := os.ReadFile(filepath.Join(migrationsDir, "001_initial_schema.sql"))
		if err != nil {
			t.Fatalf("read original migration: %v", err)
		}
		cleanedSQL := stripRoleGrants(string(originalSQL))
		if err := os.WriteFile(filepath.Join(tmpDir, "001_initial_schema.sql"), []byte(cleanedSQL), 0o644); err != nil {
			t.Fatalf("write cleaned migration: %v", err)
		}

		if err := migrate.Run(ctx, conn, tmpDir); err != nil {
			t.Fatalf("Run: %v", err)
		}

		// Verify the schema was created
		var schemaExists bool
		err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = 'auth')`).Scan(&schemaExists)
		if err != nil {
			t.Fatalf("check schema: %v", err)
		}
		if !schemaExists {
			t.Error("auth schema not created")
		}

		// Verify a table was created
		var tableExists bool
		err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema = 'auth' AND table_name = 'users')`).Scan(&tableExists)
		if err != nil {
			t.Fatalf("check table: %v", err)
		}
		if !tableExists {
			t.Error("auth.users table not created")
		}

		// Verify migration was recorded
		var version string
		err = conn.QueryRow(ctx, `SELECT version FROM public.schema_migrations WHERE version = '001_initial_schema.sql'`).Scan(&version)
		if err != nil {
			t.Fatalf("check migration record: %v", err)
		}
		if version != "001_initial_schema.sql" {
			t.Errorf("version = %q, want %q", version, "001_initial_schema.sql")
		}
	})

	t.Run("Idempotent - run twice is no-op", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		tmpDir := t.TempDir()
		originalSQL, err := os.ReadFile("../../migrations/001_initial_schema.sql")
		if err != nil {
			t.Fatalf("read migration: %v", err)
		}
		cleanedSQL := stripRoleGrants(string(originalSQL))
		if err := os.WriteFile(filepath.Join(tmpDir, "001_initial_schema.sql"), []byte(cleanedSQL), 0o644); err != nil {
			t.Fatalf("write migration: %v", err)
		}

		// First run
		if err := migrate.Run(ctx, conn, tmpDir); err != nil {
			t.Fatalf("Run first: %v", err)
		}

		// Second run should be a no-op (no error)
		if err := migrate.Run(ctx, conn, tmpDir); err != nil {
			t.Fatalf("Run second: %v", err)
		}

		// Verify only one migration was recorded
		var count int
		err = conn.QueryRow(ctx, `SELECT COUNT(*) FROM public.schema_migrations`).Scan(&count)
		if err != nil {
			t.Fatalf("count migrations: %v", err)
		}
		if count != 1 {
			t.Errorf("migration count = %d, want 1", count)
		}
	})

	t.Run("Invalid SQL rolls back", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		tmpDir := t.TempDir()
		invalidSQL := `CREATE TABLE this_is_valid (id INT);
THIS IS INVALID SQL;`
		if err := os.WriteFile(filepath.Join(tmpDir, "001_bad.sql"), []byte(invalidSQL), 0o644); err != nil {
			t.Fatalf("write bad migration: %v", err)
		}

		err := migrate.Run(ctx, conn, tmpDir)
		if err == nil {
			t.Fatal("expected error for invalid SQL, got nil")
		}

		// Verify no migration was recorded (rolled back)
		var count int
		err = conn.QueryRow(ctx, `SELECT COUNT(*) FROM public.schema_migrations`).Scan(&count)
		if err != nil {
			t.Fatalf("count migrations: %v", err)
		}
		if count != 0 {
			t.Errorf("migration count = %d, want 0 (should have rolled back)", count)
		}
	})

	t.Run("Non-existent directory returns error", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		err := migrate.Run(ctx, conn, "/nonexistent/path/to/migrations")
		if err == nil {
			t.Fatal("expected error for non-existent directory, got nil")
		}
	})

	t.Run("Empty directory is no-op", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		tmpDir := t.TempDir()
		if err := migrate.Run(ctx, conn, tmpDir); err != nil {
			t.Fatalf("Run with empty dir: %v", err)
		}

		// Verify schema_migrations table was still created
		var exists bool
		err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'schema_migrations')`).Scan(&exists)
		if err != nil {
			t.Fatalf("check schema_migrations: %v", err)
		}
		if !exists {
			t.Error("schema_migrations table should exist even with no migration files")
		}
	})

	t.Run("Multiple migrations applied in order", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		tmpDir := t.TempDir()
		mig1 := `CREATE TABLE public.test_table_1 (id INT PRIMARY KEY);`
		mig2 := `CREATE TABLE public.test_table_2 (id INT PRIMARY KEY, ref INT REFERENCES public.test_table_1(id));`

		if err := os.WriteFile(filepath.Join(tmpDir, "001_first.sql"), []byte(mig1), 0o644); err != nil {
			t.Fatalf("write mig1: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "002_second.sql"), []byte(mig2), 0o644); err != nil {
			t.Fatalf("write mig2: %v", err)
		}

		if err := migrate.Run(ctx, conn, tmpDir); err != nil {
			t.Fatalf("Run: %v", err)
		}

		// Verify both tables exist
		for _, table := range []string{"test_table_1", "test_table_2"} {
			var exists bool
			err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, table).Scan(&exists)
			if err != nil {
				t.Fatalf("check %s: %v", table, err)
			}
			if !exists {
				t.Errorf("table %s not created", table)
			}
		}

		// Verify both migrations were recorded
		var count int
		err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM public.schema_migrations`).Scan(&count)
		if err != nil {
			t.Fatalf("count migrations: %v", err)
		}
		if count != 2 {
			t.Errorf("migration count = %d, want 2", count)
		}
	})

	t.Run("Non-SQL files are ignored", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		tmpDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("not sql"), 0o644); err != nil {
			t.Fatalf("write readme: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "001_valid.sql"), []byte("CREATE TABLE public.ignore_test (id INT);"), 0o644); err != nil {
			t.Fatalf("write valid migration: %v", err)
		}

		if err := migrate.Run(ctx, conn, tmpDir); err != nil {
			t.Fatalf("Run: %v", err)
		}

		var count int
		err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM public.schema_migrations`).Scan(&count)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 1 {
			t.Errorf("migration count = %d, want 1 (non-SQL files should be skipped)", count)
		}
	})

	t.Run("Partial failure does not affect previously applied migrations", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		tmpDir := t.TempDir()
		mig1 := `CREATE TABLE public.partial_test (id INT PRIMARY KEY);`
		mig2 := `INVALID SQL HERE;`

		if err := os.WriteFile(filepath.Join(tmpDir, "001_good.sql"), []byte(mig1), 0o644); err != nil {
			t.Fatalf("write mig1: %v", err)
		}

		// First run: only good migration
		if err := migrate.Run(ctx, conn, tmpDir); err != nil {
			t.Fatalf("Run first: %v", err)
		}

		// Now add the bad migration
		if err := os.WriteFile(filepath.Join(tmpDir, "002_bad.sql"), []byte(mig2), 0o644); err != nil {
			t.Fatalf("write mig2: %v", err)
		}

		// Second run should fail on 002_bad.sql
		err := migrate.Run(ctx, conn, tmpDir)
		if err == nil {
			t.Fatal("expected error for bad migration")
		}

		// Verify first migration still recorded
		var count int
		err = conn.QueryRow(ctx, `SELECT COUNT(*) FROM public.schema_migrations WHERE version = '001_good.sql'`).Scan(&count)
		if err != nil {
			t.Fatalf("check first migration: %v", err)
		}
		if count != 1 {
			t.Errorf("first migration count = %d, want 1", count)
		}

		// Verify table from first migration still exists
		var exists bool
		err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'partial_test')`).Scan(&exists)
		if err != nil {
			t.Fatalf("check table: %v", err)
		}
		if !exists {
			t.Error("partial_test table should still exist")
		}
	})

	t.Run("Canceled context fails acquiring the migration lock", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := migrate.Run(ctx, conn, t.TempDir())
		if err == nil {
			t.Fatal("expected error for canceled context, got nil")
		}
		if !strings.Contains(err.Error(), "acquire migration lock") {
			t.Errorf("error = %q, want it to contain %q", err, "acquire migration lock")
		}
	})

	t.Run("A role without CREATE on public fails at the tracking table", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		// The lock has to be reachable by a role that cannot create the table,
		// or this covers the lock's error path a second time instead of the
		// CREATE's. pg_advisory_lock is executable by PUBLIC; CREATE on schema
		// public has not been granted to PUBLIC since PostgreSQL 15.
		if _, err := conn.Exec(ctx,
			`CREATE ROLE migrate_nocreate LOGIN PASSWORD 'migrate_nocreate'`); err != nil {
			t.Fatalf("create role: %v", err)
		}

		cfg := conn.Config().Copy()
		cfg.User = "migrate_nocreate"
		cfg.Password = "migrate_nocreate"
		limited, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("connect as migrate_nocreate: %v", err)
		}
		defer limited.Close(ctx)

		err = migrate.Run(ctx, limited, t.TempDir())
		if err == nil {
			t.Fatal("expected error creating the tracking table without CREATE, got nil")
		}
		if !strings.Contains(err.Error(), "create schema_migrations") {
			t.Errorf("error = %q, want it to contain %q", err, "create schema_migrations")
		}

		// The lock is released even though the run failed, so the next runner
		// does not queue behind a session that already gave up. Asked from a
		// third session, which is the only place the answer means anything.
		var free bool
		if err := conn.QueryRow(ctx,
			"SELECT pg_try_advisory_lock($1)", migrate.LockKey).Scan(&free); err != nil {
			t.Fatalf("probe the migration lock: %v", err)
		}
		if !free {
			t.Error("the migration advisory lock is still held after a failed run; the next " +
				"replica to boot would wait behind a session that already gave up")
		} else if _, err := conn.Exec(ctx,
			"SELECT pg_advisory_unlock($1)", migrate.LockKey); err != nil {
			t.Fatalf("release the probe lock: %v", err)
		}
	})

	t.Run("Malformed tracking table fails applied query", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		// Pre-create a tracking table without a version column so
		// CREATE TABLE IF NOT EXISTS skips and the SELECT fails
		if _, err := conn.Exec(ctx, `CREATE TABLE public.schema_migrations (nope INT)`); err != nil {
			t.Fatalf("create divergent table: %v", err)
		}

		err := migrate.Run(ctx, conn, t.TempDir())
		if err == nil {
			t.Fatal("expected error for missing version column, got nil")
		}
		if !strings.Contains(err.Error(), "query applied") {
			t.Errorf("error = %q, want it to contain %q", err, "query applied")
		}
	})

	t.Run("NULL version fails scan", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		// Pre-create the tracking table with a nullable version and a NULL row
		if _, err := conn.Exec(ctx, `CREATE TABLE public.schema_migrations (version VARCHAR(255), applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`); err != nil {
			t.Fatalf("create nullable table: %v", err)
		}
		if _, err := conn.Exec(ctx, `INSERT INTO public.schema_migrations (version) VALUES (NULL)`); err != nil {
			t.Fatalf("insert NULL version: %v", err)
		}

		err := migrate.Run(ctx, conn, t.TempDir())
		if err == nil {
			t.Fatal("expected error scanning NULL version, got nil")
		}
		if !strings.Contains(err.Error(), "scan version") {
			t.Errorf("error = %q, want it to contain %q", err, "scan version")
		}
	})

	t.Run("Failing tracking view surfaces iterate error", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		// A view named schema_migrations makes CREATE TABLE IF NOT EXISTS skip;
		// the SELECT prepares fine but raises during execution, which pgx
		// defers to rows.Err()
		if _, err := conn.Exec(ctx, `CREATE FUNCTION public.migrate_boom() RETURNS SETOF text LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'boom'; END $$`); err != nil {
			t.Fatalf("create function: %v", err)
		}
		if _, err := conn.Exec(ctx, `CREATE VIEW public.schema_migrations AS SELECT public.migrate_boom() AS version`); err != nil {
			t.Fatalf("create view: %v", err)
		}

		err := migrate.Run(ctx, conn, t.TempDir())
		if err == nil {
			t.Fatal("expected error from failing view, got nil")
		}
		if !strings.Contains(err.Error(), "iterate migrations") {
			t.Errorf("error = %q, want it to contain %q", err, "iterate migrations")
		}
	})

	t.Run("Unreadable migration file returns error", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		// A dangling symlink lists in ReadDir but fails ReadFile
		tmpDir := t.TempDir()
		if err := os.Symlink(filepath.Join(tmpDir, "missing-target"), filepath.Join(tmpDir, "001_broken.sql")); err != nil {
			t.Fatalf("create symlink: %v", err)
		}

		err := migrate.Run(ctx, conn, tmpDir)
		if err == nil {
			t.Fatal("expected error for unreadable migration, got nil")
		}
		if !strings.Contains(err.Error(), "read 001_broken.sql") {
			t.Errorf("error = %q, want it to contain %q", err, "read 001_broken.sql")
		}
	})

	t.Run("Duplicate version record rolls back", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		// The migration inserts its own version, so Run's tracking INSERT
		// hits the primary key inside the same tx
		tmpDir := t.TempDir()
		selfSQL := `INSERT INTO public.schema_migrations (version) VALUES ('001_self.sql');`
		if err := os.WriteFile(filepath.Join(tmpDir, "001_self.sql"), []byte(selfSQL), 0o644); err != nil {
			t.Fatalf("write migration: %v", err)
		}

		err := migrate.Run(ctx, conn, tmpDir)
		if err == nil {
			t.Fatal("expected error recording duplicate version, got nil")
		}
		if !strings.Contains(err.Error(), "record 001_self.sql") {
			t.Errorf("error = %q, want it to contain %q", err, "record 001_self.sql")
		}

		// Verify the migration's own insert rolled back too
		var count int
		if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM public.schema_migrations`).Scan(&count); err != nil {
			t.Fatalf("count migrations: %v", err)
		}
		if count != 0 {
			t.Errorf("migration count = %d, want 0 (should have rolled back)", count)
		}
	})

	t.Run("Deferred constraint violation fails at commit", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		// The deferred unique check passes tx.Exec and only fires inside tx.Commit
		tmpDir := t.TempDir()
		deferredSQL := `CREATE TABLE public.deferred_test (id INT, CONSTRAINT deferred_test_uq UNIQUE (id) DEFERRABLE INITIALLY DEFERRED);
INSERT INTO public.deferred_test VALUES (1), (1);`
		if err := os.WriteFile(filepath.Join(tmpDir, "001_deferred.sql"), []byte(deferredSQL), 0o644); err != nil {
			t.Fatalf("write migration: %v", err)
		}

		err := migrate.Run(ctx, conn, tmpDir)
		if err == nil {
			t.Fatal("expected error committing deferred violation, got nil")
		}
		if !strings.Contains(err.Error(), "commit 001_deferred.sql") {
			t.Errorf("error = %q, want it to contain %q", err, "commit 001_deferred.sql")
		}

		// Verify nothing was recorded
		var count int
		if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM public.schema_migrations`).Scan(&count); err != nil {
			t.Fatalf("count migrations: %v", err)
		}
		if count != 0 {
			t.Errorf("migration count = %d, want 0 (commit failed)", count)
		}
	})
}

// migrateReplicas is how many runners race. The chart ships replicaCount 3 with
// VAULT_AUTO_MIGRATE true, and three was enough to lose two of them on a real
// database, so the number here is the deployed one and not a stress figure.
const migrateReplicas = 3

// TestMigrateRunConcurrentReplicas is the gate on the advisory lock.
//
// Without it, three replicas booting together against one database is not a
// theoretical race: two of the three die, on a fresh install with `create
// schema_migrations: duplicate key value violates unique constraint
// "pg_type_typname_nsp_index"` (CREATE TABLE IF NOT EXISTS is not atomic against
// concurrent DDL), and on an upgrade with the same error against
// pg_proc_proname_args_nsp_index (CREATE OR REPLACE FUNCTION races identically).
// cmd/vault turns each into log.Fatalf, so each loser is a CrashLoopBackOff.
//
// Both shapes are here because they fail on different statements: the first
// outside any transaction, the second inside one.
func TestMigrateRunConcurrentReplicas(t *testing.T) {
	t.Run("Fresh database", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()

		dir := t.TempDir()
		writeMigration(t, dir, "001_schema.sql",
			`CREATE SCHEMA IF NOT EXISTS racy;
CREATE TABLE racy.rows (id INT PRIMARY KEY);`)

		runMigrateRace(t, conn, dir)
		assertAppliedVersions(t, conn, []string{"001_schema.sql"})
	})

	t.Run("Upgrade staged one migration behind", func(t *testing.T) {
		conn, cleanup := setupRawPostgres(t)
		defer cleanup()
		ctx := context.Background()

		dir := t.TempDir()
		writeMigration(t, dir, "001_schema.sql", `CREATE SCHEMA IF NOT EXISTS racy;`)
		if err := migrate.Run(ctx, conn, dir); err != nil {
			t.Fatalf("stage the database: %v", err)
		}

		// A function replacement, which is what migration 030 does and what the
		// three replicas collided on in the measured upgrade.
		writeMigration(t, dir, "002_function.sql",
			`CREATE OR REPLACE FUNCTION racy.answer() RETURNS INT
LANGUAGE sql AS $$ SELECT 42 $$;`)

		runMigrateRace(t, conn, dir)
		assertAppliedVersions(t, conn, []string{"001_schema.sql", "002_function.sql"})
	})
}

// runMigrateRace releases migrateReplicas runners on their own connections at
// the same instant and requires every one of them to return nil.
func runMigrateRace(t *testing.T, conn *pgx.Conn, dir string) {
	t.Helper()
	ctx := context.Background()

	start := make(chan struct{})
	errs := make([]error, migrateReplicas)
	var wg sync.WaitGroup

	for i := range migrateReplicas {
		replica, err := pgx.ConnectConfig(ctx, conn.Config().Copy())
		if err != nil {
			t.Fatalf("connect replica %d: %v", i, err)
		}
		defer replica.Close(ctx)

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = migrate.Run(ctx, replica, dir)
		}()
	}

	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("replica %d failed: %v\nWith VAULT_AUTO_MIGRATE and more than one replica "+
				"this is a pod that never becomes ready. The runs are serialized by an advisory "+
				"lock precisely so every replica either applies the migrations or finds them "+
				"already applied.", i, err)
		}
	}
}

func writeMigration(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// assertAppliedVersions checks that the race applied each migration exactly
// once. Three runners that each recorded a row would pass a count check on the
// number of runners and mean the opposite of what this test is about.
func assertAppliedVersions(t *testing.T, conn *pgx.Conn, want []string) {
	t.Helper()
	rows, err := conn.Query(context.Background(),
		`SELECT version FROM public.schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	defer rows.Close()

	var got []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan version: %v", err)
		}
		got = append(got, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate schema_migrations: %v", err)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("schema_migrations holds %v, want %v", got, want)
	}
}
