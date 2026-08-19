package attack

// Shared PostgreSQL harness for the db-privesc attack suite (atk_db_*).
//
// This mirrors tests/integration/containers_test.go on purpose, with one
// deliberate difference: the integration fixture runs every migration through
// stripRoleGrants() and connects as the container owner, which erases the whole
// privilege model before a single test sees it. That is exactly why real grant
// bugs shipped green there. The attack suite must exercise the model as deployed,
// so this harness applies every migration VERBATIM, including the CREATE ROLE
// blocks and the GRANT/REVOKE statements, and then hands out pools authenticated
// as the real vault_app / vault_admin roles.
//
// Everything here is namespaced atkDB* so it cannot collide with helpers another
// agent drops into package attack.

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/tests/testutil"
)

// atkDBSkipIfNoDocker honors the same opt-out switch the integration suite uses,
// so a machine with no container runtime can still run the pure-Go tests, and
// probes the runtime rather than assuming testcontainers will find a live one.
func atkDBSkipIfNoDocker(t *testing.T) {
	t.Helper()
	testutil.RequireContainerRuntime(t)
}

// atkDBSetupPG starts a PostgreSQL container and applies every migration in
// order, unmodified. The returned pool is authenticated as the container owner
// (a superuser), which is the migration/DDL role vault_mig models. Callers who
// need a least-privilege role open one with atkDBRolePool.
//
// Container startup on the shared podman socket is occasionally flaky, so this
// retries the create once before giving up, per the suite's operating notes.
func atkDBSetupPG(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	atkDBSkipIfNoDocker(t)
	ctx := context.Background()

	var pgContainer *tcpostgres.PostgresContainer
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		pgContainer, err = tcpostgres.Run(ctx,
			"postgres:16-alpine",
			tcpostgres.WithDatabase("vault_test"),
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
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("start postgres container (after retry): %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("connection string: %v", err)
	}

	poolCfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("parse pool config: %v", err)
	}
	poolCfg.MaxConns = 5
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("create pool: %v", err)
	}

	// A dedicated connection for DDL. The migrations carry DO $$ blocks and
	// dollar-quoted function bodies, so each file goes to the server as one simple
	// query rather than being split on ';' the way applyRealGrants has to.
	migConn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		pool.Close()
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("connect for migrations: %v", err)
	}

	for _, f := range atkDBMigrationFiles(t) {
		sqlBytes, readErr := os.ReadFile("../../migrations/" + f)
		if readErr != nil {
			migConn.Close(ctx)
			pool.Close()
			_ = pgContainer.Terminate(ctx)
			t.Fatalf("read migration %s: %v", f, readErr)
		}
		if _, execErr := migConn.Exec(ctx, string(sqlBytes)); execErr != nil {
			migConn.Close(ctx)
			pool.Close()
			_ = pgContainer.Terminate(ctx)
			t.Fatalf("apply migration %s VERBATIM: %v", f, execErr)
		}
	}

	cleanup := func() {
		migConn.Close(ctx)
		pool.Close()
		// Only ever terminate the container this call created, by its own handle.
		// Never a broad sweep: production pods share this podman socket.
		_ = pgContainer.Terminate(ctx)
	}
	return pool, cleanup
}

// atkDBMigrationFiles returns the migration filenames in lexical (== apply) order.
func atkDBMigrationFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("../../migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	return files
}

// atkDBRolePool opens a pool authenticated as the named least-privilege role.
// Migration 001 creates the roles with LOGIN but no password; TCP auth needs one,
// so we set it here as the owner and then connect fresh as the role. The
// current_user check is not decoration: a test that silently ran as the owner
// would prove the opposite of what it claims.
func atkDBRolePool(t *testing.T, owner *pgxpool.Pool, role string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	pw := role + "_atk_pw"
	if _, err := owner.Exec(ctx, fmt.Sprintf("ALTER ROLE %s WITH PASSWORD '%s'", role, pw)); err != nil {
		t.Fatalf("set %s password: %v", role, err)
	}

	cfg := owner.Config().ConnConfig
	dsn := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(role, pw),
		Host:     cfg.Host + ":" + strconv.Itoa(int(cfg.Port)),
		Path:     "/" + cfg.Database,
		RawQuery: "sslmode=disable",
	}).String()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect as %s: %v", role, err)
	}
	t.Cleanup(pool.Close)

	var who string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&who); err != nil {
		t.Fatalf("verify role: %v", err)
	}
	if who != role {
		t.Fatalf("connected as %q, want %q: the test would prove nothing", who, role)
	}
	return pool
}

// atkDBRandomID returns a fresh UUID string using the product's own generator,
// so the ids these tests write are shaped exactly like the ones it writes.
func atkDBRandomID(t *testing.T) string {
	t.Helper()
	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("random uuid: %v", err)
	}
	return id
}
