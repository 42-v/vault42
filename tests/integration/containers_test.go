package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/42-v/vault42/internal/redis"
)

// skipIfNoDocker skips the test if Docker is not available.
func skipIfNoDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("SKIP_INTEGRATION") == "1" {
		t.Skip("SKIP_INTEGRATION=1")
	}
}

// setupPostgres starts a PostgreSQL testcontainer and runs the initial migration.
// Returns a *pgxpool.Pool and the raw connection string. Callers must call cleanup.
func setupPostgres(t *testing.T) (*pgxpool.Pool, *pgx.Conn, func()) {
	t.Helper()
	skipIfNoDocker(t)
	ctx := context.Background()

	pgContainer, err := tcpostgres.Run(ctx,
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
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		pgContainer.Terminate(ctx)
		t.Fatalf("get connection string: %v", err)
	}

	// Create pool for app usage
	poolCfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		pgContainer.Terminate(ctx)
		t.Fatalf("parse pool config: %v", err)
	}
	poolCfg.MaxConns = 5
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		pgContainer.Terminate(ctx)
		t.Fatalf("create pool: %v", err)
	}

	// Single connection for migrations
	migConn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		pool.Close()
		pgContainer.Terminate(ctx)
		t.Fatalf("connect for migrations: %v", err)
	}

	// Run all migrations in order
	migFiles := []string{
		"001_initial_schema.sql",
	}
	for _, f := range migFiles {
		migSQL, err := os.ReadFile("../../migrations/" + f)
		if err != nil {
			migConn.Close(ctx)
			pool.Close()
			pgContainer.Terminate(ctx)
			t.Fatalf("read migration %s: %v", f, err)
		}
		migStr := stripRoleGrants(string(migSQL))
		if _, err := migConn.Exec(ctx, migStr); err != nil {
			migConn.Close(ctx)
			pool.Close()
			pgContainer.Terminate(ctx)
			t.Fatalf("run migration %s: %v", f, err)
		}
	}

	cleanup := func() {
		migConn.Close(ctx)
		pool.Close()
		pgContainer.Terminate(ctx)
	}

	return pool, migConn, cleanup
}

// stripRoleGrants removes GRANT/REVOKE and ALTER DEFAULT PRIVILEGES lines
// that reference vault_app (which doesn't exist in the test DB).
func stripRoleGrants(sql string) string {
	var result []byte
	lines := []byte(sql)
	start := 0
	for i := 0; i < len(lines); i++ {
		if lines[i] == '\n' || i == len(lines)-1 {
			end := i
			if i == len(lines)-1 && lines[i] != '\n' {
				end = i + 1
			}
			line := string(lines[start:end])
			skip := false
			for _, prefix := range []string{"GRANT ", "REVOKE ", "ALTER DEFAULT"} {
				if len(line) >= len(prefix) && line[:len(prefix)] == prefix {
					skip = true
					break
				}
			}
			if !skip {
				result = append(result, lines[start:end]...)
				result = append(result, '\n')
			}
			start = i + 1
		}
	}
	return string(result)
}

// setupRedis starts a Redis testcontainer using the base testcontainers API.
// Returns a *redis.Client and address. Callers must call cleanup.
func setupRedis(t *testing.T) (*redis.Client, string, func()) {
	t.Helper()
	skipIfNoDocker(t)
	ctx := context.Background()

	redisContainer, err := testcontainers.Run(ctx,
		"redis:7-alpine",
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForLog("Ready to accept connections").
					WithStartupTimeout(120*time.Second),
				wait.ForListeningPort("6379/tcp").
					WithStartupTimeout(120*time.Second),
			),
		),
		testcontainers.WithCmdArgs("--loglevel", "verbose"),
	)
	if err != nil {
		t.Fatalf("start redis container: %v", err)
	}

	endpoint, err := redisContainer.Endpoint(ctx, "")
	if err != nil {
		redisContainer.Terminate(ctx)
		t.Fatalf("get redis endpoint: %v", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr: endpoint,
	})

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx); err != nil {
		client.Close()
		redisContainer.Terminate(ctx)
		t.Fatalf("ping redis: %v", err)
	}

	cleanup := func() {
		client.Close()
		redisContainer.Terminate(ctx)
	}

	return client, endpoint, cleanup
}
