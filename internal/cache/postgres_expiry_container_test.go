package cache

import (
	"context"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// The Postgres backend keeps its expiry rules in SQL, which is the one part of
// this package that cannot be judged by reading Go. SetIfNotExists decides
// whether a guard key is free, and its answer depends on how PostgreSQL
// resolves an ON CONFLICT arbiter and an ON CONFLICT DO UPDATE predicate
// against rows the same command is touching. The documentation does not settle
// that, so the tests below run the real statements against a real server and
// judge the return value a caller sees.
//
// One PostgreSQL container is shared by every test in this file and started
// lazily, so a machine without a container runtime still runs the rest of the
// package.

var (
	cachePGOnce sync.Once
	cachePGPool *pgxpool.Pool
	cachePGStop func()
	cachePGErr  string
)

// TestMain terminates the shared PostgreSQL container once the package is done
// with it. Without this the container outlives the test binary and the next run
// competes with it for the daemon.
func TestMain(m *testing.M) {
	code := m.Run()
	if cachePGStop != nil {
		cachePGStop()
	}
	os.Exit(code)
}

// cachePGRuntime points DOCKER_HOST at a reachable container socket, or skips.
// Failing hard would make a runtime-free machine indistinguishable from a
// broken backend; the canonical coverage run refuses to start without a
// runtime, so nothing is silently skipped there.
func cachePGRuntime(t *testing.T) {
	t.Helper()
	if os.Getenv("SKIP_INTEGRATION") == "1" {
		t.Skip("SKIP_INTEGRATION=1")
	}
	if os.Getenv("DOCKER_HOST") != "" {
		return
	}
	candidates := []string{"/run/podman/podman.sock", "/var/run/docker.sock"}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		candidates = append([]string{runtimeDir + "/podman/podman.sock"}, candidates...)
	}
	for _, sock := range candidates {
		if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			t.Setenv("DOCKER_HOST", "unix://"+sock)
			return
		}
	}
	t.Skip("no container runtime found; set DOCKER_HOST or start the rootless podman socket")
}

// cachePGStripRoleGrants drops the top-level GRANT/REVOKE/ALTER DEFAULT
// statements from a migration. They name roles the throwaway container has no
// reason to own, and the privilege model is asserted where it belongs, against
// the real roles in tests/integration.
func cachePGStripRoleGrants(sql string) string {
	var kept []string
	for _, line := range strings.Split(sql, "\n") {
		skip := false
		for _, prefix := range []string{"GRANT ", "REVOKE ", "ALTER DEFAULT"} {
			if strings.HasPrefix(line, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// startCachePG brings up PostgreSQL and applies every migration in order. The
// migrations rather than a hand-written CREATE TABLE are what make the fixture
// binding: auth.cache's primary key is the ON CONFLICT arbiter under test, and
// a fixture that drifted from the real schema would answer a different question
// than the one production asks.
func startCachePG() (*pgxpool.Pool, func(), string) {
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("vault_cache"),
		tcpostgres.WithUsername("vault_cache"),
		tcpostgres.WithPassword("vault_cache"),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(180*time.Second),
				wait.ForListeningPort("5432/tcp").
					WithStartupTimeout(180*time.Second),
			),
		),
	)
	if err != nil {
		return nil, nil, "start postgres: " + err.Error()
	}
	stop := func() { _ = container.Terminate(context.Background()) }

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		stop()
		return nil, nil, "connection string: " + err.Error()
	}

	migConn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		stop()
		return nil, nil, "connect for migrations: " + err.Error()
	}
	defer migConn.Close(ctx) //nolint:errcheck // fixture teardown

	entries, err := os.ReadDir("../../migrations")
	if err != nil {
		stop()
		return nil, nil, "read migrations: " + err.Error()
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, f := range files {
		sql, readErr := os.ReadFile("../../migrations/" + f)
		if readErr != nil {
			stop()
			return nil, nil, "read migration " + f + ": " + readErr.Error()
		}
		if _, execErr := migConn.Exec(ctx, cachePGStripRoleGrants(string(sql))); execErr != nil {
			stop()
			return nil, nil, "run migration " + f + ": " + execErr.Error()
		}
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		stop()
		return nil, nil, "create pool: " + err.Error()
	}
	return pool, func() { pool.Close(); stop() }, ""
}

// newPostgresCacheOnRealServer returns a PostgresCache wired to the shared
// container. The background sweep is stopped immediately: these tests seed
// expired rows deliberately, and a reaper racing them would turn "SetIfNotExists
// saw an expired row" into "SetIfNotExists saw no row at all", which is the very
// distinction under test.
func newPostgresCacheOnRealServer(t *testing.T) (*PostgresCache, *pgxpool.Pool) {
	t.Helper()
	cachePGRuntime(t)
	cachePGOnce.Do(func() { cachePGPool, cachePGStop, cachePGErr = startCachePG() })
	if cachePGErr != "" {
		t.Fatalf("postgres fixture: %s", cachePGErr)
	}
	c, err := NewPostgresCache(cachePGPool)
	if err != nil {
		t.Fatalf("NewPostgresCache: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("stop sweep: %v", err)
	}
	return c, cachePGPool
}

// seedCacheRow writes a row straight into auth.cache, bypassing the cache API,
// so a test can state exactly what the server holds before the call it judges.
func seedCacheRow(t *testing.T, pool *pgxpool.Pool, key, value string, expiresAt *time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO auth.cache (key, value, expires_at) VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET value = $2, expires_at = $3
	`, key, value, expiresAt); err != nil {
		t.Fatalf("seed %q: %v", key, err)
	}
}

// readCacheRow reports the raw row behind a key, expiry included, without the
// expires_at filter every read path applies. Tests need to distinguish "the
// guard is gone" from "the guard is present but expired".
func readCacheRow(t *testing.T, pool *pgxpool.Pool, key string) (value string, expiresAt *time.Time, found bool) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT value, expires_at FROM auth.cache WHERE key = $1`, key).Scan(&value, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, false
		}
		t.Fatalf("read %q: %v", key, err)
	}
	return value, expiresAt, true
}

// An expired guard key must be takeable again. Every caller of SetIfNotExists
// treats false as "someone else already holds this", so a backend that refuses
// an expired key refuses work that is legitimately due: clearLockout's
// lock_notify: key is re-taken once each lockout window to send the "account
// locked" mail, and import_claim_sent: is re-taken once the claim window
// lapses. A false there is a security mail that is silently never sent, and on
// the guard paths (challenge_used:, totp_used:, dpop_jti:) it is a valid
// request rejected as a replay.
func TestAnExpiredGuardKeyIsTakeableAgainOnThePostgresBackend(t *testing.T) {
	c, pool := newPostgresCacheOnRealServer(t)
	ctx := context.Background()
	key := "lock_notify:expired"

	past := time.Now().Add(-time.Hour)
	seedCacheRow(t, pool, key, "old", &past)

	took, err := c.SetIfNotExists(ctx, key, "new", time.Minute)
	if err != nil {
		t.Fatalf("SetIfNotExists: %v", err)
	}
	if !took {
		t.Fatal("SetIfNotExists refused a key whose guard expired an hour ago; the caller is told the key is still held and skips work that is due")
	}

	value, expiresAt, found := readCacheRow(t, pool, key)
	if !found {
		t.Fatal("SetIfNotExists reported it took the key but left no row; the guard it claims to hold does not exist")
	}
	if value != "new" {
		t.Errorf("guard row holds %q, want %q; the caller was told it took the key", value, "new")
	}
	if expiresAt == nil || !expiresAt.After(time.Now()) {
		t.Errorf("guard row expires at %v, want a future instant; an already-expired guard protects nothing", expiresAt)
	}
}

// A live guard key must not be takeable, and the refusal must leave the guard
// standing. This is the single-use property itself: two concurrent TOTP verifies
// of the same code, two presentations of one DPoP proof, or two redemptions of
// one 2fa_challenge token must produce exactly one winner. A true here is a
// replay accepted.
func TestALiveGuardKeyIsRefusedAndLeftIntactOnThePostgresBackend(t *testing.T) {
	c, pool := newPostgresCacheOnRealServer(t)
	ctx := context.Background()
	key := "totp_used:live"

	future := time.Now().Add(time.Hour)
	seedCacheRow(t, pool, key, "held", &future)

	took, err := c.SetIfNotExists(ctx, key, "stolen", time.Minute)
	if err != nil {
		t.Fatalf("SetIfNotExists: %v", err)
	}
	if took {
		t.Fatal("SetIfNotExists took a key that is still held; a replayed TOTP code or DPoP proof would be accepted as fresh")
	}

	value, expiresAt, found := readCacheRow(t, pool, key)
	if !found {
		t.Fatal("SetIfNotExists deleted a live guard row while refusing it; the next replay of the same code finds the key free and succeeds")
	}
	if value != "held" {
		t.Errorf("guard row holds %q, want %q; a refused call must not overwrite the winner's value", value, "held")
	}
	if expiresAt == nil || !expiresAt.After(time.Now().Add(30*time.Minute)) {
		t.Errorf("guard row expires at %v, want the original hour-long window; a refused call must not extend or shorten the holder's guard", expiresAt)
	}
}

// A guard key stored without a TTL never expires, so it must never be takeable.
// Set is called with ttl <= 0 in several places and writes expires_at NULL;
// SetIfNotExists must read NULL as "held forever" rather than as "no expiry
// recorded, therefore free".
func TestAGuardKeyWithNoExpiryIsNeverTakeableOnThePostgresBackend(t *testing.T) {
	c, pool := newPostgresCacheOnRealServer(t)
	ctx := context.Background()
	key := "challenge_used:permanent"

	seedCacheRow(t, pool, key, "held", nil)

	took, err := c.SetIfNotExists(ctx, key, "stolen", time.Minute)
	if err != nil {
		t.Fatalf("SetIfNotExists: %v", err)
	}
	if took {
		t.Fatal("SetIfNotExists took a key stored with no expiry; a permanent single-use marker would be reusable")
	}

	value, expiresAt, found := readCacheRow(t, pool, key)
	if !found {
		t.Fatal("SetIfNotExists deleted a guard row that never expires")
	}
	if value != "held" || expiresAt != nil {
		t.Errorf("guard row is now (%q, %v), want (%q, NULL); a refused call must leave a permanent guard permanent", value, expiresAt, "held")
	}
}

// A key nobody holds must be takeable, and exactly once. The second caller in a
// race has to lose, or the single-use guarantee behind OTP redemption and OAuth
// state consumption is not a guarantee.
func TestAFreeKeyIsTakenExactlyOnceOnThePostgresBackend(t *testing.T) {
	c, pool := newPostgresCacheOnRealServer(t)
	ctx := context.Background()
	key := "dpop_jti:free"

	if _, err := pool.Exec(ctx, `DELETE FROM auth.cache WHERE key = $1`, key); err != nil {
		t.Fatalf("clear %q: %v", key, err)
	}

	took, err := c.SetIfNotExists(ctx, key, "first", time.Minute)
	if err != nil {
		t.Fatalf("first SetIfNotExists: %v", err)
	}
	if !took {
		t.Fatal("SetIfNotExists refused a key that does not exist; every guarded operation would be rejected as a replay of itself")
	}

	took, err = c.SetIfNotExists(ctx, key, "second", time.Minute)
	if err != nil {
		t.Fatalf("second SetIfNotExists: %v", err)
	}
	if took {
		t.Fatal("SetIfNotExists handed the same key to a second caller; the DPoP proof it guards would be replayable")
	}

	value, _, found := readCacheRow(t, pool, key)
	if !found || value != "first" {
		t.Errorf("guard row holds (%q, found=%v), want %q; the winner's value must survive the loser's call", value, found, "first")
	}
}

// Reclaiming an expired key must still hand it to exactly one caller. This is
// the case the whole atomic-statement design exists for: an expired
// challenge_used: or totp_used: guard is precisely when two racing requests are
// both eligible to take it, and a second winner there is a replay accepted. The
// losers must also see no error, or a fail-closed caller turns a lost race into
// a 503.
func TestOnlyOneConcurrentCallerReclaimsAnExpiredKeyOnThePostgresBackend(t *testing.T) {
	c, pool := newPostgresCacheOnRealServer(t)
	ctx := context.Background()
	key := "challenge_used:contended"

	past := time.Now().Add(-time.Hour)
	seedCacheRow(t, pool, key, "old", &past)

	const callers = 16
	var wg sync.WaitGroup
	results := make([]bool, callers)
	errs := make([]error, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = c.SetIfNotExists(ctx, key, strconv.Itoa(i), time.Minute)
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for i := range results {
		if errs[i] != nil {
			t.Errorf("caller %d: %v; a lost race must not surface as an error, a fail-closed caller answers 503", i, errs[i])
		}
		if results[i] {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("%d of %d concurrent callers were told they took the expired key, want exactly 1; every extra winner is a replayed challenge token accepted", winners, callers)
	}

	value, expiresAt, found := readCacheRow(t, pool, key)
	if !found {
		t.Fatal("no guard row survived the race; the key the winner believes it holds is free")
	}
	if value == "old" {
		t.Error("the guard row still holds the expired value; the winner's write was lost")
	}
	if expiresAt == nil || !expiresAt.After(time.Now()) {
		t.Errorf("guard row expires at %v, want a future instant", expiresAt)
	}
}

// The counter must keep counting past the signed 32-bit limit. The memory and
// Redis backends count in int64 and the Cache interface returns int64, so a
// Postgres backend that overflowed at 2^31 would not merely lose precision: the
// query errors, Increment returns (0, err), and every rate limiter on it either
// fails closed and starts refusing traffic or, where the counter is best-effort,
// stops counting the account lockout entirely.
func TestThePostgresCounterKeepsCountingPastTheSignedThirtyTwoBitLimit(t *testing.T) {
	c, pool := newPostgresCacheOnRealServer(t)
	ctx := context.Background()
	key := "rl:ip:overflow"

	future := time.Now().Add(time.Hour)
	seedCacheRow(t, pool, key, "2147483647", &future)

	count, err := c.Increment(ctx, key, time.Minute)
	if err != nil {
		t.Fatalf("Increment past the 32-bit limit: %v", err)
	}
	if count != 2147483648 {
		t.Errorf("Increment returned %d, want 2147483648; the other two backends count in int64 and callers compare against an int64 limit", count)
	}
}
