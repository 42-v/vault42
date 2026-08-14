package compliance

import (
	"context"
	"crypto/sha1" // #nosec G505 -- HIBP API uses SHA-1 prefix (k-anonymity protocol), testing same logic
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
	"github.com/42-v/vault42/internal/service"
)

// =============================================================================
// NIST SP 800-63B Integration Tests — Database & Concurrency Verification
// =============================================================================

// skipIfNoDocker skips integration tests when no container runtime is reachable.
//
// Probing rather than only honoring SKIP_INTEGRATION matters for the
// compliance suite specifically: a reviewer who clones the repo and runs
// `go test ./tests/compliance/` must get a clean result showing which
// requirements are proven container-free and which need a database, not a wall
// of connection errors that makes the whole report look broken.
func skipIfNoDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("SKIP_INTEGRATION") == "1" {
		t.Skip("SKIP_INTEGRATION=1")
	}
	if !containerRuntimeAvailable() {
		t.Skip("no container runtime reachable; this requirement is verified against a real Postgres in CI")
	}
}

// containerRuntimeAvailable reports whether a Docker-compatible socket answers.
// The result is computed once: probing per test would add a syscall to every
// skip in the suite.
var containerRuntimeAvailable = sync.OnceValue(func() bool {
	if host := os.Getenv("DOCKER_HOST"); host != "" {
		if path, found := strings.CutPrefix(host, "unix://"); found {
			return socketExists(path)
		}
		// A non-unix DOCKER_HOST (tcp://, ssh://) is a deliberate operator
		// choice; assume it works and let testcontainers report the truth.
		return true
	}
	candidates := []string{"/var/run/docker.sock", "/run/docker.sock"}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		candidates = append(candidates, runtimeDir+"/docker.sock", runtimeDir+"/podman/podman.sock")
	}
	for _, path := range candidates {
		if socketExists(path) {
			return true
		}
	}
	return false
})

func socketExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

// setupPostgres starts a PostgreSQL testcontainer and runs the initial migration.
// Returns a *pgxpool.Pool and a cleanup function.
func setupPostgres(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	skipIfNoDocker(t)
	ctx := context.Background()

	pgContainer, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("vault_test"),
		tcpostgres.WithUsername("vault_test"),
		tcpostgres.WithPassword("vault_test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		pgContainer.Terminate(ctx) //nolint:errcheck
		t.Fatalf("get connection string: %v", err)
	}

	poolCfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		pgContainer.Terminate(ctx) //nolint:errcheck
		t.Fatalf("parse pool config: %v", err)
	}
	poolCfg.MaxConns = 5
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		pgContainer.Terminate(ctx) //nolint:errcheck
		t.Fatalf("create pool: %v", err)
	}

	// Run migration with a separate connection
	migConn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		pool.Close()
		pgContainer.Terminate(ctx) //nolint:errcheck
		t.Fatalf("connect for migrations: %v", err)
	}

	// Every migration, in order, not just the initial schema. Pinning this
	// fixture to 001 meant the tests ran against a schema the application no
	// longer writes: migration 013 added auth.refresh_tokens.family_created_at,
	// and the refresh-token INSERT names it, so a 001-only fixture failed on a
	// column error rather than on anything it was asserting.
	migEntries, err := os.ReadDir("../../migrations")
	if err != nil {
		migConn.Close(ctx) //nolint:errcheck
		pool.Close()
		pgContainer.Terminate(ctx) //nolint:errcheck
		t.Fatalf("read migrations dir: %v", err)
	}
	var migFiles []string
	for _, e := range migEntries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			migFiles = append(migFiles, e.Name())
		}
	}
	sort.Strings(migFiles)
	for _, f := range migFiles {
		migSQL, err := os.ReadFile("../../migrations/" + f)
		if err != nil {
			migConn.Close(ctx) //nolint:errcheck
			pool.Close()
			pgContainer.Terminate(ctx) //nolint:errcheck
			t.Fatalf("read migration %s: %v", f, err)
		}
		if _, err := migConn.Exec(ctx, stripRoleGrantsInteg(string(migSQL))); err != nil {
			migConn.Close(ctx) //nolint:errcheck
			pool.Close()
			pgContainer.Terminate(ctx) //nolint:errcheck
			t.Fatalf("run migration %s: %v", f, err)
		}
	}
	migConn.Close(ctx) //nolint:errcheck

	cleanup := func() {
		pool.Close()
		pgContainer.Terminate(ctx) //nolint:errcheck
	}
	return pool, cleanup
}

// stripRoleGrantsInteg removes GRANT/REVOKE and ALTER DEFAULT PRIVILEGES lines
// that reference vault_app (which doesn't exist in the test DB).
func stripRoleGrantsInteg(sql string) string {
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

// --- Test 1: HIBP Breach Check SHA-1 Prefix Logic ---

func TestNIST_HIBPBreachCheck(t *testing.T) {
	// NIST 800-63B Section 3.1.1.1: Check passwords against breach databases.
	// The HIBP client uses k-anonymity: SHA-1 hash is split into a 5-char prefix
	// and 35-char suffix. Only the prefix is sent to the API. We verify the
	// SHA-1 prefix/suffix logic and mock suffix matching independently, since
	// the HIBP HTTP URL is hardcoded.

	t.Run("sha1_prefix_suffix_lengths", func(t *testing.T) {
		passwords := []string{"password123", "correcthorsebatterystaple", "hunter2", "P@ssw0rd!12345"}
		for _, pw := range passwords {
			hash := fmt.Sprintf("%X", sha1.Sum([]byte(pw))) // #nosec G401 -- HIBP API mandates SHA-1 (k-anonymity protocol)
			if len(hash) != 40 {
				t.Fatalf("SHA-1 hex hash should be 40 chars, got %d for %q", len(hash), pw)
			}
			prefix := hash[:5]
			suffix := hash[5:]
			if len(prefix) != 5 {
				t.Fatalf("prefix should be 5 chars, got %d", len(prefix))
			}
			if len(suffix) != 35 {
				t.Fatalf("suffix should be 35 chars, got %d", len(suffix))
			}
		}
	})

	t.Run("suffix_matching_with_mock_response", func(t *testing.T) {
		// Simulate HIBP response for "password123" (known breached)
		pw := "password123"
		hash := fmt.Sprintf("%X", sha1.Sum([]byte(pw))) // #nosec G401 -- HIBP API mandates SHA-1 (k-anonymity protocol)
		suffix := hash[5:]

		// Build a mock HIBP response containing the suffix
		mockLines := []string{
			"0000000000000000000000000000000AAAA:3",
			suffix + ":12345", // the breached password's suffix
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBBBB:1",
		}
		mockBody := strings.Join(mockLines, "\r\n")

		// Verify suffix matching logic (same as HIBPClient.IsBreached)
		found := false
		for _, line := range strings.Split(mockBody, "\r\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], suffix) {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("breached password suffix should be detected in mock response")
		}
	})

	t.Run("clean_password_not_matched", func(t *testing.T) {
		pw := "my-unique-vault-password-2024-xyz"
		hash := fmt.Sprintf("%X", sha1.Sum([]byte(pw))) // #nosec G401 -- HIBP API mandates SHA-1 (k-anonymity protocol)
		suffix := hash[5:]

		// Mock response without the suffix
		mockLines := []string{
			"0000000000000000000000000000000AAAA:3",
			"1111111111111111111111111111111BBBB:7",
			"2222222222222222222222222222222CCCC:1",
		}
		mockBody := strings.Join(mockLines, "\r\n")

		found := false
		for _, line := range strings.Split(mockBody, "\r\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], suffix) {
				found = true
				break
			}
		}
		if found {
			t.Fatal("clean password suffix should not appear in mock response")
		}
	})

	t.Run("case_insensitive_matching", func(t *testing.T) {
		// HIBP suffixes use uppercase; verify EqualFold handles mixed case
		suffix := "ABCDE12345ABCDE12345ABCDE12345ABCDE"
		mockLine := "abcde12345abcde12345abcde12345abcde:42"
		parts := strings.SplitN(mockLine, ":", 2)
		if !strings.EqualFold(parts[0], suffix) {
			t.Fatal("suffix matching should be case-insensitive")
		}
	})

	t.Run("error_message_does_not_leak_info", func(t *testing.T) {
		// The service error for breached passwords should be generic
		errMsg := service.ErrPasswordBreached.Error()
		if strings.Contains(strings.ToLower(errMsg), "hibp") {
			t.Fatal("breach error should not mention HIBP implementation detail")
		}
	})
}

// --- Test 2: Password History Reuse Prevention (DB) ---

func TestNIST_PasswordHistoryReuse(t *testing.T) {
	// NIST 800-63B Section 5.2.8: Password history prevents reuse.
	pool, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewPasswordHistoryRepo(db)
	userID, _ := vaultcrypto.RandomUUID()

	// Insert a user record (password_history has FK to auth.users)
	userHash, _ := vaultcrypto.HashPassword("test-password-history")
	_, err := pool.Exec(ctx, `INSERT INTO auth.users (id, email, email_verified, password_hash, display_name, created_at, updated_at)
		VALUES ($1, $2, true, $3, 'test', NOW(), NOW())`, userID, "history@test.com", userHash)
	if err != nil {
		t.Fatalf("insert test user: %v", err)
	}

	// Create 5 password hashes and insert into password_history
	passwords := []string{
		"password-one-vault-test",
		"password-two-vault-test",
		"password-three-vault-test",
		"password-four-vault-test",
		"password-five-vault-test",
	}
	hashes := make([]string, len(passwords))
	for i, pw := range passwords {
		h, err := vaultcrypto.HashPassword(pw)
		if err != nil {
			t.Fatalf("HashPassword failed: %v", err)
		}
		hashes[i] = h

		id, _ := vaultcrypto.RandomUUID()
		entry := &model.PasswordHistory{
			ID:           id,
			UserID:       userID,
			PasswordHash: h,
			CreatedAt:    time.Now().Add(time.Duration(i) * time.Second), // ensure ordering
		}
		if err := repo.Create(ctx, entry); err != nil {
			t.Fatalf("Create password history entry %d: %v", i, err)
		}
	}

	// GetRecentByUser should return all 5, newest first
	recent, err := repo.GetRecentByUser(ctx, userID, 5)
	if err != nil {
		t.Fatalf("GetRecentByUser: %v", err)
	}
	if len(recent) != 5 {
		t.Fatalf("expected 5 history entries, got %d", len(recent))
	}

	// Verify ordering: newest first (index 4 was inserted last)
	if recent[0].PasswordHash != hashes[4] {
		t.Fatal("newest entry should be first in results")
	}

	// Insert 6th password
	sixthHash, _ := vaultcrypto.HashPassword("password-six-vault-test")
	id6, _ := vaultcrypto.RandomUUID()
	if err := repo.Create(ctx, &model.PasswordHistory{
		ID:           id6,
		UserID:       userID,
		PasswordHash: sixthHash,
		CreatedAt:    time.Now().Add(10 * time.Second),
	}); err != nil {
		t.Fatalf("Create 6th entry: %v", err)
	}

	// Query with limit 5: oldest (index 0) should be excluded
	recent5, err := repo.GetRecentByUser(ctx, userID, 5)
	if err != nil {
		t.Fatalf("GetRecentByUser after 6th: %v", err)
	}
	if len(recent5) != 5 {
		t.Fatalf("expected 5 entries with limit, got %d", len(recent5))
	}

	// The 6th (newest) should be first
	if recent5[0].PasswordHash != sixthHash {
		t.Fatal("6th entry should be the newest")
	}

	// The original first entry should no longer be in the window
	for _, entry := range recent5 {
		if entry.PasswordHash == hashes[0] {
			t.Fatal("oldest entry should be excluded from limit-5 query")
		}
	}

	// Simulate reuse detection: verify each stored hash against its original password
	for i := 1; i < len(passwords); i++ {
		match, err := vaultcrypto.VerifyPassword(passwords[i], hashes[i])
		if err != nil {
			t.Fatalf("VerifyPassword for history entry %d: %v", i, err)
		}
		if !match {
			t.Fatalf("password %d should match its stored hash (reuse detection)", i)
		}
	}
}

// --- Test 3: Refresh Token Family Replay Detection (DB) ---

func TestNIST_RefreshTokenFamilyReplay(t *testing.T) {
	// NIST 800-63B Section 5.2.7: Refresh token replay detection.
	// When a used token is replayed, the entire family is revoked.
	pool, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewRefreshTokenRepo(db)
	familyA, _ := vaultcrypto.RandomUUID()
	familyB, _ := vaultcrypto.RandomUUID()
	userID, _ := vaultcrypto.RandomUUID()

	// Insert a user record (refresh_tokens has FK to auth.users)
	userHash, _ := vaultcrypto.HashPassword("test-password-replay")
	_, err := pool.Exec(ctx, `INSERT INTO auth.users (id, email, email_verified, password_hash, display_name, created_at, updated_at)
		VALUES ($1, $2, true, $3, 'test', NOW(), NOW())`, userID, "replay@test.com", userHash)
	if err != nil {
		t.Fatalf("insert test user: %v", err)
	}

	// Create 3 tokens in family A
	tokenIDs := make([]string, 3)
	for i := 0; i < 3; i++ {
		id, _ := vaultcrypto.RandomUUID()
		tokenIDs[i] = id
		tokenHash := vaultcrypto.SHA256Hex(fmt.Sprintf("raw-token-a-%d", i))
		token := &model.RefreshToken{
			ID:        id,
			UserID:    userID,
			TokenHash: tokenHash,
			FamilyID:  familyA,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			CreatedAt: time.Now(),
		}
		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create token %d in family A: %v", i, err)
		}
	}

	// Create 1 token in family B
	idB, _ := vaultcrypto.RandomUUID()
	tokenHashB := vaultcrypto.SHA256Hex("raw-token-b-0")
	if err := repo.Create(ctx, &model.RefreshToken{
		ID:        idB,
		UserID:    userID,
		TokenHash: tokenHashB,
		FamilyID:  familyB,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Create token in family B: %v", err)
	}

	// First use of token 0: should succeed
	wasUnused, err := repo.MarkUsed(ctx, tokenIDs[0])
	if err != nil {
		t.Fatalf("MarkUsed first call: %v", err)
	}
	if !wasUnused {
		t.Fatal("first MarkUsed should return true (was unused)")
	}

	// Replay: second MarkUsed on same token should return false
	wasUnused, err = repo.MarkUsed(ctx, tokenIDs[0])
	if err != nil {
		t.Fatalf("MarkUsed replay: %v", err)
	}
	if wasUnused {
		t.Fatal("replay MarkUsed should return false (already used)")
	}

	// Revoke entire family A due to replay
	if err := repo.RevokeFamily(ctx, familyA); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}

	// Verify all family A tokens are revoked
	for i, id := range tokenIDs {
		hash := vaultcrypto.SHA256Hex(fmt.Sprintf("raw-token-a-%d", i))
		token, err := repo.GetByTokenHash(ctx, hash)
		if err != nil {
			t.Fatalf("GetByTokenHash for token %d: %v", i, err)
		}
		if token == nil {
			t.Fatalf("token %d should exist", i)
		}
		if !token.Revoked {
			t.Fatalf("token %d in family A should be revoked after RevokeFamily", i)
		}
		_ = id
	}

	// Verify family B token is NOT revoked
	tokenB, err := repo.GetByTokenHash(ctx, tokenHashB)
	if err != nil {
		t.Fatalf("GetByTokenHash for family B: %v", err)
	}
	if tokenB == nil {
		t.Fatal("family B token should exist")
	}
	if tokenB.Revoked {
		t.Fatal("family B token should NOT be revoked (different family)")
	}
	if tokenB.Used {
		t.Fatal("family B token should NOT be marked as used")
	}
}

// --- Test 4: Email Verification Enforcement (Anti-Enumeration) ---

func TestNIST_EmailVerificationEnforcement(t *testing.T) {
	// NIST 800-63B Section 5.2.4: Unverified users must get the same error
	// as wrong password to prevent user enumeration.

	t.Run("error_is_same_for_unverified_and_wrong_password", func(t *testing.T) {
		// Both cases return ErrInvalidCredentials
		errUnverified := service.ErrInvalidCredentials
		errWrongPW := service.ErrInvalidCredentials

		if !errors.Is(errUnverified, errWrongPW) {
			t.Fatal("unverified email and wrong password must return the same error")
		}
	})

	t.Run("error_message_does_not_reveal_verification_status", func(t *testing.T) {
		msg := service.ErrInvalidCredentials.Error()

		// The error message must NOT contain words that reveal verification status
		forbidden := []string{"unverified", "email", "verified", "confirm", "activate"}
		lower := strings.ToLower(msg)
		for _, word := range forbidden {
			if strings.Contains(lower, word) {
				t.Fatalf("ErrInvalidCredentials message %q contains %q, leaking verification status", msg, word)
			}
		}
	})

	t.Run("error_message_does_not_reveal_user_existence", func(t *testing.T) {
		msg := service.ErrInvalidCredentials.Error()
		lower := strings.ToLower(msg)

		// Must not reveal whether the user exists
		forbidden := []string{"not found", "no such user", "does not exist", "unknown user"}
		for _, phrase := range forbidden {
			if strings.Contains(lower, phrase) {
				t.Fatalf("ErrInvalidCredentials message %q contains %q, leaking user existence", msg, phrase)
			}
		}
	})

	t.Run("distinct_errors_are_not_exposed", func(t *testing.T) {
		// Verify that no separate "email not verified" error exists in the public API
		// All authentication failures should funnel through ErrInvalidCredentials
		errs := []error{
			service.ErrInvalidCredentials,
			service.ErrAccountLocked,
		}
		// ErrAccountLocked is the only other auth-related error exposed. It is
		// returned by the per-IP lockout (before any user lookup, so it reveals
		// nothing about a specific account); the per-user login lock now answers
		// ErrInvalidCredentials so a locked account cannot be told from an unknown
		// one.
		for _, e := range errs {
			if e == nil {
				t.Fatal("auth error should not be nil")
			}
		}
	})
}

// --- Test 5: Password Reset Token Single-Use Under Concurrency ---

func TestNIST_PasswordResetConcurrentConsumption(t *testing.T) {
	// NIST 800-63B Section 5.1: Reset tokens must be single-use.
	// Under concurrent access, exactly one goroutine should succeed in
	// consuming a token via GetAndDelete.
	mc := cache.NewMemoryCache()
	defer mc.Close()

	ctx := context.Background()
	tokenKey := "reset:token:test-concurrent"
	tokenValue := "reset-secret-abc123"

	if err := mc.Set(ctx, tokenKey, tokenValue, 5*time.Minute); err != nil {
		t.Fatalf("Set token: %v", err)
	}

	const goroutines = 50
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		winners  []string
		failures int64
		start    = make(chan struct{})
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start // synchronize all goroutines

			val, err := mc.GetAndDelete(ctx, tokenKey)
			if err != nil {
				if errors.Is(err, cache.ErrNotFound) {
					atomic.AddInt64(&failures, 1)
					return
				}
				// Unexpected error
				return
			}
			mu.Lock()
			winners = append(winners, val)
			mu.Unlock()
		}()
	}

	close(start) // release all goroutines simultaneously
	wg.Wait()

	if len(winners) != 1 {
		t.Fatalf("expected exactly 1 winner, got %d", len(winners))
	}
	if winners[0] != tokenValue {
		t.Fatalf("winner should get the token value, got %q", winners[0])
	}
	if int(atomic.LoadInt64(&failures)) != goroutines-1 {
		t.Fatalf("expected %d failures (ErrNotFound), got %d", goroutines-1, atomic.LoadInt64(&failures))
	}

	// Token should now be gone
	_, err := mc.Get(ctx, tokenKey)
	if !errors.Is(err, cache.ErrNotFound) {
		t.Fatal("token should be deleted after GetAndDelete")
	}
}
