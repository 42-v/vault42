package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// mockClientRepo implements repository.ClientRepository for tests.
type mockClientRepo struct {
	CreateFn     func(ctx context.Context, client *model.Client) error
	GetByIDFn    func(ctx context.Context, id string) (*model.Client, error)
	GetByNameFn  func(ctx context.Context, name string) (*model.Client, error)
	ListFn       func(ctx context.Context) ([]*model.Client, error)
	UpdateFn     func(ctx context.Context, client *model.Client) error
	DeactivateFn func(ctx context.Context, id string) error
}

func (m *mockClientRepo) Create(ctx context.Context, client *model.Client) error {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, client)
	}
	return nil
}

func (m *mockClientRepo) GetByID(ctx context.Context, id string) (*model.Client, error) {
	if m.GetByIDFn != nil {
		return m.GetByIDFn(ctx, id)
	}
	return nil, nil
}

func (m *mockClientRepo) GetByName(ctx context.Context, name string) (*model.Client, error) {
	if m.GetByNameFn != nil {
		return m.GetByNameFn(ctx, name)
	}
	return nil, nil
}

func (m *mockClientRepo) List(ctx context.Context) ([]*model.Client, error) {
	if m.ListFn != nil {
		return m.ListFn(ctx)
	}
	return nil, nil
}

func (m *mockClientRepo) Update(ctx context.Context, client *model.Client) error {
	if m.UpdateFn != nil {
		return m.UpdateFn(ctx, client)
	}
	return nil
}

func (m *mockClientRepo) Deactivate(ctx context.Context, id string) error {
	if m.DeactivateFn != nil {
		return m.DeactivateFn(ctx, id)
	}
	return nil
}

// mockUserRepo implements repository.UserRepository for tests.
type mockUserRepo struct {
	LockUntilFn func(ctx context.Context, id string, until time.Time) error
	UnlockFn    func(ctx context.Context, id string) error
}

func (m *mockUserRepo) Create(context.Context, *model.User) error               { return nil }
func (m *mockUserRepo) GetByID(context.Context, string) (*model.User, error)    { return nil, nil }
func (m *mockUserRepo) GetByEmail(context.Context, string) (*model.User, error) { return nil, nil }
func (m *mockUserRepo) Update(context.Context, *model.User) error               { return nil }
func (m *mockUserRepo) UpdatePassword(context.Context, string, string) error    { return nil }
func (m *mockUserRepo) IncrementFailedLogin(context.Context, string) error      { return nil }
func (m *mockUserRepo) ResetFailedLogin(context.Context, string) error          { return nil }
func (m *mockUserRepo) VerifyEmail(context.Context, string) error               { return nil }
func (m *mockUserRepo) SetLastLogin(context.Context, string) error              { return nil }
func (m *mockUserRepo) CreateImported(context.Context, *model.User) error       { return nil }
func (m *mockUserRepo) ClearImportPending(context.Context, string) error        { return nil }
func (m *mockUserRepo) SoftDeleteScrub(context.Context, string, string) error   { return nil }
func (m *mockUserRepo) LockUntil(ctx context.Context, id string, until time.Time) error {
	if m.LockUntilFn != nil {
		return m.LockUntilFn(ctx, id, until)
	}
	return nil
}

func (m *mockUserRepo) Unlock(ctx context.Context, id string) error {
	if m.UnlockFn != nil {
		return m.UnlockFn(ctx, id)
	}
	return nil
}

// mockRefreshTokenRepo implements repository.RefreshTokenRepository for tests.
type mockRefreshTokenRepo struct {
	DeleteExpiredFn    func(ctx context.Context) (int64, error)
	RevokeAllForUserFn func(ctx context.Context, userID string) error
	RevokeAllFn        func(ctx context.Context) error
}

func (m *mockRefreshTokenRepo) Create(context.Context, *model.RefreshToken) error { return nil }
func (m *mockRefreshTokenRepo) CreateWithinCap(context.Context, *model.RefreshToken, int) error {
	return nil
}

func (m *mockRefreshTokenRepo) GetByTokenHash(context.Context, string) (*model.RefreshToken, error) {
	return nil, nil
}
func (m *mockRefreshTokenRepo) MarkUsed(context.Context, string) (bool, error) { return true, nil }
func (m *mockRefreshTokenRepo) RevokeByID(context.Context, string) error       { return nil }
func (m *mockRefreshTokenRepo) RevokeByDeviceID(context.Context, string) error { return nil }
func (m *mockRefreshTokenRepo) RevokeFamily(context.Context, string) error     { return nil }
func (m *mockRefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	if m.RevokeAllForUserFn != nil {
		return m.RevokeAllForUserFn(ctx, userID)
	}
	return nil
}

func (m *mockRefreshTokenRepo) DeleteAllForUser(context.Context, string) error { return nil }

func (m *mockRefreshTokenRepo) RevokeAll(ctx context.Context) error {
	if m.RevokeAllFn != nil {
		return m.RevokeAllFn(ctx)
	}
	return nil
}

func (m *mockRefreshTokenRepo) CountActiveFamilies(_ context.Context, _ string) (int, error) {
	return 0, nil
}

func (m *mockRefreshTokenRepo) DeleteExpired(ctx context.Context) (int64, error) {
	if m.DeleteExpiredFn != nil {
		return m.DeleteExpiredFn(ctx)
	}
	return 0, nil
}

// mockAdminConfigRepo implements repository.AdminConfigRepository for tests.
type mockAdminConfigRepo struct {
	ListFn   func(ctx context.Context) (map[string]string, error)
	GetFn    func(ctx context.Context, key string) (string, error)
	SetFn    func(ctx context.Context, key, value string) error
	DeleteFn func(ctx context.Context, key string) error
}

func (m *mockAdminConfigRepo) List(ctx context.Context) (map[string]string, error) {
	if m.ListFn != nil {
		return m.ListFn(ctx)
	}
	return map[string]string{}, nil
}

func (m *mockAdminConfigRepo) Get(ctx context.Context, key string) (string, error) {
	if m.GetFn != nil {
		return m.GetFn(ctx, key)
	}
	return "", nil
}

func (m *mockAdminConfigRepo) Set(ctx context.Context, key, value string) error {
	if m.SetFn != nil {
		return m.SetFn(ctx, key, value)
	}
	return nil
}

func (m *mockAdminConfigRepo) Delete(ctx context.Context, key string) error {
	if m.DeleteFn != nil {
		return m.DeleteFn(ctx, key)
	}
	return nil
}

// mockAuditRepo implements repository.AuditRepository for tests.
type mockAuditRepo struct {
	InsertFn      func(ctx context.Context, entry *model.AuditEntry) error
	InsertBatchFn func(ctx context.Context, entries []*model.AuditEntry) error
	QueryFn       func(ctx context.Context, filter repository.AuditFilter) ([]*model.AuditEntry, error)
	CleanupFn     func(ctx context.Context, olderThan time.Time) (int64, error)
}

func (m *mockAuditRepo) Insert(ctx context.Context, entry *model.AuditEntry) error {
	if m.InsertFn != nil {
		return m.InsertFn(ctx, entry)
	}
	return nil
}

func (m *mockAuditRepo) InsertBatch(ctx context.Context, entries []*model.AuditEntry) error {
	if m.InsertBatchFn != nil {
		return m.InsertBatchFn(ctx, entries)
	}
	return nil
}

func (m *mockAuditRepo) Query(ctx context.Context, filter repository.AuditFilter) ([]*model.AuditEntry, error) {
	if m.QueryFn != nil {
		return m.QueryFn(ctx, filter)
	}
	return nil, nil
}

func (*mockAuditRepo) CountByUser(context.Context, string) (int, error) {
	return 0, nil
}

func (m *mockAuditRepo) Cleanup(ctx context.Context, olderThan time.Time) (int64, error) {
	if m.CleanupFn != nil {
		return m.CleanupFn(ctx, olderThan)
	}
	return 0, nil
}

func (*mockAuditRepo) CleanupLocked(context.Context, time.Time) (int64, bool, error) {
	return 0, true, nil
}

// Compile-time interface checks.
var (
	_ repository.ClientRepository       = (*mockClientRepo)(nil)
	_ repository.UserRepository         = (*mockUserRepo)(nil)
	_ repository.RefreshTokenRepository = (*mockRefreshTokenRepo)(nil)
	_ repository.AdminConfigRepository  = (*mockAdminConfigRepo)(nil)
	_ repository.AuditRepository        = (*mockAuditRepo)(nil)
)

// newTestCLI creates a CLI with default (no-op) mocks.
func newTestCLI() (*CLI, *mockClientRepo, *mockUserRepo, *mockRefreshTokenRepo, *mockAdminConfigRepo) {
	clients := &mockClientRepo{}
	users := &mockUserRepo{}
	tokens := &mockRefreshTokenRepo{}
	admin := &mockAdminConfigRepo{}
	audit := &mockAuditRepo{}
	c := New(clients, users, tokens, admin, audit, "")
	return c, clients, users, tokens, admin
}

// captureStdout captures stdout output during fn execution.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// captureStderr captures stderr output during fn execution.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	fn()

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// hashToken hashes a plaintext token using Argon2id (same as production).
func hashToken(t *testing.T, token string) string {
	t.Helper()
	h, err := vaultcrypto.HashPassword(token)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return h
}

// ---------------------------------------------------------------------------
// TestNew
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	c, _, _, _, _ := newTestCLI()
	if c == nil {
		t.Fatal("New returned nil")
	}
}

func TestNewFieldsSet(t *testing.T) {
	clients := &mockClientRepo{}
	users := &mockUserRepo{}
	tokens := &mockRefreshTokenRepo{}
	admin := &mockAdminConfigRepo{}
	audit := &mockAuditRepo{}
	c := New(clients, users, tokens, admin, audit, "")

	if c.clients != clients {
		t.Error("clients field not set")
	}
	if c.users != users {
		t.Error("users field not set")
	}
	if c.tokens != tokens {
		t.Error("tokens field not set")
	}
	if c.adminConfig != admin {
		t.Error("adminConfig field not set")
	}
	if c.audit != audit {
		t.Error("audit field not set")
	}
}

// ---------------------------------------------------------------------------
// TestGetFlag
// ---------------------------------------------------------------------------

func TestGetFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
		flag string
		want string
	}{
		{"present", []string{"cmd", "--name", "frontend"}, "--name", "frontend"},
		{"missing", []string{"cmd", "--other", "val"}, "--name", ""},
		{"empty args", nil, "--name", ""},
		{"flag at end without value", []string{"cmd", "--name"}, "--name", ""},
		{"multiple flags first", []string{"cmd", "--a", "1", "--b", "2"}, "--a", "1"},
		{"multiple flags second", []string{"cmd", "--a", "1", "--b", "2"}, "--b", "2"},
		{"odd-length args flag missing value", []string{"cmd", "--name"}, "--name", ""},
		{"flag value is another flag", []string{"cmd", "--name", "--role"}, "--name", "--role"},
		{"duplicate flag returns first", []string{"cmd", "--name", "first", "--name", "second"}, "--name", "first"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getFlag(tt.args, tt.flag)
			if got != tt.want {
				t.Errorf("getFlag(%v, %q) = %q, want %q", tt.args, tt.flag, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestVerifyAdminToken
// ---------------------------------------------------------------------------

func TestVerifyAdminToken(t *testing.T) {
	const plainToken = "super-secret-admin-token"

	t.Run("correct token", func(t *testing.T) {
		hash := hashToken(t, plainToken)
		c, _, _, _, admin := newTestCLI()
		admin.GetFn = func(_ context.Context, key string) (string, error) {
			if key == "admin_token_hash" {
				return hash, nil
			}
			return "", nil
		}
		if !c.verifyAdminToken(context.Background(), plainToken) {
			t.Error("expected true for correct token")
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		hash := hashToken(t, plainToken)
		c, _, _, _, admin := newTestCLI()
		admin.GetFn = func(_ context.Context, key string) (string, error) {
			return hash, nil
		}
		if c.verifyAdminToken(context.Background(), "wrong-token") {
			t.Error("expected false for wrong token")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		c, _, _, _, _ := newTestCLI()
		if c.verifyAdminToken(context.Background(), "") {
			t.Error("expected false for empty token")
		}
	})

	t.Run("repo error", func(t *testing.T) {
		c, _, _, _, admin := newTestCLI()
		admin.GetFn = func(_ context.Context, _ string) (string, error) {
			return "", fmt.Errorf("db down")
		}
		if c.verifyAdminToken(context.Background(), plainToken) {
			t.Error("expected false when repo returns error")
		}
	})

	t.Run("empty stored hash", func(t *testing.T) {
		c, _, _, _, admin := newTestCLI()
		admin.GetFn = func(_ context.Context, _ string) (string, error) {
			return "", nil
		}
		if c.verifyAdminToken(context.Background(), plainToken) {
			t.Error("expected false when stored hash is empty")
		}
	})
}

// ---------------------------------------------------------------------------
// TestInitAdminToken
// ---------------------------------------------------------------------------

func TestInitAdminToken(t *testing.T) {
	t.Run("success first boot", func(t *testing.T) {
		sink := firstBootSink(t)
		c, _, _, _, admin := newTestCLI()
		var storedKey, storedValue string
		admin.GetFn = func(_ context.Context, _ string) (string, error) {
			return "", nil // no existing token
		}
		admin.SetFn = func(_ context.Context, key, value string) error {
			storedKey = key
			storedValue = value
			return nil
		}

		out := captureStdout(t, func() {
			if err := c.InitAdminToken(context.Background()); err != nil {
				t.Fatalf("InitAdminToken: %v", err)
			}
		})

		if storedKey != "admin_token_hash" {
			t.Errorf("expected key admin_token_hash, got %q", storedKey)
		}
		if storedValue == "" {
			t.Error("expected non-empty hash to be stored")
		}
		if !strings.Contains(out, "FIRST BOOT") {
			t.Error("expected FIRST BOOT message in output")
		}
		if !strings.Contains(out, sink) {
			t.Error("expected the output to name where the token was delivered")
		}
	})

	t.Run("already initialized", func(t *testing.T) {
		c, _, _, _, admin := newTestCLI()
		admin.GetFn = func(_ context.Context, _ string) (string, error) {
			return "existing-hash-value", nil
		}
		setCalled := false
		admin.SetFn = func(_ context.Context, _, _ string) error {
			setCalled = true
			return nil
		}

		if err := c.InitAdminToken(context.Background()); err != nil {
			t.Fatalf("InitAdminToken: %v", err)
		}
		if setCalled {
			t.Error("Set should not be called when token already exists")
		}
	})

	t.Run("repo Set error", func(t *testing.T) {
		firstBootSink(t)
		c, _, _, _, admin := newTestCLI()
		admin.GetFn = func(_ context.Context, _ string) (string, error) {
			return "", nil
		}
		admin.SetFn = func(_ context.Context, _, _ string) error {
			return errors.New("write failed")
		}

		// Capture stdout to prevent output leaking
		captureStdout(t, func() {
			err := c.InitAdminToken(context.Background())
			if err == nil {
				t.Fatal("expected error from InitAdminToken")
			}
			if !strings.Contains(err.Error(), "write failed") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	})
}

// ---------------------------------------------------------------------------
// helpers for command tests — setup CLI with valid admin token
// ---------------------------------------------------------------------------

// setupAuthenticatedCLI creates a CLI with a known admin token pre-hashed.
// Returns the CLI, mock repos, and the args prefix needed to authenticate.
func setupAuthenticatedCLI(t *testing.T) (*CLI, *mockClientRepo, *mockUserRepo, *mockRefreshTokenRepo, *mockAdminConfigRepo, string) {
	t.Helper()
	const adminToken = "test-admin-token-12345"
	hash := hashToken(t, adminToken)

	c, clients, users, tokens, admin := newTestCLI()
	admin.GetFn = func(_ context.Context, key string) (string, error) {
		if key == "admin_token_hash" {
			return hash, nil
		}
		return "", nil
	}
	return c, clients, users, tokens, admin, adminToken
}

// ---------------------------------------------------------------------------
// TestAddClient
// ---------------------------------------------------------------------------

func TestAddClient(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		firstBootSink(t)
		c, clients, _, _, _, token := setupAuthenticatedCLI(t)
		var created *model.Client
		clients.CreateFn = func(_ context.Context, cl *model.Client) error {
			created = cl
			return nil
		}

		args := []string{"vault", "add-client", "--admin-token", token, "--name", "frontend", "--role", "web", "--scopes", "user:read,user:write"}
		out := captureStdout(t, func() {
			result := c.Run(context.Background(), args)
			if !result {
				t.Error("expected true")
			}
		})

		if created == nil {
			t.Fatal("client was not created")
		}
		if created.Name != "frontend" {
			t.Errorf("name = %q, want %q", created.Name, "frontend")
		}
		if created.Role != "web" {
			t.Errorf("role = %q, want %q", created.Role, "web")
		}
		if len(created.Scopes) != 2 {
			t.Errorf("scopes len = %d, want 2", len(created.Scopes))
		}
		if !created.Active {
			t.Error("expected Active = true")
		}
		if !strings.Contains(out, "Client created:") {
			t.Error("expected 'Client created:' in output")
		}
		if !strings.Contains(out, "Secret written to:") {
			t.Error("expected the output to name where the secret was delivered")
		}
		if strings.Contains(out, "Secret: ") {
			t.Error("the client secret was printed rather than delivered")
		}
	})

	t.Run("missing name flag", func(t *testing.T) {
		c, _, _, _, _, token := setupAuthenticatedCLI(t)
		args := []string{"vault", "add-client", "--admin-token", token, "--role", "web"}
		stderr := captureStderr(t, func() {
			result := c.Run(context.Background(), args)
			if !result {
				t.Error("expected true (usage printed)")
			}
		})
		if !strings.Contains(stderr, "Usage:") {
			t.Error("expected usage message on stderr")
		}
	})

	t.Run("missing role flag", func(t *testing.T) {
		c, _, _, _, _, token := setupAuthenticatedCLI(t)
		args := []string{"vault", "add-client", "--admin-token", token, "--name", "frontend"}
		stderr := captureStderr(t, func() {
			result := c.Run(context.Background(), args)
			if !result {
				t.Error("expected true (usage printed)")
			}
		})
		if !strings.Contains(stderr, "Usage:") {
			t.Error("expected usage message on stderr")
		}
	})

	t.Run("repo create error", func(t *testing.T) {
		// The sink matters: without it the command stops at delivery and never
		// reaches Create, so the assertion below would pass on the wrong error.
		firstBootSink(t)
		c, clients, _, _, _, token := setupAuthenticatedCLI(t)
		clients.CreateFn = func(_ context.Context, _ *model.Client) error {
			return errors.New("duplicate client")
		}

		args := []string{"vault", "add-client", "--admin-token", token, "--name", "frontend", "--role", "web", "--scopes", "user:read"}
		stderr := captureStderr(t, func() {
			captureStdout(t, func() {
				result := c.Run(context.Background(), args)
				if !result {
					t.Error("expected true")
				}
			})
		})
		if !strings.Contains(stderr, "ERROR:") {
			t.Error("expected ERROR on stderr")
		}
	})

	t.Run("empty scopes", func(t *testing.T) {
		firstBootSink(t)
		c, clients, _, _, _, token := setupAuthenticatedCLI(t)
		var created *model.Client
		clients.CreateFn = func(_ context.Context, cl *model.Client) error {
			created = cl
			return nil
		}

		args := []string{"vault", "add-client", "--admin-token", token, "--name", "svc", "--role", "service", "--scopes", ""}
		captureStdout(t, func() {
			c.Run(context.Background(), args)
		})

		if created == nil {
			t.Fatal("client was not created")
		}
		// Empty string split produces [""]
		if len(created.Scopes) != 1 || created.Scopes[0] != "" {
			t.Errorf("scopes = %v, want [\"\"]", created.Scopes)
		}
	})
}

// ---------------------------------------------------------------------------
// TestListClients
// ---------------------------------------------------------------------------

func TestListClients(t *testing.T) {
	t.Run("success with clients", func(t *testing.T) {
		c, clients, _, _, _, token := setupAuthenticatedCLI(t)
		clients.ListFn = func(_ context.Context) ([]*model.Client, error) {
			return []*model.Client{
				{ID: "id-1", Name: "web", Active: true, Scopes: []string{"user:read"}},
				{ID: "id-2", Name: "admin", Active: false, Scopes: []string{"admin:all"}},
			}, nil
		}

		args := []string{"vault", "list-clients", "--admin-token", token}
		out := captureStdout(t, func() {
			result := c.Run(context.Background(), args)
			if !result {
				t.Error("expected true")
			}
		})

		if !strings.Contains(out, "id-1") {
			t.Error("expected id-1 in output")
		}
		if !strings.Contains(out, "web") {
			t.Error("expected web in output")
		}
		if !strings.Contains(out, "active") {
			t.Error("expected 'active' status")
		}
		if !strings.Contains(out, "revoked") {
			t.Error("expected 'revoked' status for inactive client")
		}
	})

	t.Run("empty list", func(t *testing.T) {
		c, clients, _, _, _, token := setupAuthenticatedCLI(t)
		clients.ListFn = func(_ context.Context) ([]*model.Client, error) {
			return nil, nil
		}

		args := []string{"vault", "list-clients", "--admin-token", token}
		out := captureStdout(t, func() {
			result := c.Run(context.Background(), args)
			if !result {
				t.Error("expected true")
			}
		})
		// No client lines printed
		if strings.Contains(out, "id-") {
			t.Error("expected no client output")
		}
	})

	t.Run("repo error", func(t *testing.T) {
		c, clients, _, _, _, token := setupAuthenticatedCLI(t)
		clients.ListFn = func(_ context.Context) ([]*model.Client, error) {
			return nil, errors.New("connection refused")
		}

		args := []string{"vault", "list-clients", "--admin-token", token}
		stderr := captureStderr(t, func() {
			result := c.Run(context.Background(), args)
			if !result {
				t.Error("expected true")
			}
		})
		if !strings.Contains(stderr, "ERROR:") {
			t.Error("expected ERROR on stderr")
		}
	})
}

// ---------------------------------------------------------------------------
// TestRevokeClient
// ---------------------------------------------------------------------------

func TestRevokeClient_RetiredDoesNotWriteAndPointsAtAdminPlane(t *testing.T) {
	c, clients, _, _, _, token := setupAuthenticatedCLI(t)
	called := false
	clients.DeactivateFn = func(_ context.Context, _ string) error {
		called = true
		return nil
	}

	args := []string{"vault", "revoke-client", "--admin-token", token, "--id", "client-123"}
	stderr := captureStderr(t, func() {
		if handled := c.Run(context.Background(), args); !handled {
			t.Error("revoke-client must stay a recognized command so it does not fall through to booting the server")
		}
	})

	if called {
		t.Error("revoke-client issued a vault_app Deactivate write; client revocation must not run from cmd/vault")
	}
	if !strings.Contains(stderr, "/admin/clients") || !strings.Contains(stderr, "revoke") {
		t.Errorf("revoke-client did not point the operator at the admin route: %q", stderr)
	}
}

// ---------------------------------------------------------------------------
// TestRotateClientSecret
// ---------------------------------------------------------------------------

func TestRotateClientSecret_RetiredDoesNotWriteAndPointsAtAdminPlane(t *testing.T) {
	c, clients, _, _, _, token := setupAuthenticatedCLI(t)
	getCalled, updateCalled := false, false
	clients.GetByIDFn = func(_ context.Context, id string) (*model.Client, error) {
		getCalled = true
		return &model.Client{ID: id, Name: "frontend"}, nil
	}
	clients.UpdateFn = func(_ context.Context, _ *model.Client) error {
		updateCalled = true
		return nil
	}

	args := []string{"vault", "rotate-client-secret", "--admin-token", token, "--id", "client-1"}
	stderr := captureStderr(t, func() {
		if handled := c.Run(context.Background(), args); !handled {
			t.Error("rotate-client-secret must stay a recognized command so it does not fall through to booting the server")
		}
	})

	if getCalled || updateCalled {
		t.Error("rotate-client-secret touched the clients repository; secret rotation must not run from cmd/vault")
	}
	if !strings.Contains(stderr, "/admin/clients") || !strings.Contains(stderr, "rotate") {
		t.Errorf("rotate-client-secret did not point the operator at the admin route: %q", stderr)
	}
}

// lock-user and unlock-user are retired (they no longer write via vault_app);
// their contract is pinned in cli_lock_retired_test.go.

// ---------------------------------------------------------------------------
// TestRevokeAllSessions
// ---------------------------------------------------------------------------

func TestRevokeAllSessions(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _, _, tokens, _, token := setupAuthenticatedCLI(t)
		tokens.DeleteExpiredFn = func(_ context.Context) (int64, error) {
			return 5, nil
		}
		tokens.RevokeAllFn = func(_ context.Context) error {
			return nil
		}

		args := []string{"vault", "revoke-all-sessions", "--admin-token", token}
		out := captureStdout(t, func() {
			result := c.Run(context.Background(), args)
			if !result {
				t.Error("expected true")
			}
		})

		if !strings.Contains(out, "Cleaned 5 expired tokens") {
			t.Error("expected cleaned token count in output")
		}
		if !strings.Contains(out, "All sessions revoked") {
			t.Error("expected 'All sessions revoked' in output")
		}
	})

	t.Run("delete expired error", func(t *testing.T) {
		c, _, _, tokens, _, token := setupAuthenticatedCLI(t)
		tokens.DeleteExpiredFn = func(_ context.Context) (int64, error) {
			return 0, errors.New("cleanup failed")
		}
		tokens.RevokeAllFn = func(_ context.Context) error {
			return nil
		}

		args := []string{"vault", "revoke-all-sessions", "--admin-token", token}
		var stdout, stderr string
		stderr = captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				c.Run(context.Background(), args)
			})
		})
		if !strings.Contains(stderr, "ERROR") {
			t.Error("expected error about cleanup failure on stderr")
		}
		// Should still proceed to revoke all
		if !strings.Contains(stdout, "All sessions revoked") {
			t.Error("expected 'All sessions revoked' even after cleanup error")
		}
	})

	t.Run("revoke all error", func(t *testing.T) {
		c, _, _, tokens, _, token := setupAuthenticatedCLI(t)
		tokens.DeleteExpiredFn = func(_ context.Context) (int64, error) {
			return 0, nil
		}
		tokens.RevokeAllFn = func(_ context.Context) error {
			return errors.New("bulk revoke not supported")
		}

		args := []string{"vault", "revoke-all-sessions", "--admin-token", token}
		stderr := captureStderr(t, func() {
			captureStdout(t, func() {
				c.Run(context.Background(), args)
			})
		})
		if !strings.Contains(stderr, "ERROR:") {
			t.Error("expected ERROR on stderr for revoke failure")
		}
	})
}

// ---------------------------------------------------------------------------
// TestRotateAdminToken
// ---------------------------------------------------------------------------

func TestRotateAdminToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		sink := firstBootSink(t)
		c, _, _, _, admin, token := setupAuthenticatedCLI(t)
		var storedHash string
		admin.SetFn = func(_ context.Context, key, value string) error {
			if key == "admin_token_hash" {
				storedHash = value
			}
			return nil
		}

		args := []string{"vault", "rotate-admin-token", "--admin-token", token}
		out := captureStdout(t, func() {
			result := c.Run(context.Background(), args)
			if !result {
				t.Error("expected true")
			}
		})

		if storedHash == "" {
			t.Error("expected new hash to be stored")
		}
		if !strings.Contains(out, sink) {
			t.Error("expected the output to name where the new token was delivered")
		}
	})

	t.Run("repo Set error", func(t *testing.T) {
		c, _, _, _, admin, token := setupAuthenticatedCLI(t)
		admin.SetFn = func(_ context.Context, key, _ string) error {
			if key == "admin_token_hash" {
				return errors.New("disk full")
			}
			return nil
		}

		args := []string{"vault", "rotate-admin-token", "--admin-token", token}
		stderr := captureStderr(t, func() {
			captureStdout(t, func() {
				result := c.Run(context.Background(), args)
				if !result {
					t.Error("expected true")
				}
			})
		})
		if !strings.Contains(stderr, "ERROR:") {
			t.Error("expected ERROR on stderr")
		}
	})
}

// ---------------------------------------------------------------------------
// TestRun
// ---------------------------------------------------------------------------

func TestRun(t *testing.T) {
	t.Run("too few args returns false", func(t *testing.T) {
		c, _, _, _, _ := newTestCLI()
		if c.Run(context.Background(), []string{"vault"}) {
			t.Error("expected false for single arg")
		}
	})

	t.Run("empty args returns false", func(t *testing.T) {
		c, _, _, _, _ := newTestCLI()
		if c.Run(context.Background(), nil) {
			t.Error("expected false for nil args")
		}
	})

	t.Run("unknown command returns false", func(t *testing.T) {
		c, _, _, _, _, token := setupAuthenticatedCLI(t)
		args := []string{"vault", "unknown-command", "--admin-token", token}
		if c.Run(context.Background(), args) {
			t.Error("expected false for unknown command")
		}
	})

	t.Run("routes to list-clients", func(t *testing.T) {
		c, clients, _, _, _, token := setupAuthenticatedCLI(t)
		listCalled := false
		clients.ListFn = func(_ context.Context) ([]*model.Client, error) {
			listCalled = true
			return nil, nil
		}

		args := []string{"vault", "list-clients", "--admin-token", token}
		captureStdout(t, func() {
			c.Run(context.Background(), args)
		})

		if !listCalled {
			t.Error("expected list-clients to be routed")
		}
	})

	t.Run("routes to lock-user", func(t *testing.T) {
		c, _, users, _, _, token := setupAuthenticatedCLI(t)
		lockCalled := false
		users.LockUntilFn = func(_ context.Context, _ string, _ time.Time) error {
			lockCalled = true
			return nil
		}

		// lock-user is retired: dispatch reaches the retirement handler, which
		// prints the admin-route redirect and issues no vault_app write.
		args := []string{"vault", "lock-user", "--admin-token", token, "--id", "u1"}
		stderr := captureStderr(t, func() {
			if !c.Run(context.Background(), args) {
				t.Error("expected lock-user to be routed (handled), not fall through to the server")
			}
		})

		if lockCalled {
			t.Error("retired lock-user must not issue a vault_app LockUntil write")
		}
		if !strings.Contains(stderr, "/admin/users") {
			t.Errorf("expected lock-user to point at the admin route, got %q", stderr)
		}
	})

	t.Run("routes to revoke-all-sessions", func(t *testing.T) {
		c, _, _, tokens, _, token := setupAuthenticatedCLI(t)
		revokeCalled := false
		tokens.RevokeAllFn = func(_ context.Context) error {
			revokeCalled = true
			return nil
		}

		args := []string{"vault", "revoke-all-sessions", "--admin-token", token}
		captureStdout(t, func() {
			c.Run(context.Background(), args)
		})

		if !revokeCalled {
			t.Error("expected revoke-all-sessions to be routed")
		}
	})

	t.Run("routes to seed", func(t *testing.T) {
		c, _, _, _, _, token := setupAuthenticatedCLI(t)
		path := filepath.Join(t.TempDir(), "seed.json")
		if err := os.WriteFile(path, []byte(`{"clients":[],"users":[]}`), 0o600); err != nil {
			t.Fatalf("write seed file: %v", err)
		}

		args := []string{"vault", "seed", "--admin-token", token, "--file", path}
		out := captureStdout(t, func() {
			result := c.Run(context.Background(), args)
			if !result {
				t.Error("expected true")
			}
		})

		if !strings.Contains(out, "Seeding complete.") {
			t.Errorf("expected seed to be routed and complete, got %q", out)
		}
	})

	// cleanup-audit is retired (it no longer deletes via vault_app); its routing
	// and inertness are pinned in cli_cleanup_audit_retired_test.go.

	t.Run("routes to export-audit", func(t *testing.T) {
		c, _, _, _, _, token := setupAuthenticatedCLI(t)
		queryCalled := false
		c.audit.(*mockAuditRepo).QueryFn = func(_ context.Context, _ repository.AuditFilter) ([]*model.AuditEntry, error) {
			queryCalled = true
			return nil, nil
		}

		args := []string{"vault", "export-audit", "--admin-token", token}
		captureStdout(t, func() {
			result := c.Run(context.Background(), args)
			if !result {
				t.Error("expected true")
			}
		})

		if !queryCalled {
			t.Error("expected export-audit to be routed")
		}
	})
}

// ---------------------------------------------------------------------------
// TestRotateJWKS
// ---------------------------------------------------------------------------

func TestRotateJWKS(t *testing.T) {
	// The stdout path is retired. A PKCS#1 private key printed by a rotation Job
	// lands in the pod log next to the tokens it signs, and there is no safe way
	// to print it — only the 0600 file --output already wrote. What used to be
	// asserted about that stdout key is now asserted about the file, one subtest
	// down.
	t.Run("refuses to mint a key it cannot deliver to a file", func(t *testing.T) {
		c, _, _, _, _, token := setupAuthenticatedCLI(t)

		args := []string{"vault", "rotate-jwks", "--admin-token", token}
		var stdout, stderr string
		stderr = captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				if !c.Run(context.Background(), args) {
					t.Error("expected true")
				}
			})
		})

		if strings.Contains(stdout, "PRIVATE KEY") || strings.Contains(stderr, "PRIVATE KEY") {
			t.Errorf("rotate-jwks printed a private key\nstdout: %s\nstderr: %s", stdout, stderr)
		}
		if strings.Contains(stdout, "kid: ") {
			t.Error("a key was minted although there was nowhere to put it")
		}
		if !strings.Contains(stderr, "--output") {
			t.Errorf("stderr does not name the required flag: %q", stderr)
		}
	})

	t.Run("success write to file", func(t *testing.T) {
		c, _, _, _, _, token := setupAuthenticatedCLI(t)

		outFile := filepath.Join(t.TempDir(), "jwks-key.pem")
		args := []string{"vault", "rotate-jwks", "--admin-token", token, "--output", outFile}

		var stdout string
		captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				result := c.Run(context.Background(), args)
				if !result {
					t.Error("expected true")
				}
			})
		})

		// Stdout should have kid and file path, but NOT the PEM
		if !strings.Contains(stdout, "kid: ") {
			t.Error("expected kid in stdout")
		}
		if !strings.Contains(stdout, outFile) {
			t.Error("expected output file path in stdout")
		}
		if strings.Contains(stdout, "-----BEGIN RSA PRIVATE KEY-----") {
			t.Error("PEM should NOT be in stdout when --output is used")
		}

		// Verify file was written with correct permissions and valid content
		data, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}

		block, _ := pem.Decode(data)
		if block == nil {
			t.Fatal("failed to decode PEM from file")
		}
		if block.Type != "RSA PRIVATE KEY" {
			t.Errorf("PEM type = %q, want %q", block.Type, "RSA PRIVATE KEY")
		}

		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse private key from file: %v", err)
		}
		if key.N.BitLen() != 2048 {
			t.Errorf("key size = %d bits, want 2048", key.N.BitLen())
		}

		// Verify file permissions (0600)
		info, err := os.Stat(outFile)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		perm := info.Mode().Perm()
		if perm != 0o600 {
			t.Errorf("file permissions = %o, want 0600", perm)
		}
	})

	t.Run("write to bad path", func(t *testing.T) {
		c, _, _, _, _, token := setupAuthenticatedCLI(t)

		args := []string{"vault", "rotate-jwks", "--admin-token", token, "--output", "/nonexistent/dir/key.pem"}
		stderr := captureStderr(t, func() {
			captureStdout(t, func() {
				result := c.Run(context.Background(), args)
				if !result {
					t.Error("expected true")
				}
			})
		})

		if !strings.Contains(stderr, "ERROR: write key file:") {
			t.Errorf("expected write error on stderr, got: %q", stderr)
		}
	})

	t.Run("unique kid per invocation", func(t *testing.T) {
		c, _, _, _, _, token := setupAuthenticatedCLI(t)
		dir := t.TempDir()

		var kids []string
		for i := 0; i < 3; i++ {
			args := []string{"vault", "rotate-jwks", "--admin-token", token,
				"--output", filepath.Join(dir, fmt.Sprintf("key-%d.pem", i))}
			var stdout string
			captureStderr(t, func() {
				stdout = captureStdout(t, func() {
					c.Run(context.Background(), args)
				})
			})
			for _, line := range strings.Split(stdout, "\n") {
				if strings.HasPrefix(line, "kid: ") {
					kids = append(kids, strings.TrimPrefix(line, "kid: "))
				}
			}
		}

		if len(kids) != 3 {
			t.Fatalf("expected 3 kids, got %d", len(kids))
		}
		// All kids should be unique
		seen := make(map[string]bool)
		for _, k := range kids {
			if seen[k] {
				t.Errorf("duplicate kid: %s", k)
			}
			seen[k] = true
		}
	})

	t.Run("routes via Run", func(t *testing.T) {
		c, _, _, _, _, token := setupAuthenticatedCLI(t)
		args := []string{"vault", "rotate-jwks", "--admin-token", token}

		var handled bool
		captureStderr(t, func() {
			captureStdout(t, func() {
				handled = c.Run(context.Background(), args)
			})
		})
		if !handled {
			t.Error("expected rotate-jwks to be handled by Run")
		}
	})
}
