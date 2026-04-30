package seed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// Compile-time interface checks.
var (
	_ repository.UserRepository   = (*mockUserRepo)(nil)
	_ repository.ClientRepository = (*mockClientRepo)(nil)
)

// ---------------------------------------------------------------------------
// Minimal mock repos — only methods used by seed
// ---------------------------------------------------------------------------

type mockUserRepo struct {
	users   map[string]*model.User
	created []*model.User
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: make(map[string]*model.User)}
}

func (m *mockUserRepo) Create(_ context.Context, u *model.User) error {
	m.created = append(m.created, u)
	m.users[u.Email] = u
	return nil
}

func (m *mockUserRepo) GetByEmail(_ context.Context, email string) (*model.User, error) {
	return m.users[email], nil
}

func (m *mockUserRepo) GetByID(context.Context, string) (*model.User, error)     { return nil, nil }
func (m *mockUserRepo) Update(context.Context, *model.User) error                { return nil }
func (m *mockUserRepo) UpdatePassword(context.Context, string, string) error     { return nil }
func (m *mockUserRepo) IncrementFailedLogin(context.Context, string) error       { return nil }
func (m *mockUserRepo) ResetFailedLogin(context.Context, string) error           { return nil }
func (m *mockUserRepo) LockUntil(_ context.Context, _ string, _ time.Time) error { return nil }
func (m *mockUserRepo) Unlock(context.Context, string) error                     { return nil }
func (m *mockUserRepo) VerifyEmail(context.Context, string) error                { return nil }

type mockClientRepo struct {
	clients map[string]*model.Client
	created []*model.Client
}

func newMockClientRepo() *mockClientRepo {
	return &mockClientRepo{clients: make(map[string]*model.Client)}
}

func (m *mockClientRepo) Create(_ context.Context, c *model.Client) error {
	m.created = append(m.created, c)
	m.clients[c.Name] = c
	return nil
}

func (m *mockClientRepo) GetByName(_ context.Context, name string) (*model.Client, error) {
	return m.clients[name], nil
}

func (m *mockClientRepo) GetByID(context.Context, string) (*model.Client, error) { return nil, nil }
func (m *mockClientRepo) List(context.Context) ([]*model.Client, error)          { return nil, nil }
func (m *mockClientRepo) Update(context.Context, *model.Client) error            { return nil }
func (m *mockClientRepo) Deactivate(context.Context, string) error               { return nil }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestLoad_Valid(t *testing.T) {
	data := `{
		"clients": [
			{"name": "web", "role": "frontend", "scopes": ["user:read"]}
		],
		"users": [
			{"email": "a@b.com", "password": "TestPassword12345!"}
		]
	}`

	path := writeTemp(t, data)
	sf, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(sf.Clients) != 1 || sf.Clients[0].Name != "web" {
		t.Fatalf("unexpected clients: %+v", sf.Clients)
	}
	if len(sf.Users) != 1 || sf.Users[0].Email != "a@b.com" {
		t.Fatalf("unexpected users: %+v", sf.Users)
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	path := writeTemp(t, `{not json}`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidate_ClientNameRequired(t *testing.T) {
	sf := &SeedFile{Clients: []ClientSeed{{Role: "frontend"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for empty client name")
	}
}

func TestValidate_ClientRoleRequired(t *testing.T) {
	sf := &SeedFile{Clients: []ClientSeed{{Name: "web"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for empty client role")
	}
}

func TestValidate_DuplicateClientName(t *testing.T) {
	sf := &SeedFile{Clients: []ClientSeed{
		{Name: "web", Role: "frontend"},
		{Name: "web", Role: "service"},
	}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for duplicate client name")
	}
}

func TestValidate_UserEmailRequired(t *testing.T) {
	sf := &SeedFile{Users: []UserSeed{{Password: "TestPassword12345!"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for empty user email")
	}
}

func TestValidate_UserEmailInvalid(t *testing.T) {
	sf := &SeedFile{Users: []UserSeed{{Email: "notanemail", Password: "TestPassword12345!"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for invalid email")
	}
}

func TestValidate_UserPasswordRequired(t *testing.T) {
	sf := &SeedFile{Users: []UserSeed{{Email: "a@b.com"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestValidate_UserPasswordTooShort(t *testing.T) {
	sf := &SeedFile{Users: []UserSeed{{Email: "a@b.com", Password: "short"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for short password")
	}
}

func TestValidate_DuplicateEmail(t *testing.T) {
	sf := &SeedFile{Users: []UserSeed{
		{Email: "a@b.com", Password: "TestPassword12345!"},
		{Email: "a@b.com", Password: "AnotherPassword12345!"},
	}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for duplicate email")
	}
}

func TestRun_NewClients(t *testing.T) {
	clients := newMockClientRepo()
	users := newMockUserRepo()

	sf := &SeedFile{
		Clients: []ClientSeed{
			{Name: "web", Role: "frontend", Scopes: []string{"user:read"}},
			{Name: "api", Role: "service", Scopes: []string{"user:read", "audit:read"}},
		},
	}

	err := Run(context.Background(), sf, Deps{Users: users, Clients: clients})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(clients.created) != 2 {
		t.Fatalf("expected 2 clients created, got %d", len(clients.created))
	}
	if clients.created[0].Name != "web" || clients.created[0].Role != "frontend" {
		t.Fatalf("unexpected client[0]: %+v", clients.created[0])
	}
	if !clients.created[0].Active {
		t.Fatal("client should be active")
	}
}

func TestRun_ExistingClient(t *testing.T) {
	clients := newMockClientRepo()
	clients.clients["web"] = &model.Client{ID: "existing-id", Name: "web"}

	sf := &SeedFile{
		Clients: []ClientSeed{{Name: "web", Role: "frontend"}},
	}

	err := Run(context.Background(), sf, Deps{Users: newMockUserRepo(), Clients: clients})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(clients.created) != 0 {
		t.Fatalf("expected 0 clients created (skip existing), got %d", len(clients.created))
	}
}

func TestRun_NewUsers(t *testing.T) {
	users := newMockUserRepo()

	sf := &SeedFile{
		Users: []UserSeed{
			{Email: "dev@test.com", Password: "TestPassword12345!", DisplayName: "Dev", Locale: "sk"},
		},
	}

	err := Run(context.Background(), sf, Deps{Users: users, Clients: newMockClientRepo()})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(users.created) != 1 {
		t.Fatalf("expected 1 user created, got %d", len(users.created))
	}
	u := users.created[0]
	if u.Email != "dev@test.com" {
		t.Fatalf("unexpected email: %s", u.Email)
	}
	if u.Locale != "sk" {
		t.Fatalf("expected locale 'sk', got %q", u.Locale)
	}
	if !u.EmailVerified {
		t.Fatal("email should be verified by default")
	}
	if u.PasswordHash == "" {
		t.Fatal("password hash should be set")
	}
}

func TestRun_ExistingUser(t *testing.T) {
	users := newMockUserRepo()
	users.users["dev@test.com"] = &model.User{ID: "existing-id", Email: "dev@test.com"}

	sf := &SeedFile{
		Users: []UserSeed{{Email: "dev@test.com", Password: "TestPassword12345!"}},
	}

	err := Run(context.Background(), sf, Deps{Users: users, Clients: newMockClientRepo()})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(users.created) != 0 {
		t.Fatalf("expected 0 users created (skip existing), got %d", len(users.created))
	}
}

func TestRun_UserDefaultLocale(t *testing.T) {
	users := newMockUserRepo()

	sf := &SeedFile{
		Users: []UserSeed{{Email: "a@b.com", Password: "TestPassword12345!"}},
	}

	err := Run(context.Background(), sf, Deps{Users: users, Clients: newMockClientRepo()})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if users.created[0].Locale != "en" {
		t.Fatalf("expected default locale 'en', got %q", users.created[0].Locale)
	}
}

func TestRun_UserEmailVerifiedExplicitFalse(t *testing.T) {
	users := newMockUserRepo()

	f := false
	sf := &SeedFile{
		Users: []UserSeed{{Email: "a@b.com", Password: "TestPassword12345!", EmailVerified: &f}},
	}

	err := Run(context.Background(), sf, Deps{Users: users, Clients: newMockClientRepo()})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if users.created[0].EmailVerified {
		t.Fatal("email should NOT be verified when explicitly set to false")
	}
}

// A-1: pepper is threaded through user seeding when Deps.Pepper is set.
// A seeded user's PasswordHash must verify with the pepper and FAIL to verify
// without it — proving the HMAC-pre-hash barrier is being applied at seed time.
func TestRun_UserPasswordPeppered(t *testing.T) {
	users := newMockUserRepo()
	const pepper = "audit-2026-04-25-test-pepper"
	const password = "TestPassword12345!"

	sf := &SeedFile{
		Users: []UserSeed{{Email: "peppered@test.com", Password: password, DisplayName: "P"}},
	}

	err := Run(context.Background(), sf,
		Deps{Users: users, Clients: newMockClientRepo(), Pepper: pepper})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(users.created) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users.created))
	}
	hash := users.created[0].PasswordHash

	// Login flow uses VerifyPassword with the pepper — must succeed.
	ok, err := vaultcrypto.VerifyPassword(password, hash, pepper)
	if err != nil {
		t.Fatalf("VerifyPassword(with pepper): %v", err)
	}
	if !ok {
		t.Fatal("seeded hash must verify with pepper")
	}

	// Without pepper — must fail (proves pepper was applied at seed time).
	// VerifyPassword returns (false, nil) on a real mismatch.
	ok, err = vaultcrypto.VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword(no pepper): %v", err)
	}
	if ok {
		t.Fatal("seeded hash must NOT verify without pepper — pepper missing from seed flow")
	}
}

// A-1 negative-control: when Deps.Pepper is empty, hashes verify without pepper
// (backward compatibility — an operator who hasn't configured VAULT_PEPPER
// gets the same behavior as before).
func TestRun_UserPasswordNoPepperBackcompat(t *testing.T) {
	users := newMockUserRepo()
	const password = "TestPassword12345!"

	sf := &SeedFile{Users: []UserSeed{{Email: "nopepper@test.com", Password: password}}}
	err := Run(context.Background(), sf,
		Deps{Users: users, Clients: newMockClientRepo()}) // no Pepper
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	hash := users.created[0].PasswordHash

	ok, err := vaultcrypto.VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("hash must verify without pepper when Deps.Pepper is empty")
	}
}

func TestRun_ClientRepoError(t *testing.T) {
	clients := &errorClientRepo{err: errors.New("db down")}

	sf := &SeedFile{
		Clients: []ClientSeed{{Name: "web", Role: "frontend"}},
	}

	err := Run(context.Background(), sf, Deps{Users: newMockUserRepo(), Clients: clients})
	if err == nil {
		t.Fatal("expected error from client repo")
	}
}

// ---------------------------------------------------------------------------
// Error mocks
// ---------------------------------------------------------------------------

type errorClientRepo struct{ err error }

func (m *errorClientRepo) Create(context.Context, *model.Client) error { return m.err }
func (m *errorClientRepo) GetByName(context.Context, string) (*model.Client, error) {
	return nil, m.err
}
func (m *errorClientRepo) GetByID(context.Context, string) (*model.Client, error) { return nil, nil }
func (m *errorClientRepo) List(context.Context) ([]*model.Client, error)          { return nil, nil }
func (m *errorClientRepo) Update(context.Context, *model.Client) error            { return nil }
func (m *errorClientRepo) Deactivate(context.Context, string) error               { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "seed.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
