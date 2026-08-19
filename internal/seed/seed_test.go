package seed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// Compile-time interface checks.
var (
	_ repository.UserRepository      = (*mockUserRepo)(nil)
	_ repository.ClientRepository    = (*mockClientRepo)(nil)
	_ repository.AdminUserRepository = (*mockAdminUserRepo)(nil)
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
func (m *mockUserRepo) SetLastLogin(context.Context, string) error               { return nil }
func (m *mockUserRepo) CreateImported(context.Context, *model.User) error        { return nil }
func (m *mockUserRepo) ClearImportPending(context.Context, string) error         { return nil }
func (m *mockUserRepo) ClearMustResetPassword(context.Context, string) error     { return nil }
func (m *mockUserRepo) SetMustResetPassword(context.Context, string, bool) error { return nil }
func (m *mockUserRepo) SoftDeleteScrub(context.Context, string, string) error    { return nil }

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
	sf := &File{Clients: []ClientSeed{{Role: "frontend"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for empty client name")
	}
}

func TestValidate_ClientRoleRequired(t *testing.T) {
	sf := &File{Clients: []ClientSeed{{Name: "web"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for empty client role")
	}
}

func TestValidate_DuplicateClientName(t *testing.T) {
	sf := &File{Clients: []ClientSeed{
		{Name: "web", Role: "frontend"},
		{Name: "web", Role: "service"},
	}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for duplicate client name")
	}
}

func TestValidate_UserEmailRequired(t *testing.T) {
	sf := &File{Users: []UserSeed{{Password: "TestPassword12345!"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for empty user email")
	}
}

func TestValidate_UserEmailInvalid(t *testing.T) {
	sf := &File{Users: []UserSeed{{Email: "notanemail", Password: "TestPassword12345!"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for invalid email")
	}
}

func TestValidate_UserPasswordRequired(t *testing.T) {
	sf := &File{Users: []UserSeed{{Email: "a@b.com"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestValidate_UserPasswordTooShort(t *testing.T) {
	sf := &File{Users: []UserSeed{{Email: "a@b.com", Password: "short"}}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for short password")
	}
}

func TestValidate_DuplicateEmail(t *testing.T) {
	sf := &File{Users: []UserSeed{
		{Email: "a@b.com", Password: "TestPassword12345!"},
		{Email: "a@b.com", Password: "AnotherPassword12345!"},
	}}
	if err := validate(sf); err == nil {
		t.Fatal("expected error for duplicate email")
	}
}

func TestRun_NewClients(t *testing.T) {
	firstBootSink(t)
	clients := newMockClientRepo()
	users := newMockUserRepo()

	sf := &File{
		Clients: []ClientSeed{
			{Name: "web", Role: "frontend", Scopes: []string{"user:read"}},
			{Name: "api", Role: "service", Scopes: []string{"user:read", "audit:read"}},
		},
	}

	err := Run(context.Background(), sf, Deps{Users: users, Clients: clients}, "")
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

	sf := &File{
		Clients: []ClientSeed{{Name: "web", Role: "frontend"}},
	}

	err := Run(context.Background(), sf, Deps{Users: newMockUserRepo(), Clients: clients}, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(clients.created) != 0 {
		t.Fatalf("expected 0 clients created (skip existing), got %d", len(clients.created))
	}
}

func TestRun_NewUsers(t *testing.T) {
	users := newMockUserRepo()

	sf := &File{
		Users: []UserSeed{
			{Email: "dev@test.com", Password: "TestPassword12345!", DisplayName: "Dev", Locale: "sk"},
		},
	}

	err := Run(context.Background(), sf, Deps{Users: users, Clients: newMockClientRepo()}, "")
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

	sf := &File{
		Users: []UserSeed{{Email: "dev@test.com", Password: "TestPassword12345!"}},
	}

	err := Run(context.Background(), sf, Deps{Users: users, Clients: newMockClientRepo()}, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(users.created) != 0 {
		t.Fatalf("expected 0 users created (skip existing), got %d", len(users.created))
	}
}

func TestRun_UserDefaultLocale(t *testing.T) {
	users := newMockUserRepo()

	sf := &File{
		Users: []UserSeed{{Email: "a@b.com", Password: "TestPassword12345!"}},
	}

	err := Run(context.Background(), sf, Deps{Users: users, Clients: newMockClientRepo()}, "")
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
	sf := &File{
		Users: []UserSeed{{Email: "a@b.com", Password: "TestPassword12345!", EmailVerified: &f}},
	}

	err := Run(context.Background(), sf, Deps{Users: users, Clients: newMockClientRepo()}, "")
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

	sf := &File{
		Users: []UserSeed{{Email: "peppered@test.com", Password: password, DisplayName: "P"}},
	}

	err := Run(context.Background(), sf,
		Deps{Users: users, Clients: newMockClientRepo()}, pepper)
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

// A-1 negative-control: when the pepper is empty, hashes verify without one
// (backward compatibility for an operator who has not configured VAULT_PEPPER).
// The empty pepper is passed explicitly, because that is now the only way to
// ask for it: it used to be an unset struct field, and cmd/vault leaving it
// unset by accident locked every seeded account out of the server.
func TestRun_UserPasswordNoPepperBackcompat(t *testing.T) {
	users := newMockUserRepo()
	const password = "TestPassword12345!"

	sf := &File{Users: []UserSeed{{Email: "nopepper@test.com", Password: password}}}
	err := Run(context.Background(), sf,
		Deps{Users: users, Clients: newMockClientRepo()}, "")
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

	sf := &File{
		Clients: []ClientSeed{{Name: "web", Role: "frontend"}},
	}

	err := Run(context.Background(), sf, Deps{Users: newMockUserRepo(), Clients: clients}, "")
	if err == nil {
		t.Fatal("expected error from client repo")
	}
}

// TestLoad_ValidationErrors is table-driven covering error paths in Load+validate.
func TestLoad_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string // substring in error
	}{
		{"client name required", `{"clients":[{"role":"frontend"}]}`, "name is required"},
		{"client role required", `{"clients":[{"name":"web"}]}`, "role is required"},
		{"duplicate client", `{"clients":[{"name":"web","role":"a"},{"name":"web","role":"b"}]}`, "duplicate name"},
		{"user email required", `{"users":[{"password":"TestPassword12345!"}]}`, "email is required"},
		{"user email invalid no @", `{"users":[{"email":"noat","password":"TestPassword12345!"}]}`, "invalid email"},
		{"user password required", `{"users":[{"email":"a@b.com"}]}`, "password is required"},
		{"user password short", `{"users":[{"email":"a@b.com","password":"short123"}]}`, "at least 15"},
		{"duplicate user email", `{"users":[{"email":"a@b.com","password":"TestPassword12345!"},{"email":"a@b.com","password":"TestPassword12345!"}]}`, "duplicate email"},
		{"admin reserved role on user", `{"users":[{"email":"a@b.com","password":"TestPassword12345!","roles":["admin"]}]}`, "reserved for the admins"},
		{"admin username required", `{"admins":[{"password":"TestPassword12345!","role":"viewer"}]}`, "username is required"},
		{"admin password required", `{"admins":[{"username":"root","role":"viewer"}]}`, "password is required"},
		{"admin password short", `{"admins":[{"username":"root","password":"short","role":"viewer"}]}`, "at least 15"},
		{"admin bad role", `{"admins":[{"username":"root","password":"TestPassword12345!","role":"root"}]}`, `role "root" is not an admin tier`},
		{"admin duplicate", `{"admins":[{"username":"root","password":"TestPassword12345!","role":"viewer"},{"username":"root","password":"TestPassword12345!","role":"viewer"}]}`, "duplicate username"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTemp(t, tt.content)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
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

func (m *errorClientRepo) List(context.Context) ([]*model.Client, error) { return nil, nil }
func (m *errorClientRepo) Update(context.Context, *model.Client) error   { return nil }
func (m *errorClientRepo) Deactivate(context.Context, string) error      { return nil }

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

// Table for FilterUserRoles covering reserved stripping and edges.
func TestFilterUserRoles_Table(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"user only", []string{"user"}, []string{"user"}},
		{"strips admin", []string{"user", "admin"}, []string{"user"}},
		{"strips super", []string{"super_admin"}, nil},
		{"strips mixed keeps others", []string{"admin", "operator", "super_admin", "viewer"}, []string{"operator", "viewer"}},
		{"all reserved", []string{"admin", "super_admin"}, nil},
		{"dupe preserved order except strip", []string{"user", "user"}, []string{"user", "user"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterUserRoles(tt.in)
			if len(got) != len(tt.want) {
				t.Errorf("len got %d want %d: %v vs %v", len(got), len(tt.want), got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("at %d: %q != %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// mockAdminUserRepo for testing admins seed.
type mockAdminUserRepo struct {
	users map[string]*model.AdminUser
}

func newMockAdminUserRepo() *mockAdminUserRepo {
	return &mockAdminUserRepo{users: make(map[string]*model.AdminUser)}
}

func (m *mockAdminUserRepo) Create(_ context.Context, u *model.AdminUser) error {
	m.users[u.Username] = u
	return nil
}

func (m *mockAdminUserRepo) GetByUsername(_ context.Context, un string) (*model.AdminUser, error) {
	return m.users[un], nil
}

func (m *mockAdminUserRepo) GetByID(context.Context, string) (*model.AdminUser, error) {
	return nil, nil
}
func (m *mockAdminUserRepo) List(context.Context) ([]*model.AdminUser, error) { return nil, nil }
func (m *mockAdminUserRepo) Count(context.Context) (int, error)               { return 0, nil }
func (m *mockAdminUserRepo) Update(context.Context, *model.AdminUser) error   { return nil }
func (m *mockAdminUserRepo) IncrementFailedLogin(context.Context, string) (int, error) {
	return 0, nil
}

func (m *mockAdminUserRepo) ResetFailedLogin(context.Context, string) error { return nil }

func (m *mockAdminUserRepo) LockUntil(context.Context, string, time.Time) error { return nil }

func (m *mockAdminUserRepo) UpdateLastTOTPCounter(context.Context, string, int64) error { return nil }

func (m *mockAdminUserRepo) UpdateLastLogin(context.Context, string) error { return nil }

func (m *mockAdminUserRepo) Revoke(context.Context, string) error { return nil }

// TestLoad_Table covers happy and all error paths in Load/validate.
func TestLoad_Table(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{"empty ok", `{}`, ""},
		{"client missing name", `{"clients":[{"role":"web"}]}`, "name is required"},
		{"client missing role", `{"clients":[{"name":"c"}]}`, "role is required"},
		{"client dup name", `{"clients":[{"name":"c","role":"r"},{"name":"c","role":"r"}]}`, "duplicate name"},
		{"user missing email", `{"users":[{"password":"123456789012345"}]}`, "email is required"},
		{"user invalid email no @", `{"users":[{"email":"noat","password":"123456789012345"}]}`, "invalid email"},
		{"user missing pass", `{"users":[{"email":"e@x.com"}]}`, "password is required"},
		{"user short pass", `{"users":[{"email":"e@x.com","password":"short"}]}`, "at least 15 characters"},
		{"user dup email", `{"users":[{"email":"e@x.com","password":"123456789012345"},{"email":"e@x.com","password":"123456789012345"}]}`, "duplicate email"},
		{"user reserved role", `{"users":[{"email":"e@x.com","password":"123456789012345","roles":["admin"]}]}`, "reserved for the admins"},
		{"admin missing username", `{"admins":[{"password":"123456789012345","role":"viewer"}]}`, "username is required"},
		{"admin missing pass", `{"admins":[{"username":"a","role":"viewer"}]}`, "password is required"},
		{"admin short pass", `{"admins":[{"username":"a","password":"short","role":"viewer"}]}`, "at least 15"},
		{"admin bad role", `{"admins":[{"username":"a","password":"123456789012345","role":"root"}]}`, `role "root" is not an admin tier`},
		{"admin dup username", `{"admins":[{"username":"a","password":"123456789012345","role":"viewer"},{"username":"a","password":"123456789012345","role":"viewer"}]}`, "duplicate username"},
		{"valid with admins", `{"admins":[{"username":"root","password":"123456789012345","role":"super_admin"}]}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := writeTemp(t, tt.json)
			sf, err := Load(p)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("err=%v want contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected err: %v", err)
			}
			if sf == nil {
				t.Error("nil sf on success")
			}
		})
	}
}

// TestRunAdmins_Table covers RunAdmins happy, skip, error paths.
func TestRunAdmins_Table(t *testing.T) {
	tests := []struct {
		name    string
		sf      *File
		setup   func(*mockAdminUserRepo)
		wantErr string
	}{
		{
			name: "empty admins ok",
			sf:   &File{},
		},
		{
			name: "seed new admin",
			sf:   &File{Admins: []AdminSeed{{Username: "adm", Password: "123456789012345", Role: "viewer"}}},
		},
		{
			name: "skip existing admin",
			sf:   &File{Admins: []AdminSeed{{Username: "ex", Password: "123456789012345", Role: "operator"}}},
			setup: func(m *mockAdminUserRepo) {
				m.users["ex"] = &model.AdminUser{ID: "1", Username: "ex"}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newMockAdminUserRepo()
			if tt.setup != nil {
				tt.setup(a)
			}
			err := RunAdmins(context.Background(), tt.sf, a, "")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("err %v want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("err %v", err)
			}
		})
	}
}
