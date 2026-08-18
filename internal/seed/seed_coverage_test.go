package seed

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// --- inline mocks (only the methods the seed paths touch) ---

// Each mock embeds the full repository interface (nil) and overrides only the
// methods the seed path calls; any unexpected call would nil-panic, which is the
// desired signal in a focused test.

type seedClientRepo struct {
	repository.ClientRepository
	getByName func(context.Context, string) (*model.Client, error)
	create    func(context.Context, *model.Client) error
}

func (m *seedClientRepo) Create(ctx context.Context, c *model.Client) error {
	return m.create(ctx, c)
}

func (m *seedClientRepo) GetByName(ctx context.Context, n string) (*model.Client, error) {
	return m.getByName(ctx, n)
}

type seedUserRepo struct {
	repository.UserRepository
	getByEmail func(context.Context, string) (*model.User, error)
	create     func(context.Context, *model.User) error
}

func (m *seedUserRepo) Create(ctx context.Context, u *model.User) error { return m.create(ctx, u) }
func (m *seedUserRepo) GetByEmail(ctx context.Context, e string) (*model.User, error) {
	return m.getByEmail(ctx, e)
}

type seedAdminRepo struct {
	repository.AdminUserRepository
	getByUsername func(context.Context, string) (*model.AdminUser, error)
	create        func(context.Context, *model.AdminUser) error
	list          func(context.Context) ([]*model.AdminUser, error)
}

func (m *seedAdminRepo) Create(ctx context.Context, a *model.AdminUser) error {
	return m.create(ctx, a)
}

// List is what seedAdmin consults to attribute a seeded row to a creator, which
// migration 016 requires once any admin exists. A nil list stands for an empty
// table, so the seeded admin goes in unattributed the way first boot does.
func (m *seedAdminRepo) List(ctx context.Context) ([]*model.AdminUser, error) {
	if m.list == nil {
		return nil, nil
	}
	return m.list(ctx)
}

func (m *seedAdminRepo) GetByUsername(ctx context.Context, u string) (*model.AdminUser, error) {
	return m.getByUsername(ctx, u)
}

func okClientRepo(created *bool) *seedClientRepo {
	return &seedClientRepo{
		getByName: func(context.Context, string) (*model.Client, error) { return nil, nil },
		create:    func(context.Context, *model.Client) error { *created = true; return nil },
	}
}

func TestSeedClient(t *testing.T) {
	ctx := context.Background()
	cs := ClientSeed{Name: "frontend", Role: "frontend", Scopes: []string{"user:read"}}

	t.Run("creates a new client", func(t *testing.T) {
		firstBootSink(t)
		created := false
		if err := seedClient(ctx, cs, okClientRepo(&created)); err != nil {
			t.Fatalf("seedClient: %v", err)
		}
		if !created {
			t.Error("Create not called")
		}
	})

	t.Run("skips an existing client", func(t *testing.T) {
		repo := &seedClientRepo{
			getByName: func(context.Context, string) (*model.Client, error) {
				return &model.Client{ID: "c1", Name: "frontend"}, nil
			},
			create: func(context.Context, *model.Client) error { t.Fatal("should not create when existing"); return nil },
		}
		if err := seedClient(ctx, cs, repo); err != nil {
			t.Fatalf("seedClient (existing): %v", err)
		}
	})

	t.Run("propagates lookup and create errors", func(t *testing.T) {
		firstBootSink(t)
		lookupErr := &seedClientRepo{getByName: func(context.Context, string) (*model.Client, error) { return nil, errors.New("db") }}
		if err := seedClient(ctx, cs, lookupErr); err == nil {
			t.Error("expected lookup error")
		}
		createErr := &seedClientRepo{
			getByName: func(context.Context, string) (*model.Client, error) { return nil, nil },
			create:    func(context.Context, *model.Client) error { return errors.New("db") },
		}
		if err := seedClient(ctx, cs, createErr); err == nil {
			t.Error("expected create error")
		}
	})
}

func TestSeedUser(t *testing.T) {
	ctx := context.Background()
	us := UserSeed{Email: "u@test.com", Password: "correct-horse-battery", Locale: "en"}

	t.Run("skips an existing user", func(t *testing.T) {
		repo := &seedUserRepo{getByEmail: func(context.Context, string) (*model.User, error) {
			return &model.User{ID: "u1"}, nil
		}}
		if err := seedUser(ctx, us, repo, ""); err != nil {
			t.Fatalf("seedUser (existing): %v", err)
		}
	})

	t.Run("lookup error propagates", func(t *testing.T) {
		repo := &seedUserRepo{getByEmail: func(context.Context, string) (*model.User, error) { return nil, errors.New("db") }}
		if err := seedUser(ctx, us, repo, ""); err == nil {
			t.Error("expected lookup error")
		}
	})

	t.Run("creates a new user with roles and email-verified flag", func(t *testing.T) {
		verified := true
		full := UserSeed{Email: "new@test.com", Password: "correct-horse-battery", Locale: "en", EmailVerified: &verified, Roles: []string{"user"}}
		created := false
		repo := &seedUserRepo{
			getByEmail: func(context.Context, string) (*model.User, error) { return nil, nil },
			create:     func(_ context.Context, u *model.User) error { created = true; return nil },
		}
		if err := seedUser(ctx, full, repo, "pepper"); err != nil {
			t.Fatalf("seedUser: %v", err)
		}
		if !created {
			t.Error("Create not called for a new user")
		}
	})

	t.Run("create error propagates", func(t *testing.T) {
		repo := &seedUserRepo{
			getByEmail: func(context.Context, string) (*model.User, error) { return nil, nil },
			create:     func(context.Context, *model.User) error { return errors.New("db") },
		}
		if err := seedUser(ctx, us, repo, ""); err == nil {
			t.Error("expected create error")
		}
	})
}

func TestRunAdmins(t *testing.T) {
	ctx := context.Background()
	sf := &SeedFile{Admins: []AdminSeed{{Username: "root", Password: "correct-horse-battery", Role: "super_admin"}}}

	t.Run("creates a new admin", func(t *testing.T) {
		created := false
		repo := &seedAdminRepo{
			getByUsername: func(context.Context, string) (*model.AdminUser, error) { return nil, nil },
			create:        func(context.Context, *model.AdminUser) error { created = true; return nil },
		}
		if err := RunAdmins(ctx, sf, repo, "pepper-value"); err != nil {
			t.Fatalf("RunAdmins: %v", err)
		}
		if !created {
			t.Error("admin not created")
		}
	})

	t.Run("skips an existing admin", func(t *testing.T) {
		repo := &seedAdminRepo{
			getByUsername: func(context.Context, string) (*model.AdminUser, error) {
				return &model.AdminUser{ID: "a1", Username: "root"}, nil
			},
			create: func(context.Context, *model.AdminUser) error { t.Fatal("should not create existing admin"); return nil },
		}
		if err := RunAdmins(ctx, sf, repo, ""); err != nil {
			t.Fatalf("RunAdmins (existing): %v", err)
		}
	})

	t.Run("lookup and create errors propagate", func(t *testing.T) {
		lookupErr := &seedAdminRepo{getByUsername: func(context.Context, string) (*model.AdminUser, error) { return nil, errors.New("db") }}
		if err := RunAdmins(ctx, sf, lookupErr, ""); err == nil {
			t.Error("expected lookup error")
		}
		createErr := &seedAdminRepo{
			getByUsername: func(context.Context, string) (*model.AdminUser, error) { return nil, nil },
			create:        func(context.Context, *model.AdminUser) error { return errors.New("db") },
		}
		if err := RunAdmins(ctx, sf, createErr, ""); err == nil {
			t.Error("expected create error")
		}
	})

	// A seed file names a role and never an actor. Migration 016 refuses an admin
	// row that outranks its creator and refuses an unattributed one once any admin
	// exists, so a seeded super_admin must be attributed to an account that can
	// carry it or the insert dies at the database.
	t.Run("attributes the seeded admin to the highest-ranked existing one", func(t *testing.T) {
		var got *model.AdminUser
		repo := &seedAdminRepo{
			getByUsername: func(context.Context, string) (*model.AdminUser, error) { return nil, nil },
			create:        func(_ context.Context, a *model.AdminUser) error { got = a; return nil },
			list: func(context.Context) ([]*model.AdminUser, error) {
				return []*model.AdminUser{
					nil,
					{ID: "viewer-id", Role: "viewer"},
					{ID: "boss-id", Role: "super_admin"},
					{ID: "unknown-id", Role: "not-a-role"},
					{ID: "op-id", Role: "operator"},
				}, nil
			},
		}
		if err := RunAdmins(ctx, sf, repo, ""); err != nil {
			t.Fatalf("RunAdmins: %v", err)
		}
		if got == nil {
			t.Fatal("the seeded admin was never created")
		}
		if got.CreatedBy != "boss-id" {
			t.Fatalf("CreatedBy = %q, want the super_admin's id", got.CreatedBy)
		}
	})

	t.Run("a failed creator lookup stops the seed", func(t *testing.T) {
		repo := &seedAdminRepo{
			getByUsername: func(context.Context, string) (*model.AdminUser, error) { return nil, nil },
			create: func(context.Context, *model.AdminUser) error {
				t.Fatal("must not create without a creator")
				return nil
			},
			list: func(context.Context) ([]*model.AdminUser, error) { return nil, errors.New("db") },
		}
		if err := RunAdmins(ctx, sf, repo, ""); err == nil {
			t.Error("expected the list error to propagate")
		}
	})
}

func TestRun_PropagatesErrors(t *testing.T) {
	ctx := context.Background()
	sf := &SeedFile{Clients: []ClientSeed{{Name: "x", Role: "frontend"}}}
	deps := Deps{Clients: &seedClientRepo{getByName: func(context.Context, string) (*model.Client, error) { return nil, errors.New("db") }}}
	if err := Run(ctx, sf, deps, ""); err == nil {
		t.Error("Run should propagate a client seed error")
	}
}

func TestValidate_Errors(t *testing.T) {
	long := "correct-horse-battery-staple"
	cases := []struct {
		name string
		sf   SeedFile
	}{
		{"client missing name", SeedFile{Clients: []ClientSeed{{Role: "frontend"}}}},
		{"client missing role", SeedFile{Clients: []ClientSeed{{Name: "a"}}}},
		{"duplicate client name", SeedFile{Clients: []ClientSeed{{Name: "a", Role: "r"}, {Name: "a", Role: "r"}}}},
		{"user missing email", SeedFile{Users: []UserSeed{{Password: long}}}},
		{"user invalid email", SeedFile{Users: []UserSeed{{Email: "nope", Password: long}}}},
		{"user missing password", SeedFile{Users: []UserSeed{{Email: "u@test.com"}}}},
		{"user short password", SeedFile{Users: []UserSeed{{Email: "u@test.com", Password: "short"}}}},
		{"duplicate email", SeedFile{Users: []UserSeed{{Email: "u@test.com", Password: long}, {Email: "u@test.com", Password: long}}}},
		{"user with reserved admin role", SeedFile{Users: []UserSeed{{Email: "u@test.com", Password: long, Roles: []string{"super_admin"}}}}},
		{"admin missing username", SeedFile{Admins: []AdminSeed{{Password: long}}}},
		{"admin missing password", SeedFile{Admins: []AdminSeed{{Username: "root"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validate(&tc.sf); err == nil {
				t.Errorf("validate(%s) = nil, want an error", tc.name)
			}
		})
	}

	t.Run("valid file passes", func(t *testing.T) {
		sf := SeedFile{
			Clients: []ClientSeed{{Name: "frontend", Role: "frontend"}},
			Users:   []UserSeed{{Email: "u@test.com", Password: long}},
			Admins:  []AdminSeed{{Username: "root", Password: long, Role: "super_admin"}},
		}
		if err := validate(&sf); err != nil {
			t.Errorf("validate(valid) = %v, want nil", err)
		}
	})
}

func TestFilterUserRoles(t *testing.T) {
	if got := FilterUserRoles(nil); got != nil {
		t.Errorf("FilterUserRoles(nil) = %v, want nil", got)
	}
	// Reserved admin roles are stripped; ordinary roles pass through.
	got := FilterUserRoles([]string{"user", "super_admin", "moderator"})
	for _, r := range got {
		if ReservedAdminRoles[r] {
			t.Errorf("FilterUserRoles kept reserved role %q", r)
		}
	}
}
