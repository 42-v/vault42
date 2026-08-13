package seed

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Seeding runs once, at deploy time, usually unattended. A failure that is swallowed
// leaves a half-seeded deployment — the OAuth client exists but the first user does not,
// or neither does — and the operator has no reason to look, because the seed reported
// success. Every failure must come back named, so the log says which client or which
// user could not be created.
func TestSeedRun_FailuresAreNotSwallowed(t *testing.T) {
	boom := errors.New("db down")

	t.Run("a client that cannot be looked up", func(t *testing.T) {
		sf := &SeedFile{Clients: []ClientSeed{{Name: "beon3-web", Role: "app", Scopes: []string{"read"}}}}
		deps := Deps{
			Clients: &mocks.MockClientRepo{
				GetByNameFn: func(context.Context, string) (*model.Client, error) { return nil, boom },
			},
			Users: &mocks.MockUserRepo{},
		}

		err := Run(context.Background(), sf, deps, "")
		if err == nil {
			t.Fatal("seeding reported success while the database was down")
		}
		if !strings.Contains(err.Error(), "beon3-web") {
			t.Errorf("error %q does not name the client that failed", err)
		}
	})

	t.Run("a client that cannot be created", func(t *testing.T) {
		sf := &SeedFile{Clients: []ClientSeed{{Name: "beon3-web", Role: "app", Scopes: []string{"read"}}}}
		deps := Deps{
			Clients: &mocks.MockClientRepo{
				GetByNameFn: func(context.Context, string) (*model.Client, error) { return nil, nil },
				CreateFn:    func(context.Context, *model.Client) error { return boom },
			},
			Users: &mocks.MockUserRepo{},
		}

		if err := Run(context.Background(), sf, deps, ""); err == nil {
			t.Fatal("seeding reported success though the client was never written")
		}
	})

	t.Run("a user that cannot be created", func(t *testing.T) {
		sf := &SeedFile{Users: []UserSeed{{Email: "first@example.com", Password: "correctP@ssw0rd!"}}}
		deps := Deps{
			Clients: &mocks.MockClientRepo{},
			Users: &mocks.MockUserRepo{
				GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
				CreateFn:     func(context.Context, *model.User) error { return boom },
			},
		}

		err := Run(context.Background(), sf, deps, "")
		if err == nil {
			t.Fatal("seeding reported success though the first user was never written")
		}
		if !strings.Contains(err.Error(), "first@example.com") {
			t.Errorf("error %q does not name the user that failed", err)
		}
	})

	t.Run("a user that cannot be looked up", func(t *testing.T) {
		sf := &SeedFile{Users: []UserSeed{{Email: "first@example.com", Password: "correctP@ssw0rd!"}}}
		deps := Deps{
			Clients: &mocks.MockClientRepo{},
			Users: &mocks.MockUserRepo{
				GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, boom },
			},
		}

		if err := Run(context.Background(), sf, deps, ""); err == nil {
			t.Fatal("seeding reported success while the user lookup was failing")
		}
	})
}
