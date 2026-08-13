package seed

import (
	"context"
	"errors"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// cliconfigStubHasher replaces the Argon2id hasher for the duration of a test.
// The returned recorder reports whether the hasher was reached at all, which is
// what separates "seeding stopped early" from "seeding hashed and then failed".
func cliconfigStubHasher(t *testing.T, err error) *int {
	t.Helper()
	calls := 0
	old := hashPassword
	hashPassword = func(string, ...string) (string, error) {
		calls++
		return "", err
	}
	t.Cleanup(func() { hashPassword = old })
	return &calls
}

// The argon2id semaphore rejects work when the box is already running four
// hashes (ErrArgon2Overloaded). Seeding is unattended, so a rejected hash must
// abort the whole run: writing a row with an empty password hash would create
// an account nobody can log into but every attacker can enumerate.
func TestSeedRun_HashFailureCreatesNothing(t *testing.T) {
	t.Run("client secret", func(t *testing.T) {
		calls := cliconfigStubHasher(t, vaultcrypto.ErrArgon2Overloaded)
		created := 0
		deps := Deps{
			Clients: &mocks.MockClientRepo{
				GetByNameFn: func(context.Context, string) (*model.Client, error) { return nil, nil },
				CreateFn:    func(context.Context, *model.Client) error { created++; return nil },
			},
			Users: &mocks.MockUserRepo{},
		}
		sf := &SeedFile{Clients: []ClientSeed{{Name: "beon3-web", Role: "app", Scopes: []string{"read"}}}}

		err := Run(context.Background(), sf, deps, "")
		if err == nil {
			t.Fatal("seeding reported success though the client secret was never hashed")
		}
		if !errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			t.Errorf("error %v does not wrap ErrArgon2Overloaded", err)
		}
		if !strings.Contains(err.Error(), "beon3-web") {
			t.Errorf("error %q does not name the client that failed", err)
		}
		if *calls != 1 {
			t.Errorf("hasher called %d times, want 1", *calls)
		}
		if created != 0 {
			t.Errorf("client was written %d times despite a hashing failure", created)
		}
	})

	t.Run("user password", func(t *testing.T) {
		calls := cliconfigStubHasher(t, vaultcrypto.ErrArgon2Overloaded)
		var written []*model.User
		deps := Deps{
			Clients: &mocks.MockClientRepo{},
			Users: &mocks.MockUserRepo{
				GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
				CreateFn:     func(_ context.Context, u *model.User) error { written = append(written, u); return nil },
			},
		}
		sf := &SeedFile{Users: []UserSeed{
			{Email: "first@example.com", Password: "correctP@ssw0rd!"},
			{Email: "second@example.com", Password: "correctP@ssw0rd!"},
		}}

		err := Run(context.Background(), sf, deps, "")
		if err == nil {
			t.Fatal("seeding reported success though no password was ever hashed")
		}
		if !errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			t.Errorf("error %v does not wrap ErrArgon2Overloaded", err)
		}
		if !strings.Contains(err.Error(), "first@example.com") {
			t.Errorf("error %q does not name the user that failed", err)
		}
		if len(written) != 0 {
			t.Errorf("wrote %d users despite a hashing failure", len(written))
		}
		if *calls != 1 {
			t.Errorf("hasher called %d times, want 1: seeding continued past the failure", *calls)
		}
	})
}

// The admin seed array is the only path to the super_admin tier, so a rejected
// hash there must not leave a half-built privileged account behind.
func TestSeedRunAdmins_HashFailureCreatesNothing(t *testing.T) {
	calls := cliconfigStubHasher(t, vaultcrypto.ErrArgon2Overloaded)
	admins := newMockAdminUserRepo()
	sf := &SeedFile{Admins: []AdminSeed{{Username: "root", Password: "correctP@ssw0rd!", Role: "super_admin"}}}

	err := RunAdmins(context.Background(), sf, admins, "")
	if err == nil {
		t.Fatal("admin seeding reported success though the password was never hashed")
	}
	if !errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
		t.Errorf("error %v does not wrap ErrArgon2Overloaded", err)
	}
	if !strings.Contains(err.Error(), "root") {
		t.Errorf("error %q does not name the admin that failed", err)
	}
	if *calls != 1 {
		t.Errorf("hasher called %d times, want 1", *calls)
	}
	if got, _ := admins.GetByUsername(context.Background(), "root"); got != nil {
		t.Error("a super_admin row was created without a password hash")
	}
}

// The pepper must reach the hasher for users and admins (it binds the hash to a
// server-side secret) and must never be applied to a client secret, which is
// full-entropy random and gains nothing from it.
func TestSeed_PepperReachesPasswordHashesOnly(t *testing.T) {
	var peppers [][]string
	old := hashPassword
	hashPassword = func(_ string, pepper ...string) (string, error) {
		peppers = append(peppers, pepper)
		return "", errors.New("stop here")
	}
	t.Cleanup(func() { hashPassword = old })

	deps := Deps{
		Clients: &mocks.MockClientRepo{
			GetByNameFn: func(context.Context, string) (*model.Client, error) { return nil, nil },
		},
		Users: &mocks.MockUserRepo{GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil }},
	}

	if err := Run(context.Background(), &SeedFile{Clients: []ClientSeed{{Name: "c", Role: "app"}}}, deps, "server-side-pepper"); err == nil {
		t.Fatal("expected the stub hasher to abort client seeding")
	}
	if len(peppers) != 1 || len(peppers[0]) != 0 {
		t.Fatalf("client secret was peppered: %v", peppers)
	}

	peppers = nil
	sf := &SeedFile{Users: []UserSeed{{Email: "u@example.com", Password: "correctP@ssw0rd!"}}}
	if err := Run(context.Background(), sf, deps, "server-side-pepper"); err == nil {
		t.Fatal("expected the stub hasher to abort user seeding")
	}
	if len(peppers) != 1 || len(peppers[0]) != 1 || peppers[0][0] != "server-side-pepper" {
		t.Fatalf("user password hash did not receive the pepper: %v", peppers)
	}
}
