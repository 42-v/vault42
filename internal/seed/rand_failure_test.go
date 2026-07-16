package seed

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// Seeding mints IDs and client secrets straight from crypto/rand. If entropy
// fails mid-seed, the run must abort with a named error instead of writing a
// row with a zero-value ID or handing out an empty client secret.

// errSeedEntropy is what the scripted reader returns once its budget is spent.
var errSeedEntropy = errors.New("entropy exhausted")

// seedScriptedReader stands in for crypto/rand.Reader: it serves whole reads
// until the budget is spent, then fails. Every seed-path consumer reaches the
// reader via io.ReadFull (crypto.RandomBytes), so the failure comes back as an
// error instead of aborting the process.
type seedScriptedReader struct {
	reads int
}

func (r *seedScriptedReader) Read(p []byte) (int, error) {
	if r.reads <= 0 {
		return 0, errSeedEntropy
	}
	r.reads--
	for i := range p {
		p[i] = 0x42
	}
	return len(p), nil
}

// seedSwapRandReader installs r as crypto/rand.Reader and restores the
// original when the test ends. internal/seed has no parallel tests, so the
// global swap cannot race.
func seedSwapRandReader(t *testing.T, r io.Reader) {
	t.Helper()
	old := rand.Reader
	rand.Reader = r
	t.Cleanup(func() { rand.Reader = old })
}

func TestSeedClient_EntropyFailure(t *testing.T) {
	ctx := context.Background()
	cs := ClientSeed{Name: "frontend", Role: "frontend"}
	repo := &seedClientRepo{
		getByName: func(context.Context, string) (*model.Client, error) { return nil, nil },
	}

	t.Run("client ID generation fails", func(t *testing.T) {
		seedSwapRandReader(t, &seedScriptedReader{reads: 0})

		err := seedClient(ctx, cs, repo)
		if err == nil {
			t.Fatal("expected an error when client ID entropy fails")
		}
		if got, want := err.Error(), "generate client ID: crypto/rand: entropy exhausted"; got != want {
			t.Errorf("error = %q, want %q", got, want)
		}
	})

	t.Run("client secret generation fails", func(t *testing.T) {
		seedSwapRandReader(t, &seedScriptedReader{reads: 1})

		err := seedClient(ctx, cs, repo)
		if err == nil {
			t.Fatal("expected an error when client secret entropy fails")
		}
		if got, want := err.Error(), "generate client secret: crypto/rand: entropy exhausted"; got != want {
			t.Errorf("error = %q, want %q", got, want)
		}
	})
}

func TestSeedAdmin_EntropyFailure(t *testing.T) {
	seedSwapRandReader(t, &seedScriptedReader{reads: 0})
	as := AdminSeed{Username: "root", Password: "correct-horse-battery", Role: "admin"}
	repo := &seedAdminRepo{
		getByUsername: func(context.Context, string) (*model.AdminUser, error) { return nil, nil },
	}

	err := seedAdmin(context.Background(), as, repo, "")
	if err == nil {
		t.Fatal("expected an error when admin ID entropy fails")
	}
	if got, want := err.Error(), "generate admin ID: crypto/rand: entropy exhausted"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

func TestSeedUser_EntropyFailure(t *testing.T) {
	seedSwapRandReader(t, &seedScriptedReader{reads: 0})
	us := UserSeed{Email: "u@test.com", Password: "correct-horse-battery"}
	repo := &seedUserRepo{
		getByEmail: func(context.Context, string) (*model.User, error) { return nil, nil },
	}

	err := seedUser(context.Background(), us, repo, "")
	if err == nil {
		t.Fatal("expected an error when user ID entropy fails")
	}
	if got, want := err.Error(), "generate user ID: crypto/rand: entropy exhausted"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}
