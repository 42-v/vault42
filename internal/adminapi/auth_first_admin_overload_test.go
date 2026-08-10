package adminapi

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// EnsureFirstAdmin runs once, at first boot, before anything else can reach the
// gateway. Its password is generated, hashed and printed to the log exactly
// once, and the operator has no other copy.
//
// HashPassword can refuse: the argon2id semaphore turns an overload into
// ErrArgon2Overloaded rather than an OOM kill, and first boot is a plausible
// moment to hit it, since a fleet coming up together bootstraps and serves
// logins at the same time. Swallowing that refusal would write a super_admin row
// with an empty PasswordHash. VerifyPassword against "" fails for every input,
// so the account is unusable, the printed password is a lie, and Count() is now
// non-zero so no later boot will ever create a working one. The deployment ends
// up with an admin gateway nobody can log in to and no way back short of a
// manual INSERT.
//
// The semaphore is unexported, so the only way to saturate it is to hold every
// slot for real. A hash that is parked reading its salt keeps its slot without
// burning CPU, which makes the rejection deterministic rather than a race.

// adminFirstBootEntropyGate parks the first parkFirst reads and serves real
// entropy to every read after that. The parked readers are the saturating
// hashes; the call under test still needs entropy of its own for the admin's
// UUID and password bytes, and must not be starved by the gate that is holding
// the semaphore against it.
type adminFirstBootEntropyGate struct {
	parkFirst int64
	real      io.Reader

	taken   atomic.Int64
	parked  atomic.Int64
	release chan struct{}
}

func (g *adminFirstBootEntropyGate) Read(p []byte) (int, error) {
	if g.taken.Add(1) <= g.parkFirst {
		g.parked.Add(1)
		<-g.release
	}
	return g.real.Read(p)
}

// adminSaturateArgon2 fills every argon2id semaphore slot and keeps it full
// until the test ends.
func adminSaturateArgon2(t *testing.T) {
	t.Helper()

	slots := vaultcrypto.Argon2MaxConcurrent()
	gate := &adminFirstBootEntropyGate{
		parkFirst: int64(slots),
		real:      adminapiRandReal,
		release:   make(chan struct{}),
	}
	adminapiRandUse(t, gate)

	var wg sync.WaitGroup
	for range slots {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = vaultcrypto.HashPassword("hold-an-argon2-slot")
		}()
	}
	// Registered after adminapiRandUse, so LIFO cleanup releases the parked
	// readers and drains the goroutines before the entropy source is restored.
	t.Cleanup(func() {
		close(gate.release)
		wg.Wait()
	})

	// Both conditions matter. Active count says every slot is taken; parked count
	// says every holder is already inside its blocking read, so no further read
	// can consume a parked ticket and hang the call under test.
	deadline := time.Now().Add(30 * time.Second)
	for vaultcrypto.Argon2ActiveCount() < int64(slots) || gate.parked.Load() < int64(slots) {
		if time.Now().After(deadline) {
			t.Fatal("the argon2 semaphore never reached capacity")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestEnsureFirstAdmin_RefusesToBootstrapWhenHashingIsOverloaded(t *testing.T) {
	adminSaturateArgon2(t)

	repo := newFakeAdminRepo()
	err := EnsureFirstAdmin(context.Background(), repo, "test-pepper")

	if err == nil {
		t.Fatal("first-boot bootstrap reported success while password hashing was refusing work")
	}
	if !errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
		t.Errorf("err = %v, want it to wrap ErrArgon2Overloaded so the operator can retry", err)
	}
	if len(repo.users) != 0 {
		for _, u := range repo.users {
			t.Errorf("a super_admin %q was created with PasswordHash %q; the printed password would never work and Count() now blocks every later attempt",
				u.Username, u.PasswordHash)
		}
	}
}
