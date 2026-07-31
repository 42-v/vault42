package crypto

import (
	"testing"
	"time"
)

// The rotation loop is the thing that actually moves the anti-enumeration dummy
// hash forward: regenerateDummyHash is only ever called from here. Two
// properties matter and neither is visible from regenerateDummyHash alone. A
// tick must replace the hash, or the salt stays fixed for the process lifetime
// and the dummy burn keeps a recognizable memory pattern. And a tick whose
// regeneration fails must be swallowed rather than ending the loop: the process
// would otherwise stop rotating for good after a single overload, silently, and
// the previous hash has to remain a valid spec-parameter hash so the burn still
// costs what a real verification costs.

// cryptoKeysAwaitDummyRotation polls until the rotating dummy hash differs from
// prev, and returns the new value.
func cryptoKeysAwaitDummyRotation(t *testing.T, prev string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if cur := currentDummyHash(); cur != prev {
			return cur
		}
		if time.Now().After(deadline) {
			t.Fatal("the rotation loop never replaced the dummy hash")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// cryptoKeysAssertBurnableHash fails if h is not a hash the constant-time burn
// can run against with the spec parameters.
func cryptoKeysAssertBurnableHash(t *testing.T, h string) {
	t.Helper()
	salt, hash, params, err := parseArgon2Hash(h)
	if err != nil {
		t.Fatalf("dummy hash does not parse: %v", err)
	}
	if params.memory != argon2Memory || params.iterations != argon2Iterations || params.parallelism != argon2Parallelism {
		t.Errorf("dummy hash params m=%d,t=%d,p=%d, want m=%d,t=%d,p=%d",
			params.memory, params.iterations, params.parallelism,
			argon2Memory, argon2Iterations, argon2Parallelism)
	}
	if len(salt) != argon2SaltLen || len(hash) != argon2KeyLen {
		t.Errorf("dummy hash salt/key length %d/%d, want %d/%d",
			len(salt), len(hash), argon2SaltLen, argon2KeyLen)
	}
}

func TestRotateDummyHashLoop_TickRotatesAndSurvivesFailure(t *testing.T) {
	tick := make(chan time.Time)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		rotateDummyHashLoop(tick)
	}()

	initial := currentDummyHash()
	tick <- time.Now()
	rotated := cryptoKeysAwaitDummyRotation(t, initial)
	cryptoKeysAssertBurnableHash(t, rotated)

	// Saturate the semaphore so the next tick's regeneration is rejected with
	// ErrArgon2Overloaded. The follow-up send only completes once the loop is
	// back at the receive, so the failed iteration is provably finished.
	for i := 0; i < argon2MaxConcurrent; i++ {
		argon2Sem <- struct{}{}
	}
	tick <- time.Now()
	tick <- time.Now()
	if currentDummyHash() != rotated {
		t.Error("a failed regeneration replaced the rotating dummy hash")
	}
	cryptoKeysAssertBurnableHash(t, currentDummyHash())

	for i := 0; i < argon2MaxConcurrent; i++ {
		<-argon2Sem
	}
	tick <- time.Now()
	cryptoKeysAwaitDummyRotation(t, rotated)

	close(tick)
	select {
	case <-stopped:
	case <-time.After(30 * time.Second):
		t.Error("the rotation loop did not exit when its tick channel closed")
	}
}
