package crypto

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The anti-enumeration dummy hash is the one value in this package that a
// background goroutine replaces underneath live request goroutines. Every login
// for an address that does not exist calls VerifyPassword with the DummyHash
// sentinel, VerifyPassword swaps in whatever the rotation loop last stored, and
// the rotation loop rewrites that store on a timer for the life of the process.
//
// argon2_rotation_loop_test.go already pins what a tick does, but it drives the
// loop with nothing else running. That leaves the interesting half untested:
// the swap and the read overlapping. What must hold through the overlap is that
// the burn a not-found login performs is always a real Argon2id computation
// against a well-formed spec-parameter hash. A reader that caught the value
// mid-write would fall into the parse-error branch of VerifyPassword, which
// computes against a throwaway zero salt instead. That is a cheaper and
// differently-shaped operation, so the not-found path would stop matching the
// found path in time and cost, and user enumeration by timing comes back. It
// would also be silent: the caller discards the error on the not-found path.
//
// Hence the invariant below is stated as a closed set of allowed outcomes.
// (false, nil) is a completed burn. ErrArgon2Overloaded is the semaphore
// shedding load, which is legitimate. Anything else, in particular a parse
// error, means a reader saw a hash the rotation had not finished publishing.
//
// The test is deliberately small. Each Argon2id operation reserves 46 MiB and
// the semaphore admits four at once, so the peak is bounded at roughly 184 MiB
// no matter how many goroutines pile in; the goroutine count and the wall-clock
// budget are kept tight anyway so the package never becomes the reason this
// machine swaps.

const (
	// argon2RaceVerifiers is above the semaphore capacity on purpose, so some
	// callers are always queueing while others are mid-computation.
	argon2RaceVerifiers = 8
	// argon2RaceOpsPerVerifier caps the work even on a fast machine.
	argon2RaceOpsPerVerifier = 40
	// argon2RaceBudget is the wall-clock ceiling. Whichever of the two limits is
	// reached first ends the storm.
	argon2RaceBudget = 5 * time.Second
)

func TestVerifyPassword_ConcurrentWithDummyHashRotation(t *testing.T) {
	initial := currentDummyHash()

	tick := make(chan time.Time)
	loopStopped := make(chan struct{})
	go func() {
		defer close(loopStopped)
		rotateDummyHashLoop(tick)
	}()

	var (
		wg                 sync.WaitGroup
		rotatedDuringStorm atomic.Bool
		completedBurns     atomic.Int64
		sheddedBurns       atomic.Int64
	)
	stopRotating := make(chan struct{})
	deadline := time.Now().Add(argon2RaceBudget)

	// The rotation driver. Sends on an unbuffered channel to a loop shaped as
	// "for range tick { regenerate }", so a send that returns proves the
	// previous iteration's regeneration has finished and the loop is back at the
	// receive. That is what makes the mid-storm rotation check below sound
	// rather than a poll that might sample too early.
	rotatorDone := make(chan struct{})
	go func() {
		defer close(rotatorDone)
		for {
			select {
			case <-stopRotating:
				return
			case tick <- time.Now():
			}
			if currentDummyHash() != initial {
				rotatedDuringStorm.Store(true)
			}
		}
	}()

	for i := 0; i < argon2RaceVerifiers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < argon2RaceOpsPerVerifier; n++ {
				ok, err := VerifyPassword("x", DummyHash)
				if ok {
					t.Errorf("the dummy burn reported a password match, which would tell an attacker the account does not exist")
					return
				}
				switch {
				case err == nil:
					completedBurns.Add(1)
				case errors.Is(err, ErrArgon2Overloaded):
					sheddedBurns.Add(1)
				default:
					t.Errorf("the dummy burn failed with %v; only a completed burn or ErrArgon2Overloaded is acceptable, and a parse error means a half-published rotation was observed", err)
					return
				}
				if n > 0 && time.Now().After(deadline) {
					return
				}
			}
		}()
	}

	wg.Wait()
	close(stopRotating)
	<-rotatorDone

	close(tick)
	select {
	case <-loopStopped:
	case <-time.After(30 * time.Second):
		t.Error("the rotation loop did not exit when its tick channel closed")
	}

	// Without these two the test could pass having proved nothing: no burns at
	// all, or a rotation loop that never actually swapped the value while the
	// verifiers were running.
	if completedBurns.Load() == 0 {
		t.Error("no dummy burn ever completed, so the outcome assertions prove nothing")
	}
	if !rotatedDuringStorm.Load() {
		t.Errorf("the dummy hash was never rotated while %d verifiers were running, so nothing was raced", argon2RaceVerifiers)
	}
	t.Logf("burns completed=%d shed=%d", completedBurns.Load(), sheddedBurns.Load())
}
