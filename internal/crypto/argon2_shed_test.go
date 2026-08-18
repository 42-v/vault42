package crypto

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The semaphore bounds MEMORY: four slots, ~184 MiB of issued-parameter working
// set. What it did not bound was TIME. acquireArgon2 waited the whole acquire
// timeout before giving up, so the queue was however many callers could drain in
// five seconds — ~420 on a measured 47.7ms hash — and the caller at the back
// paid the full five seconds for a 503 it was going to get anyway.

// TestAcquireShedsPastTheQueueDepth drives the gauge directly rather than by
// running hundreds of real hashes: the shed decision reads argon2Waiting, so
// that is the input under test, and 64 concurrent 46 MiB hashes is not
// something a unit test should allocate.
func TestAcquireShedsPastTheQueueDepth(t *testing.T) {
	before := argon2Rejected.Load()
	argon2Waiting.Add(int64(argon2MaxQueueDepth))
	defer argon2Waiting.Add(-int64(argon2MaxQueueDepth))

	start := time.Now()
	err := acquireArgon2()
	elapsed := time.Since(start)

	if err != ErrArgon2Overloaded {
		if err == nil {
			releaseArgon2()
		}
		t.Fatalf("acquireArgon2 at queue depth %d = %v, want ErrArgon2Overloaded", argon2MaxQueueDepth, err)
	}
	if elapsed > time.Second {
		t.Errorf("shedding took %v; the point is that a caller past the depth is refused at "+
			"once rather than after the %v acquire timeout", elapsed, argon2AcquireTimeout)
	}
	if got := argon2Rejected.Load() - before; got != 1 {
		t.Errorf("Argon2RejectedCount advanced by %d, want 1 — the shed has to be countable", got)
	}
	if got := Argon2WaitingCount(); got != int64(argon2MaxQueueDepth) {
		t.Errorf("Argon2WaitingCount = %d after a shed, want %d: a shed caller must not be "+
			"counted as a waiter", got, argon2MaxQueueDepth)
	}
}

// TestAcquireStillQueuesBelowTheDepth is the control. Shedding a legitimate
// login to keep a latency number down would be worse than serving it slowly, so
// below the threshold nothing changes.
func TestAcquireStillQueuesBelowTheDepth(t *testing.T) {
	rejectedBefore := argon2Rejected.Load()

	// Fill every slot and hold them.
	var held sync.WaitGroup
	release := make(chan struct{})
	for i := 0; i < argon2MaxConcurrent; i++ {
		if err := acquireArgon2(); err != nil {
			t.Fatalf("could not fill slot %d: %v", i, err)
		}
		held.Add(1)
		go func() {
			defer held.Done()
			<-release
			releaseArgon2()
		}()
	}

	// One more caller, well under the depth, must queue and then succeed as
	// soon as a slot frees rather than being refused.
	var acquired atomic.Bool
	done := make(chan error, 1)
	go func() {
		err := acquireArgon2()
		if err == nil {
			acquired.Store(true)
			releaseArgon2()
		}
		done <- err
	}()

	// Give the waiter time to register on the gauge.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && Argon2WaitingCount() == 0 {
		time.Sleep(time.Millisecond)
	}
	if Argon2WaitingCount() == 0 {
		t.Error("a caller under the queue depth never registered as waiting")
	}

	close(release)
	held.Wait()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a caller %d under the queue depth was refused: %v", argon2MaxQueueDepth-1, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the queued caller never acquired a slot")
	}
	if !acquired.Load() {
		t.Fatal("the queued caller reported success without acquiring")
	}
	if got := argon2Rejected.Load() - rejectedBefore; got != 0 {
		t.Errorf("Argon2RejectedCount advanced by %d while under the queue depth", got)
	}
}

// TestQueueDepthIsSizedAgainstTheSlots keeps the two numbers from drifting into
// a combination that means something else. A depth at or below the slot count
// would shed callers the semaphore could serve immediately.
func TestQueueDepthIsSizedAgainstTheSlots(t *testing.T) {
	if argon2MaxQueueDepth <= argon2MaxConcurrent {
		t.Fatalf("argon2MaxQueueDepth=%d is not above argon2MaxConcurrent=%d, so callers are "+
			"shed while slots are free", argon2MaxQueueDepth, argon2MaxConcurrent)
	}
	// The depth exists to bound wait time. At a pessimistic 200ms per hash it
	// must still drain inside the server's write timeout.
	const pessimisticHash = 200 * time.Millisecond
	worstWait := time.Duration(argon2MaxQueueDepth/argon2MaxConcurrent) * pessimisticHash
	if worstWait > 10*time.Second {
		t.Fatalf("at %v per hash a full queue drains in %v, past any sensible write timeout",
			pessimisticHash, worstWait)
	}
}
