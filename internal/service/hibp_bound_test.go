package service

import (
	"sync"
	"testing"
	"time"
)

// Register calls HIBP before it checks whether the email is taken, and the
// check is fail-open by design so an HIBP outage never blocks a signup. What it
// had no bound on was outbound sockets: register is 3/hour/IP, so one address
// is harmless, but a thousand addresses registering at once opened a thousand
// concurrent five-second sockets and nothing counted them.

func TestHIBPSemaphoreBoundsConcurrency(t *testing.T) {
	h := NewHIBPClient()
	if cap(h.sem) != hibpMaxConcurrent {
		t.Fatalf("semaphore capacity = %d, want %d", cap(h.sem), hibpMaxConcurrent)
	}

	// Fill it and hold.
	for i := 0; i < hibpMaxConcurrent; i++ {
		if !h.acquire() {
			t.Fatalf("could not take slot %d of %d", i, hibpMaxConcurrent)
		}
	}

	start := time.Now()
	if h.acquire() {
		t.Fatal("a caller was admitted past the concurrency cap")
	}
	elapsed := time.Since(start)
	if elapsed > 2*hibpAcquireTimeout {
		t.Errorf("a shed caller waited %v, well past the %v acquire timeout", elapsed, hibpAcquireTimeout)
	}
	if got := h.ShedCount(); got != 1 {
		t.Errorf("ShedCount = %d, want 1 — each shed is a breached password that was accepted, "+
			"so it has to be a number an operator can read", got)
	}

	// Releasing frees the slot again, so the cap is a gate rather than a leak.
	h.release()
	if !h.acquire() {
		t.Fatal("a released slot was not reusable")
	}
	for i := 0; i < hibpMaxConcurrent; i++ {
		h.release()
	}
}

// TestHIBPFailsOpenWhenSaturated pins the behaviour the fail-open contract
// already promises: a check that cannot run answers "not breached", exactly as
// an unreachable HIBP does. Shedding must not become a way to block signups.
func TestHIBPFailsOpenWhenSaturated(t *testing.T) {
	h := NewHIBPClient()
	for i := 0; i < hibpMaxConcurrent; i++ {
		if !h.acquire() {
			t.Fatalf("could not take slot %d", i)
		}
	}
	defer func() {
		for i := 0; i < hibpMaxConcurrent; i++ {
			h.release()
		}
	}()

	// No network call happens: the semaphore is full, so IsBreached returns
	// before it builds a request.
	done := make(chan bool, 1)
	go func() { done <- h.IsBreached("correct-horse-battery-staple") }()
	select {
	case breached := <-done:
		if breached {
			t.Fatal("a shed check reported the password as breached; the contract is fail-open")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("IsBreached blocked on a full semaphore instead of failing open")
	}
	if h.ShedCount() == 0 {
		t.Error("the shed was not counted")
	}
}

// TestHIBPSemaphoreIsConcurrencySafe runs the gate under contention, since it
// is taken from every registration at once.
func TestHIBPSemaphoreIsConcurrencySafe(t *testing.T) {
	h := NewHIBPClient()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.acquire() {
				h.release()
			}
		}()
	}
	wg.Wait()
	if got := len(h.sem); got != 0 {
		t.Fatalf("%d slots left held after every caller released", got)
	}
}
