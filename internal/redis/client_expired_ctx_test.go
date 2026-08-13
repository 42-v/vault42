package redis

import (
	"context"
	"sync"
	"testing"
	"time"
)

// exec used to fold the caller's deadline into the socket deadline without
// checking that it was still in the future. A request whose context had already
// expired therefore reached SetDeadline with a time in the past, the very next
// write failed, and exec treated that as a broken connection and removed it from
// the pool.
//
// The caller's clock running out says nothing about the health of the socket, so
// every such request destroyed a good connection. It also amplifies exactly when
// it hurts: requests arrive with expired contexts precisely because they queued
// behind a slow cache, and each one costs the next caller a fresh dial plus AUTH
// and SELECT. The cache is what enforces the login rate limits and the lockout
// counters, so driving it into permanent reconnect makes Increment fail, and a
// limiter that is not FailClosed then falls back to a per-pod counter, which is
// brute-force protection weakening under exactly the load that triggers it.
//
// The test measures the survivor rather than the casualty: after a burst of
// expired-context calls, a healthy request must still be served by the
// connection that was already pooled, so the server sees no second accept.
func TestAnAlreadyExpiredContextDoesNotCostThePoolItsConnection(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr(), PoolSize: 1})
	defer c.Close() //nolint:errcheck // teardown

	if err := c.Set(context.Background(), "k", "v", time.Minute); err != nil {
		t.Fatalf("warm-up Set: %v", err)
	}
	base := m.accepts.Load()
	if base != 1 {
		t.Fatalf("warm-up dialed %d connections, want 1", base)
	}

	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for i := 0; i < 30; i++ {
		if _, err := c.Get(expired, "k"); err == nil {
			t.Fatalf("call %d with an expired deadline returned no error", i)
		}
	}

	val, err := c.Get(context.Background(), "k")
	if err != nil {
		t.Fatalf("Get with a live context after the burst: %v", err)
	}
	if val != "v" {
		t.Fatalf("Get returned %q, want %q", val, "v")
	}
	if got := m.accepts.Load(); got != base {
		t.Fatalf("the pooled connection was destroyed by callers with expired deadlines: %d extra dial(s) needed to serve the next healthy request", got-base)
	}
}

// The same rule for a context canceled with no deadline at all. exec inspected
// only ctx.Deadline(), so a canceled request was sent to Redis and answered
// normally: the caller had given up, the work was done anyway, and a call that
// must not have run mutated the cache. GETDEL and SET NX are consumed on the
// server whether or not the caller is still listening, so a canceled Exchange or
// DPoP replay check could burn its one-time entry and leave the retry to find
// nothing.
func TestACanceledContextIsNotSentToRedis(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr(), PoolSize: 1})
	defer c.Close() //nolint:errcheck // teardown

	if err := c.Set(context.Background(), "one-shot", "v", time.Minute); err != nil {
		t.Fatalf("warm-up Set: %v", err)
	}
	base := m.accepts.Load()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 30; i++ {
		if _, err := c.GetDel(canceled, "one-shot"); err == nil {
			t.Fatalf("call %d on a canceled context reached Redis and consumed the key", i)
		}
	}

	// The key must be untouched, and the connection must still be the pooled one.
	val, err := c.GetDel(context.Background(), "one-shot")
	if err != nil {
		t.Fatalf("the single-use key was consumed by a canceled call: %v", err)
	}
	if val != "v" {
		t.Fatalf("GetDel returned %q, want %q", val, "v")
	}
	if got := m.accepts.Load(); got != base {
		t.Fatalf("canceled calls cost the pool %d connection(s)", got-base)
	}
}

// The early return added to exec hands the connection back to the pool, so it
// runs the same accounting the success path does. Getting that wrong leaks
// semaphore slots (the pool wedges once maxConns callers have been canceled) or
// double-releases them (more connections in flight than the pool allows, and
// Close blocks forever draining a semaphore that was over-filled). Drive it
// concurrently with live traffic and then prove the pool still works.
func TestCanceledCallsDoNotLeakOrDoubleReleasePoolSlots(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr(), PoolSize: 4})
	defer c.Close() //nolint:errcheck // teardown

	if err := c.Set(context.Background(), "k", "v", time.Minute); err != nil {
		t.Fatalf("warm-up Set: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = c.Get(canceled, "k")
		}()
	}
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background(), "k"); err != nil {
				t.Errorf("live Get alongside canceled callers: %v", err)
			}
		}()
	}
	wg.Wait()

	// The pool must still hand out every slot it owns.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 4; i++ {
			if _, err := c.Get(context.Background(), "k"); err != nil {
				t.Errorf("Get after the canceled burst: %v", err)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pool wedged after canceled callers; a semaphore slot was leaked")
	}
}
