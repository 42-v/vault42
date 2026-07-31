package redis

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// Del is how a session, a refresh token and a consumed one-time code are revoked, and
// Expire is how a lockout window and a session TTL are refreshed. Both hand back a
// zero value on the error path, and both zero values are ordinary results elsewhere:
// (0, nil) from Del reads as "that key was already gone", (false, nil) from Expire
// reads as "no such key". A caller that only checks the value would treat a Redis
// outage as a completed revocation and leave a live token in place.
//
// The pool bookkeeping matters just as much. The connection died mid-command, so it
// must be removed rather than returned, and its semaphore slot must come back; a slot
// lost on every failed command shrinks the pool to nothing during an outage and then
// every later command blocks forever instead of erroring.
func TestClient_DelAndExpireSurfaceAMidCommandFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("Del", func(t *testing.T) {
		c := hangUpClient(t)

		n, err := c.Del(ctx, "session:abc")
		if err == nil {
			t.Fatal("Del reported a completed revocation after the connection dropped")
		}
		if n != 0 {
			t.Errorf("Del returned n=%d alongside an error, want 0", n)
		}
		mwcAssertPoolDrained(t, c)
	})

	t.Run("Expire", func(t *testing.T) {
		c := hangUpClient(t)

		ok, err := c.Expire(ctx, "lockout:user", time.Minute)
		if err == nil {
			t.Fatal("Expire reported a set TTL after the connection dropped")
		}
		if ok {
			t.Error("Expire claimed the TTL was applied while the connection was dead")
		}
		mwcAssertPoolDrained(t, c)
	})
}

func mwcAssertPoolDrained(t *testing.T, c *Client) {
	t.Helper()
	if total := atomic.LoadInt32(&c.pool.total); total != 0 {
		t.Errorf("the broken connection stayed in the pool, total=%d", total)
	}
	if active := atomic.LoadInt32(&c.pool.active); active != 0 {
		t.Errorf("active=%d after a failed command, want 0", active)
	}
	if free := len(c.pool.sem); free != c.pool.maxConns {
		t.Errorf("semaphore slot leaked: %d of %d free", free, c.pool.maxConns)
	}
}
