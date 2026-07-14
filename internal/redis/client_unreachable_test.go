package redis

import (
	"context"
	"net"
	"testing"
	"time"
)

// deadClient points at a port nothing listens on, so every command fails at dial.
// This is what a Redis outage looks like from inside the process.
func deadClient(t *testing.T) *Client {
	t.Helper()
	c := NewClient(&Options{
		Addr:        "127.0.0.1:1", // reserved; nothing listens here
		DialTimeout: 250 * time.Millisecond,
		IOTimeout:   250 * time.Millisecond,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// Redis backs the rate limiter, the session cache and the single-use OTP/reset
// tokens. Every command must report a connection failure rather than return a zero
// value, because the zero values here are all indistinguishable from success:
//
//   - Set returning nil means an OTP or reset token looks stored and then vanishes;
//     the user is handed a code that can never be redeemed.
//   - SetNX returning (true, nil) means "I acquired the lock" — the single-use
//     guarantee behind OTP redemption and idempotency keys silently disappears, and
//     a code becomes replayable.
//   - Incr returning (0, nil) means every request looks like the first in its window
//     and the rate limiter stops limiting.
//
// None of these would raise an error anywhere. They would just quietly stop working.
func TestClient_UnreachableRedisSurfacesEveryCommand(t *testing.T) {
	ctx := context.Background()

	t.Run("Ping", func(t *testing.T) {
		if err := deadClient(t).Ping(ctx); err == nil {
			t.Error("Ping reported a healthy Redis that is not there")
		}
	})

	t.Run("Get", func(t *testing.T) {
		if _, err := deadClient(t).Get(ctx, "k"); err == nil {
			t.Error("Get returned no error against an unreachable Redis")
		}
	})

	t.Run("Set", func(t *testing.T) {
		if err := deadClient(t).Set(ctx, "k", "v", time.Minute); err == nil {
			t.Error("Set reported success — the value was never stored and nothing said so")
		}
	})

	t.Run("SetNX", func(t *testing.T) {
		ok, err := deadClient(t).SetNX(ctx, "lock", "v", time.Minute)
		if err == nil {
			t.Error("SetNX reported success — the single-use guarantee would silently vanish")
		}
		if ok {
			t.Error("SetNX claimed it acquired the lock while Redis was unreachable")
		}
	})

	t.Run("Del", func(t *testing.T) {
		if _, err := deadClient(t).Del(ctx, "k"); err == nil {
			t.Error("Del reported success against an unreachable Redis")
		}
	})

	t.Run("GetDel", func(t *testing.T) {
		if _, err := deadClient(t).GetDel(ctx, "k"); err == nil {
			t.Error("GetDel returned no error — a single-use token would read as consumed")
		}
	})

	t.Run("Incr", func(t *testing.T) {
		n, err := deadClient(t).Incr(ctx, "rl:203.0.113.1")
		if err == nil {
			t.Error("Incr reported success — the rate limiter would fail open")
		}
		if n > 0 {
			t.Errorf("a failed Incr returned a count of %d", n)
		}
	})

	t.Run("Expire", func(t *testing.T) {
		if _, err := deadClient(t).Expire(ctx, "k", time.Minute); err == nil {
			t.Error("Expire reported success — a key with no TTL never expires")
		}
	})

	t.Run("Exists", func(t *testing.T) {
		if _, err := deadClient(t).Exists(ctx, "k"); err == nil {
			t.Error("Exists returned no error against an unreachable Redis")
		}
	})

	t.Run("Eval", func(t *testing.T) {
		if _, err := deadClient(t).Eval(ctx, "return 1", 0); err == nil {
			t.Error("Eval reported success against an unreachable Redis")
		}
	})
}

// hangUpServer accepts a connection and immediately closes it. This is the failure
// the tests above cannot reach: the dial *succeeds*, so the client believes it has a
// working connection, and the command then fails on the wire.
//
// It is not a contrived case. A Redis restart, a failover, or an idle proxy timeout
// all drop established connections, and the client is holding pooled ones. The dial
// error path and the command error path are separate branches, and only the second
// one is exercised when Redis dies underneath a live connection.
func hangUpServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			cn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = cn.Close()
		}
	}()
	return ln.Addr().String()
}

func hangUpClient(t *testing.T) *Client {
	t.Helper()
	c := NewClient(&Options{
		Addr:        hangUpServer(t),
		DialTimeout: time.Second,
		IOTimeout:   250 * time.Millisecond,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// Same guarantee as above, one layer deeper: the connection is established and then
// dies mid-command. Every command must still report the failure rather than hand back
// a zero value that reads as a legitimate result.
func TestClient_ConnectionDroppedMidCommandSurfaces(t *testing.T) {
	ctx := context.Background()

	t.Run("Ping", func(t *testing.T) {
		if err := hangUpClient(t).Ping(ctx); err == nil {
			t.Error("Ping reported a healthy Redis after the connection was dropped")
		}
	})

	t.Run("Get", func(t *testing.T) {
		if _, err := hangUpClient(t).Get(ctx, "k"); err == nil {
			t.Error("Get returned no error after the connection was dropped")
		}
	})

	t.Run("Set", func(t *testing.T) {
		if err := hangUpClient(t).Set(ctx, "k", "v", time.Minute); err == nil {
			t.Error("Set reported success — the value was never written and nothing said so")
		}
	})

	t.Run("SetNX", func(t *testing.T) {
		ok, err := hangUpClient(t).SetNX(ctx, "lock", "v", time.Minute)
		if err == nil {
			t.Error("SetNX reported success — a single-use token would become replayable")
		}
		if ok {
			t.Error("SetNX claimed the lock after the connection was dropped")
		}
	})

	t.Run("Exists", func(t *testing.T) {
		if _, err := hangUpClient(t).Exists(ctx, "k"); err == nil {
			t.Error("Exists returned no error after the connection was dropped")
		}
	})

	t.Run("Eval", func(t *testing.T) {
		if _, err := hangUpClient(t).Eval(ctx, "return 1", 0); err == nil {
			t.Error("Eval reported success after the connection was dropped")
		}
	})
}
