package redis

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// An idle connection past its timeout is a file descriptor held for nothing and a
// socket the server has very likely already dropped. reapIdle closes them, but only a
// tick of the reaper goroutine ever calls it: without that tick the pool fills to
// PoolSize during a traffic spike and holds every one of those sockets open for the
// life of the process, and the next caller is handed a connection that has to fail a
// health check before it can be replaced.
//
// Reaping means the socket is actually closed, not merely dropped from the slice, so
// the test writes to the reaped connection and requires the write to fail.
func TestPool_ReaperTickClosesTimedOutIdleConnections(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{
		Addr:        m.addr(),
		PoolSize:    4,
		IdleTimeout: 20 * time.Millisecond,
		DialTimeout: time.Second,
		IOTimeout:   time.Second,
	})
	defer c.Close()

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}

	c.pool.mu.Lock()
	if len(c.pool.idle) == 0 {
		c.pool.mu.Unlock()
		t.Fatal("no idle connection was pooled, so there is nothing to reap")
	}
	reaped := c.pool.idle[0]
	c.pool.mu.Unlock()

	go c.pool.reaper(2 * time.Millisecond)

	var idle int
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.pool.mu.Lock()
		idle = len(c.pool.idle)
		c.pool.mu.Unlock()
		if idle == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections stayed idle past IdleTimeout: the reaper never swept them", idle)
		}
		time.Sleep(time.Millisecond)
	}

	if total := atomic.LoadInt32(&c.pool.total); total != 0 {
		t.Errorf("total=%d after reaping every idle connection, want 0: the pool would refuse to dial replacements", total)
	}
	if _, err := reaped.netConn.Write([]byte("PING\r\n")); err == nil {
		t.Error("the reaped connection is still writable, so its socket was leaked rather than closed")
	}
}
