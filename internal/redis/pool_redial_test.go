package redis

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// When a pooled connection fails its health check, get() dials a replacement
// while still holding the semaphore slot. If that redial also fails (Redis is
// down, not just the one connection), the slot must be released or the pool
// permanently shrinks by one; enough such failures and every future get()
// blocks forever on a semaphore nobody will ever refill.
func TestPool_RedialFailureAfterFailedHealthCheckReleasesSlot(t *testing.T) {
	p := newPool(&Options{
		Addr:        "127.0.0.1:1", // reserved; nothing listens here
		DialTimeout: 250 * time.Millisecond,
	})
	defer close(p.done)

	// Seed one idle connection that is fresh enough to be reused but whose
	// health-check PING cannot be written.
	cn := newClosedPipeConn(t)
	cn.lastUsed = time.Now()
	atomic.AddInt32(&p.total, 1)
	p.idle = append(p.idle, cn)

	got, err := p.get(context.Background())
	if got != nil {
		t.Fatalf("expected no connection after a failed redial, got %v", got)
	}
	if err == nil || !strings.Contains(err.Error(), "redis: dial 127.0.0.1:1") {
		t.Fatalf("expected the redial failure to surface, got %v", err)
	}
	if free := len(p.sem); free != p.maxConns {
		t.Fatalf("semaphore slot leaked: %d of %d free", free, p.maxConns)
	}
	if active := atomic.LoadInt32(&p.active); active != 0 {
		t.Fatalf("active = %d after a failed get, want 0", active)
	}
}
