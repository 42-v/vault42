package cache

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// recordingPG is a PostgreSQL wire peer that completes the startup handshake
// and records the SQL text of every simple-protocol query it is asked to run,
// answering each with a zero-row DELETE tag unless answerWith says otherwise.
type recordingPG struct {
	mu      sync.Mutex
	queries []string
	tag     string
	before  func()
}

// answerWith replies to every subsequent query with tag, and runs before, if
// set, ahead of that reply. Running the hook before the reply rather than after
// is what makes a test deterministic: the client is still blocked waiting for
// this statement, so it cannot yet have moved on to the next one.
func (r *recordingPG) answerWith(tag string, before func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tag = tag
	r.before = before
}

func (r *recordingPG) record(sql string) (tag string, before func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, sql)
	tag = r.tag
	if tag == "" {
		tag = "DELETE 0"
	}
	return tag, r.before
}

func (r *recordingPG) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.queries...)
}

func (r *recordingPG) serve(conn net.Conn) {
	defer conn.Close() //nolint:errcheck // test peer teardown
	backend := pgproto3.NewBackend(conn, conn)
	if _, err := backend.ReceiveStartupMessage(); err != nil {
		return
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.4"})
	backend.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	backend.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
	backend.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		return
	}
	for {
		msg, err := backend.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			tag, before := r.record(m.String)
			if before != nil {
				before()
			}
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag)})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := backend.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

func newRecordingPGPool(t *testing.T) (*pgxpool.Pool, *recordingPG) {
	t.Helper()
	peer := &recordingPG{}
	cfg, err := pgxpool.ParseConfig("postgres://vault:vault@127.0.0.1:5432/vault?sslmode=disable&default_query_exec_mode=simple_protocol")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.ConnConfig.DialFunc = func(_ context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go peer.serve(server)
		return client, nil
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, peer
}

// Nothing in the codebase ever deleted an expired row from auth.cache. Get and
// GetAndDelete filter on expires_at but leave the row in place, Set overwrites
// only its own key, and there is no cron, pg_cron job or chart hook that
// touches the table. The memory backend sweeps every 30 seconds and Redis
// evicts on its own, so the Postgres backend was the one deployment shape where
// every rate-limit bucket ever created stayed on disk forever. The keys are
// created by unauthenticated traffic: each request through the IP limiter mints
// rl:ip:<addr> with a 60-second TTL, so a steady 100 req/s adds around 8.6
// million permanently dead rows a day to the primary key index of the auth
// database, and the first symptom is the whole auth service failing to write.
func TestPostgresCacheReclaimsExpiredRowsSoTheTableDoesNotGrowWithoutBound(t *testing.T) {
	prevInterval := pgSweepInterval
	pgSweepInterval = 5 * time.Millisecond
	t.Cleanup(func() { pgSweepInterval = prevInterval })

	pool, peer := newRecordingPGPool(t)

	c, err := NewPostgresCache(pool)
	if err != nil {
		t.Fatalf("NewPostgresCache: %v", err)
	}
	defer c.Close() //nolint:errcheck // teardown

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, q := range peer.seen() {
			if strings.Contains(q, "DELETE") && strings.Contains(q, "expires_at") {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the Postgres backend never issued a delete of expired rows; queries seen: %q", peer.seen())
}

// The sweeper must stop when the cache is closed. main.go defers Close on
// shutdown, and a goroutine still running Exec against a pool the process is
// tearing down logs errors during every graceful shutdown and keeps the pool
// from draining.
func TestClosingThePostgresCacheStopsTheBackgroundSweep(t *testing.T) {
	prevInterval := pgSweepInterval
	pgSweepInterval = 5 * time.Millisecond
	t.Cleanup(func() { pgSweepInterval = prevInterval })

	pool, peer := newRecordingPGPool(t)

	c, err := NewPostgresCache(pool)
	if err != nil {
		t.Fatalf("NewPostgresCache: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Allow any sweep already in flight to finish before taking the baseline.
	time.Sleep(50 * time.Millisecond)
	before := len(peer.seen())
	time.Sleep(100 * time.Millisecond)
	if after := len(peer.seen()); after != before {
		t.Fatalf("sweeper issued %d more queries after Close; it must stop", after-before)
	}
}

// The stop must also be honored between the batches of a single sweep, not
// only between ticks. A rollout onto a table that already holds millions of
// dead rows makes every tick a full run of pgSweepMaxBatches deletes, each with
// its own pgSweepTimeout budget, so a sweep in progress can outlast the whole
// shutdown window. main.go defers Close and then waits: without the per-batch
// check, it waits on twenty more DELETE statements it has already asked for
// none of, against a pool it is draining, and the graceful shutdown turns into
// the kill timeout.
func TestClosingThePostgresCacheAbandonsTheRestOfASweepInProgress(t *testing.T) {
	pool, peer := newRecordingPGPool(t)

	c, err := NewPostgresCache(pool)
	if err != nil {
		t.Fatalf("NewPostgresCache: %v", err)
	}

	// A full batch is the answer that tells the reaper there is more backlog to
	// work off, so it would issue another delete were it not closed.
	peer.answerWith(fmt.Sprintf("DELETE %d", pgSweepBatch), func() { _ = c.Close() })

	c.reapExpired()

	var deletes int
	for _, q := range peer.seen() {
		if strings.Contains(q, "DELETE") && strings.Contains(q, "auth.cache") {
			deletes++
		}
	}
	if deletes != 1 {
		t.Fatalf("the reaper ran %d delete batches against a closed cache, want 1; shutdown waits on every batch it does not abandon", deletes)
	}
}

// Close must stay safe to call more than once: main.go defers it and the
// factory error paths can reach it too. A second close of the stop channel
// panics and takes down the process during shutdown.
func TestClosingThePostgresCacheTwiceDoesNotPanic(t *testing.T) {
	pool, _ := newRecordingPGPool(t)
	c, err := NewPostgresCache(pool)
	if err != nil {
		t.Fatalf("NewPostgresCache: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// Close races with the sweep it stops and with in-flight cache operations:
// main.go closes the cache from the shutdown path while request handlers are
// still finishing. Closing the stop channel twice, or closing it while the
// sweeper reads it, panics or trips the race detector in the middle of a
// graceful shutdown.
func TestClosingThePostgresCacheConcurrentlyIsSafe(t *testing.T) {
	prevInterval := pgSweepInterval
	pgSweepInterval = time.Millisecond
	t.Cleanup(func() { pgSweepInterval = prevInterval })

	pool, _ := newRecordingPGPool(t)
	c, err := NewPostgresCache(pool)
	if err != nil {
		t.Fatalf("NewPostgresCache: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Close(); err != nil {
				t.Errorf("concurrent Close: %v", err)
			}
		}()
	}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.Delete(context.Background(), "k")
		}()
	}
	wg.Wait()
}
