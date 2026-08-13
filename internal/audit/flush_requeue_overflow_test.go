package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// gatedAuditRepo holds the first InsertBatch open until the test releases it.
//
// Flush empties the buffer under the lock and inserts outside it, so requeue
// only ever meets a non-empty buffer when events arrived during that window.
// That is the ordinary shape of the incident: the store is slow or down, the
// batch is stuck in flight, and the service keeps serving requests and logging
// what it serves. Holding the insert open is the only way to reproduce it
// without a sleep.
//
// A nil release channel means no gating, for the tests that only need a store
// that says no.
type gatedAuditRepo struct {
	mu       sync.Mutex
	fail     bool
	attempts int
	inserted []*model.AuditEntry

	entered chan struct{} // closed once the first InsertBatch is inside
	release chan struct{} // closed by the test to let that call return
	gate    sync.Once
}

func (g *gatedAuditRepo) InsertBatch(_ context.Context, entries []*model.AuditEntry) error {
	if g.release != nil {
		g.gate.Do(func() {
			close(g.entered)
			<-g.release
		})
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.attempts++
	if g.fail {
		return errors.New("audit store unavailable")
	}
	g.inserted = append(g.inserted, entries...)
	return nil
}

func (g *gatedAuditRepo) Insert(ctx context.Context, e *model.AuditEntry) error {
	return g.InsertBatch(ctx, []*model.AuditEntry{e})
}

func (g *gatedAuditRepo) Query(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
	return nil, nil
}
func (g *gatedAuditRepo) CountByUser(context.Context, string) (int, error) { return 0, nil }
func (g *gatedAuditRepo) Cleanup(context.Context, time.Time) (int64, error) {
	return 0, nil
}
func (g *gatedAuditRepo) CleanupLocked(context.Context, time.Time) (int64, bool, error) {
	return 0, true, nil
}

func (g *gatedAuditRepo) stopFailing() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fail = false
}

func (g *gatedAuditRepo) attemptCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.attempts
}

// storedUsers reports the user ID of every entry the store accepted, in order.
// The tests tag each event with a distinct user so the surviving records can be
// identified individually.
func (g *gatedAuditRepo) storedUsers() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	users := make([]string, 0, len(g.inserted))
	for _, e := range g.inserted {
		users = append(users, e.UserID)
	}
	return users
}

// logSeries writes n events tagged prefix-0 .. prefix-(n-1).
func logSeries(t *testing.T, l *Logger, prefix string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		user := fmt.Sprintf("%s-%d", prefix, i)
		if err := l.Log(context.Background(), LoginSuccess, user, "", "10.0.0.1", "ua", "", "", nil, 0); err != nil {
			t.Fatalf("Log %s: %v", user, err)
		}
	}
}

// TestRequeueBoundsItselfWhenTheBufferRefilledDuringTheInsert is the cap on the
// retry.
//
// Putting a rejected batch back cannot be unconditional. A store that stays down
// while the service keeps logging would otherwise let the buffer grow past its
// configured size on every failed flush, without limit, inside a process that is
// already unhealthy: the buffer cap exists precisely to stop an audit backlog
// from becoming the outage. Here the buffer is completely refilled while the
// insert is out, so the rejected batch has nowhere to go at all, and what cannot
// be kept has to show up in DroppedTotal instead of vanishing quietly. An
// operator alerting on that counter is entitled to read zero as no loss.
func TestRequeueBoundsItselfWhenTheBufferRefilledDuringTheInsert(t *testing.T) {
	const capacity = 4

	repo := &gatedAuditRepo{
		fail:    true,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	l := NewLoggerWithBufferSize(repo, time.Hour, capacity)

	logSeries(t, l, "older", capacity)

	flushed := make(chan error, 1)
	go func() { flushed <- l.Flush(context.Background()) }()

	// The batch is now in flight and the buffer is empty.
	<-repo.entered
	logSeries(t, l, "newer", capacity)
	close(repo.release)

	if err := <-flushed; err == nil {
		t.Fatal("Flush reported success while the store was rejecting every batch")
	}

	if dropped := l.DroppedTotal(); dropped != capacity {
		t.Errorf("DroppedTotal = %d, want %d: the rejected batch did not fit and was discarded, "+
			"and a counter that stays put leaves an operator reading no loss while audit records "+
			"are being thrown away", dropped, capacity)
	}

	repo.stopFailing()
	if err := l.Flush(context.Background()); err != nil {
		t.Fatalf("Flush after the store recovered: %v", err)
	}

	users := repo.storedUsers()
	if len(users) != capacity {
		t.Fatalf("%d entries were held against a buffer of %d: the retry ignored the cap, so a "+
			"store that stays down grows the buffer without limit", len(users), capacity)
	}
	for _, u := range users {
		if !strings.HasPrefix(u, "newer-") {
			t.Errorf("held %q: the entries already in the buffer were displaced by the rejected "+
				"batch, so the retry loses records instead of keeping them", u)
		}
	}
}

// TestRequeueKeepsTheOldestRecordsItStillHasRoomFor is the partial case, and the
// one that fixes which records are sacrificed.
//
// When only some of a rejected batch fits, the choice is not arbitrary. An
// append-only trail should lose its newest records rather than its oldest: the
// oldest are the ones nothing else is going to write again, and they are the
// ones describing what was happening as the store went down. So the batch is
// trimmed from its tail, put back ahead of everything logged while the insert
// was out, and the remainder is counted.
func TestRequeueKeepsTheOldestRecordsItStillHasRoomFor(t *testing.T) {
	const (
		capacity = 7
		// The size of both the rejected batch and the run of events that
		// arrives while it is in flight. The buffer holds two more than either,
		// so the numbers below stay distinct: a partial fit that kept the wrong
		// half, or counted the wrong half, would still be wrong by a different
		// amount.
		batch = 5
		// What the arrivals leave room for, and what has to be counted instead.
		fits    = capacity - batch // 2
		dropped = batch - fits     // 3
	)

	repo := &gatedAuditRepo{
		fail:    true,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	l := NewLoggerWithBufferSize(repo, time.Hour, capacity)

	logSeries(t, l, "older", batch)

	flushed := make(chan error, 1)
	go func() { flushed <- l.Flush(context.Background()) }()

	<-repo.entered
	logSeries(t, l, "newer", batch)
	close(repo.release)

	if err := <-flushed; err == nil {
		t.Fatal("Flush reported success while the store was rejecting every batch")
	}

	if got := l.DroppedTotal(); got != dropped {
		t.Errorf("DroppedTotal = %d, want %d: %d of the rejected entries had no room, and the "+
			"count of what was lost has to match what was actually lost", got, dropped, dropped)
	}

	repo.stopFailing()
	if err := l.Flush(context.Background()); err != nil {
		t.Fatalf("Flush after the store recovered: %v", err)
	}

	want := []string{"older-0", "older-1", "newer-0", "newer-1", "newer-2", "newer-3", "newer-4"}
	got := repo.storedUsers()
	if len(got) != len(want) {
		t.Fatalf("%d entries survived, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("surviving entries = %v, want %v: the retry must keep the oldest of the "+
				"rejected batch and put it back ahead of what arrived while the insert was out",
				got, want)
		}
	}
}

// lockedBuffer collects log output that the batch-loop goroutine writes while
// the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestBatchLoopReportsAFlushItCouldNotComplete is the regression for a store
// outage nobody could see.
//
// The periodic flush discarded its error with `_ = l.Flush(...)`, under a
// comment claiming Flush logged it, which Flush did not do. Nothing else in the
// process observes that call: the entries are buffered, so no request fails, and
// no caller gets a return value. An audit store that was rejecting every batch
// therefore produced no signal at all, on any channel, for as long as it stayed
// down. The report is now the only place an operator learns of it, and the
// entries have to still be there afterwards for the report to mean "retained"
// rather than "lost".
func TestBatchLoopReportsAFlushItCouldNotComplete(t *testing.T) {
	var out lockedBuffer
	prev := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prev) })

	repo := &gatedAuditRepo{fail: true}
	l := NewLoggerWithBufferSize(repo, 5*time.Millisecond, 100)
	t.Cleanup(func() { _ = l.Close(context.Background()) })

	logSeries(t, l, "held", 1)

	waitFor(t, func() bool { return repo.attemptCount() > 0 }, "the batch loop to attempt a flush")

	if logged := out.String(); !strings.Contains(logged, "audit: flush failed") {
		t.Errorf("the batch loop flushed into a store that rejected the batch and reported "+
			"nothing. An outage that never reaches a log is an outage nobody responds to. "+
			"Captured output: %q", logged)
	}

	repo.stopFailing()
	waitFor(t, func() bool { return len(repo.storedUsers()) > 0 }, "the recovered store to accept the batch")

	if users := repo.storedUsers(); len(users) != 1 || users[0] != "held-0" {
		t.Errorf("after the store recovered it holds %v, want [held-0]: the failed ticks were "+
			"supposed to be retaining the entry, not losing it", users)
	}
}

// waitFor polls cond until it holds or the test gives up. The batch loop runs on
// a ticker, so there is no signal to wait on.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
