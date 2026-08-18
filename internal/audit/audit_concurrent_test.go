package audit

import (
	"context"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// The batching logger has three writers to one buffer: request goroutines
// calling Log, the background batch loop calling Flush on its ticker, and
// shutdown calling Close. The audit trail is the product's evidence that a
// security-relevant thing happened, so an event that falls between two of those
// three is not a dropped metric, it is a gap in the record. Worse, the two ways
// it can vanish are both silent: Log returns nil whether the entry was
// buffered, dropped on overflow, or appended to a logger that has already shut
// its batch loop down.
//
// The existing tests in this package all drive one writer at a time. These
// drive all three at once, and the assertions are chosen so that any event
// which goes missing has to show up in the arithmetic rather than merely
// failing to appear.
//
// Two properties are asserted.
//
// Every submitted event must be accounted for. The equation is
// batch-inserted + still-buffered + DroppedTotal + AfterCloseTotal == submitted.
// Raw synchronous inserts are absent from it, which is a genuine subtlety of
// this code: DroppedTotal counts buffer-full OCCURRENCES, and a critical event
// that hits a full buffer increments it and is then written synchronously
// anyway. Counting both would double-count exactly those events. AfterCloseTotal
// is the other synchronous path — an event whose writer outlived Close — and it
// is disjoint from DroppedTotal, because a closed logger never reaches the
// buffer at all. If Log ever starts losing an entry outright, or starts counting
// one twice, this equation breaks.
//
// And a critical event submitted before shutdown began must survive shutdown.
// LoginFailure, PasswordChange, KMSUnwrap and the rest are the events an
// investigation actually reads. "Before shutdown began" is established without
// hand-waving: a logger records an event as pre-Close only if its Log call
// returned and a subsequent atomic load of the close flag still read false,
// which orders the buffer append ahead of the Close call itself, and therefore
// ahead of the flush Close performs.

// concurrentAuditRepo separates the two write paths. Only the critical
// buffer-overflow branch of Log calls Insert when batching is on, so keeping
// the counts apart is what lets the accounting equation be stated exactly.
type concurrentAuditRepo struct {
	mu     sync.Mutex
	seqs   map[int]int // seq marker -> times written
	single int
	batch  int
}

func newConcurrentAuditRepo() *concurrentAuditRepo {
	return &concurrentAuditRepo{seqs: make(map[int]int)}
}

func (r *concurrentAuditRepo) record(entry *model.AuditEntry) {
	if seq, ok := entry.Metadata["seq"].(int); ok {
		r.seqs[seq]++
	}
}

func (r *concurrentAuditRepo) Insert(_ context.Context, entry *model.AuditEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.single++
	r.record(entry)
	return nil
}

func (r *concurrentAuditRepo) InsertBatch(_ context.Context, entries []*model.AuditEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batch += len(entries)
	for _, e := range entries {
		r.record(e)
	}
	return nil
}

func (r *concurrentAuditRepo) Query(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
	return nil, nil
}

func (r *concurrentAuditRepo) CountByUser(context.Context, string) (int, error) { return 0, nil }

func (r *concurrentAuditRepo) Cleanup(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (r *concurrentAuditRepo) CleanupLocked(context.Context, time.Time) (int64, bool, error) {
	return 0, true, nil
}

func (r *concurrentAuditRepo) counts() (single, batch int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.single, r.batch
}

func (r *concurrentAuditRepo) written(seq int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seqs[seq]
}

// auditBufferedCount reports how many entries are sitting in the logger's
// buffer, which is where an event that neither reached the repository nor was
// counted as dropped has to be if the accounting is to balance.
func auditBufferedCount(l *Logger) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buffer)
}

const (
	auditRaceWriters       = 32
	auditRaceEventsPerHead = 60
	// A small buffer relative to the submission rate guarantees the overflow
	// branch is exercised rather than left to luck.
	auditRaceBufferSize = 16
)

func TestLogger_ConcurrentLogFlushCloseAccountsForEveryEvent(t *testing.T) {
	// The overflow branch logs a warning per dropped event; at this volume that
	// is thousands of lines burying any real failure output.
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	repo := newConcurrentAuditRepo()
	l := NewLoggerWithBufferSize(repo, 2*time.Millisecond, auditRaceBufferSize)
	ctx := context.Background()

	var closeStarted atomic.Bool
	var writers, helpers sync.WaitGroup
	stopHelpers := make(chan struct{})

	// preCloseCritical collects the seq markers of critical events proven to
	// have been buffered before Close was called. Each writer fills its own
	// slice so the collection itself needs no lock.
	preCloseCritical := make([][]int, auditRaceWriters)
	start := make(chan struct{})

	for w := 0; w < auditRaceWriters; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			<-start
			for n := 0; n < auditRaceEventsPerHead; n++ {
				seq := w*auditRaceEventsPerHead + n
				// Alternate so both the critical and the non-critical branch of
				// the overflow path are driven by the same storm.
				eventType := LoginSuccess
				critical := n%3 == 0
				if critical {
					eventType = LoginFailure
				}
				if err := l.Log(ctx, eventType, "u", "", "203.0.113.9", "", "", "",
					map[string]interface{}{"seq": seq}); err != nil {
					t.Errorf("Log returned an error during the storm: %v", err)
					return
				}
				// Reading the flag as false here proves the append above
				// happened before Close was called, because the flag is set
				// before the Close call and this load did not see it.
				if critical && !closeStarted.Load() {
					preCloseCritical[w] = append(preCloseCritical[w], seq)
				}
			}
		}(w)
	}

	// A flusher racing the batch loop's own ticker, so two flushers compete for
	// the same buffer.
	helpers.Add(1)
	go func() {
		defer helpers.Done()
		<-start
		for {
			select {
			case <-stopHelpers:
				return
			default:
			}
			if err := l.Flush(ctx); err != nil {
				t.Errorf("Flush returned an error during the storm: %v", err)
				return
			}
		}
	}()

	// Shutdown lands in the middle of the storm rather than after it.
	helpers.Add(1)
	go func() {
		defer helpers.Done()
		<-start
		time.Sleep(3 * time.Millisecond)
		closeStarted.Store(true)
		if err := l.Close(ctx); err != nil {
			t.Errorf("Close returned an error: %v", err)
		}
	}()

	close(start)
	writers.Wait()
	close(stopHelpers)
	helpers.Wait()

	submitted := auditRaceWriters * auditRaceEventsPerHead
	_, batched := repo.counts()
	buffered := auditBufferedCount(l)
	dropped := int(l.DroppedTotal())
	afterClose := int(l.AfterCloseTotal())

	if got := batched + buffered + dropped + afterClose; got != submitted {
		t.Errorf("audit events went unaccounted for: batch-inserted %d + still-buffered %d + DroppedTotal %d + AfterCloseTotal %d = %d, want %d submitted",
			batched, buffered, dropped, afterClose, got, submitted)
	}
	if dropped == 0 {
		t.Error("the buffer never overflowed, so the overflow branch of the accounting was never exercised")
	}
	// afterClose is deliberately not asserted non-zero: whether any writer is
	// still running when Close lands is a race this test creates but cannot
	// guarantee, and an assertion on it would be flaky rather than strict. Its
	// job here is to keep the equation exact when it does happen.
	// TestLogger_LogAfterCloseIsWrittenSynchronously covers the branch itself.

	var checked int
	for _, seqs := range preCloseCritical {
		for _, seq := range seqs {
			checked++
			if repo.written(seq) == 0 {
				t.Errorf("critical event seq=%d was submitted before shutdown began and never reached the repository", seq)
			}
		}
	}
	if checked == 0 {
		t.Error("no critical event was recorded as pre-shutdown, so the survival assertion proves nothing")
	}
}

// TestLogger_LogAfterCloseIsWrittenSynchronously pins what the batching logger
// does with an event submitted after Close.
//
// It used to append it to the buffer and return nil: the batch loop that would
// have drained it had already exited, DroppedTotal did not move, and nothing but
// an explicit further Flush would ever write it. The previous version of this
// test pinned that behavior expressly without endorsing it, and said the right
// answer was a rejection or a synchronous write rather than a silent append.
// This is that decision taken: the entry goes straight to the store, the buffer
// stays empty, and AfterCloseTotal counts it so the accounting above still
// balances and an operator has a number for "something outlived the logger".
func TestLogger_LogAfterCloseIsWrittenSynchronously(t *testing.T) {
	repo := newConcurrentAuditRepo()
	// A flush interval long enough that the batch loop never ticks, so the only
	// writes are the ones this test asks for.
	l := NewLoggerWithBufferSize(repo, time.Hour, 100)
	ctx := context.Background()

	if err := l.Log(ctx, LoginFailure, "u", "", "203.0.113.9", "", "", "",
		map[string]interface{}{"seq": 1}); err != nil {
		t.Fatalf("pre-close Log: %v", err)
	}
	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := repo.written(1); got != 1 {
		t.Fatalf("Close did not flush the pre-close event: written %d times, want 1", got)
	}

	if err := l.Log(ctx, LoginFailure, "u", "", "203.0.113.9", "", "", "",
		map[string]interface{}{"seq": 2}); err != nil {
		t.Fatalf("post-close Log: %v", err)
	}
	if got := repo.written(2); got != 1 {
		t.Errorf("a post-close event reached the repository %d times, want 1: the batch loop is "+
			"gone, so buffering it strands it", got)
	}
	if got := l.DroppedTotal(); got != 0 {
		t.Errorf("DroppedTotal = %d after a post-close Log, want 0: the event was written, not dropped", got)
	}
	if got := l.AfterCloseTotal(); got != 1 {
		t.Errorf("AfterCloseTotal = %d, want 1", got)
	}
	if got := auditBufferedCount(l); got != 0 {
		t.Errorf("post-close buffer holds %d entries, want 0: nothing will ever drain it", got)
	}

	// Close stays idempotent, and there is now nothing stranded for a further
	// Flush to find.
	if err := l.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := l.Flush(ctx); err != nil {
		t.Fatalf("post-close Flush: %v", err)
	}
	if got := repo.written(2); got != 1 {
		t.Errorf("the post-close event was written %d times, want exactly 1", got)
	}
}
