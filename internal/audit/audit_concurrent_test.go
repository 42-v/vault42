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
// batch-inserted + still-buffered + DroppedTotal == submitted, and the reason
// synchronous inserts are absent from it is a genuine subtlety of this code:
// DroppedTotal counts buffer-full OCCURRENCES, and a critical event that hits a
// full buffer increments it and is then written synchronously anyway. Counting
// both would double-count exactly those events. If Log ever starts losing an
// entry outright, or starts counting one twice, this equation breaks.
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
					map[string]interface{}{"seq": seq}, 0); err != nil {
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

	if got := batched + buffered + dropped; got != submitted {
		t.Errorf("audit events went unaccounted for: batch-inserted %d + still-buffered %d + DroppedTotal %d = %d, want %d submitted",
			batched, buffered, dropped, got, submitted)
	}
	if dropped == 0 {
		t.Error("the buffer never overflowed, so the overflow branch of the accounting was never exercised")
	}

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

// TestLogger_LogAfterCloseIsBufferedIntoADeadLogger pins what the batching
// logger currently does with an event submitted after Close, which is neither
// documented nor obviously intended. The entry is appended to the buffer, Log
// reports success, DroppedTotal does not move, and the batch loop that would
// have drained it has already exited. Nothing but an explicit further Flush
// will ever write it.
//
// This is recorded here so that a change to it is a deliberate decision rather
// than an accident, and so the accounting in the storm test above has a name
// for where its residue lives. It is being pinned, not endorsed: a critical
// event submitted during shutdown teardown disappearing without a dropped count
// is a poor answer, and the right fix is a rejection or a synchronous write
// rather than a silent append. That decision is not this test's to make.
func TestLogger_LogAfterCloseIsBufferedIntoADeadLogger(t *testing.T) {
	repo := newConcurrentAuditRepo()
	// A flush interval long enough that the batch loop never ticks, so the only
	// writes are the ones this test asks for.
	l := NewLoggerWithBufferSize(repo, time.Hour, 100)
	ctx := context.Background()

	if err := l.Log(ctx, LoginFailure, "u", "", "203.0.113.9", "", "", "",
		map[string]interface{}{"seq": 1}, 0); err != nil {
		t.Fatalf("pre-close Log: %v", err)
	}
	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := repo.written(1); got != 1 {
		t.Fatalf("Close did not flush the pre-close event: written %d times, want 1", got)
	}

	if err := l.Log(ctx, LoginFailure, "u", "", "203.0.113.9", "", "", "",
		map[string]interface{}{"seq": 2}, 0); err != nil {
		t.Fatalf("post-close Log reported an error, which is a behavior change: %v", err)
	}
	if got := repo.written(2); got != 0 {
		t.Errorf("a post-close event reached the repository %d times; the batch loop is gone, so this test's premise has changed", got)
	}
	if got := l.DroppedTotal(); got != 0 {
		t.Errorf("DroppedTotal = %d after a post-close Log, want 0: the event is stranded, not counted as dropped", got)
	}
	if got := auditBufferedCount(l); got != 1 {
		t.Errorf("post-close buffer holds %d entries, want 1: the event is appended to a logger whose batch loop has exited", got)
	}

	// Close is idempotent, so it will not drain what it stranded. Only a direct
	// Flush does, which is the sole escape hatch a caller has today.
	if err := l.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := repo.written(2); got != 0 {
		t.Errorf("a second Close flushed the stranded event %d times; Close is documented as idempotent", got)
	}
	if err := l.Flush(ctx); err != nil {
		t.Fatalf("post-close Flush: %v", err)
	}
	if got := repo.written(2); got != 1 {
		t.Errorf("an explicit post-close Flush wrote the stranded event %d times, want 1", got)
	}
}
