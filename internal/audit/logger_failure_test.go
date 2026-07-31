package audit

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// defaultAuditBufferSize mirrors the fallback NewLoggerWithBufferSize applies to
// a non-positive size. Restated here so the test fails if the production default
// moves without the invariant being reconsidered.
const defaultAuditBufferSize = 1000

// apStarvedReader is an entropy source that has run out. crypto.RandomUUID reads
// it through io.ReadFull, so installing it makes ID generation fail the way a
// broken or exhausted CSPRNG would.
type apStarvedReader struct{}

func (apStarvedReader) Read([]byte) (int, error) { return 0, errors.New("entropy exhausted") }

// apStarveEntropy swaps the process CSPRNG for the duration of one test.
func apStarveEntropy(t *testing.T) {
	t.Helper()
	orig := rand.Reader
	rand.Reader = apStarvedReader{}
	t.Cleanup(func() { rand.Reader = orig })
}

// Every audit entry is keyed by a random UUID. If ID generation fails the entry
// has no primary key, and storing it anyway would put a row in the append-only
// log that shares its blank ID with every other failed entry, unreferenceable
// and indistinguishable from the next one. The write must be refused and the
// caller told, not attempted with an empty ID.
func TestLog_IDGenerationFailureWritesNothing(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	var written []*model.AuditEntry
	repo.InsertFn = func(_ context.Context, e *model.AuditEntry) error {
		written = append(written, e)
		return nil
	}

	l := NewLogger(repo, 0)
	apStarveEntropy(t)

	err := l.Log(context.Background(), "login_success", "user-1", "", "203.0.113.1", "curl", "", "", nil, 0)
	if err == nil {
		t.Fatal("Log reported success while it could not generate an entry ID")
	}
	if len(written) != 0 {
		t.Errorf("an entry was written despite the failed ID generation: %+v", written[0])
	}
}

// A non-positive buffer size is a misconfiguration, and the fallback is what
// keeps a stray 0 in a config file from turning the audit logger into a device
// that accepts every event and stores none: Log returns nil in batch mode, so a
// zero-capacity buffer would silently drop the entire audit trail.
func TestNewLoggerWithBufferSize_NonPositiveFallsBackToDefault(t *testing.T) {
	for _, size := range []int{0, -1} {
		repo := &mocks.MockAuditRepo{}
		l := NewLoggerWithBufferSize(repo, time.Hour, size)
		t.Cleanup(func() { _ = l.Close(context.Background()) })

		for i := 0; i < defaultAuditBufferSize; i++ {
			if err := l.Log(context.Background(), "login_failed", "user-1", "", "", "", "", "", nil, 0); err != nil {
				t.Fatalf("bufferSize %d: Log: %v", size, err)
			}
		}
		if dropped := l.DroppedTotal(); dropped != 0 {
			t.Fatalf("bufferSize %d: %d events dropped before the default capacity was reached", size, dropped)
		}

		if err := l.Log(context.Background(), "login_failed", "user-1", "", "", "", "", "", nil, 0); err != nil {
			t.Fatalf("bufferSize %d: Log: %v", size, err)
		}
		if dropped := l.DroppedTotal(); dropped != 1 {
			t.Errorf("bufferSize %d: dropped = %d past the cap, want 1", size, dropped)
		}
	}
}
