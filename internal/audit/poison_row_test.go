package audit

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// poisonAuditRepo models the real audit table's two relevant behaviors: one
// row can be permanently unwritable, and a batch is one transaction.
//
// audit.audit_log.user_id is UUID (migrations/001_initial_schema.sql:156) while
// every caller passes a Go string, so an actor id that is not a UUID — a service
// document filed under an email address, a POST /mint subject like "user-8c1d4f"
// — is rejected with 22P02 for as long as the row exists. InsertBatch writes the
// whole slice in one transaction and returns on the first error
// (internal/repository/postgres/audit.go:41-66), so one such row takes the
// entire batch down with it and nothing is written.
type poisonAuditRepo struct {
	mu       sync.Mutex
	reject   func(*model.AuditEntry) bool
	inserted []*model.AuditEntry
}

func (p *poisonAuditRepo) rejectErr(e *model.AuditEntry) error {
	return fmt.Errorf("insert audit entries: ERROR: invalid input syntax for type uuid: %q (SQLSTATE 22P02)", e.UserID)
}

func (p *poisonAuditRepo) InsertBatch(_ context.Context, entries []*model.AuditEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range entries {
		if p.reject(e) {
			// One transaction: the offending row aborts it and NOTHING lands.
			return p.rejectErr(e)
		}
	}
	p.inserted = append(p.inserted, entries...)
	return nil
}

func (p *poisonAuditRepo) Insert(_ context.Context, e *model.AuditEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reject(e) {
		return p.rejectErr(e)
	}
	p.inserted = append(p.inserted, e)
	return nil
}

func (p *poisonAuditRepo) Query(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
	return nil, nil
}
func (p *poisonAuditRepo) CountByUser(context.Context, string) (int, error) { return 0, nil }
func (p *poisonAuditRepo) Cleanup(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (p *poisonAuditRepo) CleanupLocked(context.Context, time.Time) (int64, bool, error) {
	return 0, true, nil
}

func (p *poisonAuditRepo) storedUsers() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	users := make([]string, 0, len(p.inserted))
	for _, e := range p.inserted {
		users = append(users, e.UserID)
	}
	return users
}

// TestOneUnwritableRowDoesNotWedgeTheAuditPipeline is the regression for a
// security control that one HTTP request can switch off for the life of a pod.
//
// A rejected batch is put back at the FRONT of the buffer, so a row the store
// will never accept is retried first on every tick, forever. Everything logged
// behind it is counted into droppedTotal and thrown away, and the audit trail
// for that process never drains again. The attacker needs a single crafted
// request to reach it, and the result is silence on the one channel that would
// have recorded what they did next.
//
// The pipeline therefore has to be able to tell "the store said no to this row"
// from "the store is down", and the evidence is in the same flush: a store that
// accepted other entries is reachable, so the ones it refused are the problem
// and get quarantined rather than retried into a wedge.
func TestOneUnwritableRowDoesNotWedgeTheAuditPipeline(t *testing.T) {
	const poisonSubject = "alice@example.com"

	repo := &poisonAuditRepo{
		reject: func(e *model.AuditEntry) bool { return e.UserID == poisonSubject },
	}
	l := NewLoggerWithBufferSize(repo, time.Hour, 100)

	// The crafted request lands first, so it sits at the head of every batch.
	if err := l.Log(context.Background(), SvcDocPut, poisonSubject, "svc-evil", "10.0.0.9", "ua", "", "", nil, 0); err != nil {
		t.Fatalf("Log poison: %v", err)
	}
	// Ordinary traffic behind it.
	logSeries(t, l, "good", 4)

	// Flushed more than once on purpose: a wedge is not "this flush failed", it
	// is "no later flush can ever succeed either".
	for i := 0; i < 3; i++ {
		_ = l.Flush(context.Background()) // #nosec G104 -- the first flush is expected to report the rejection
	}

	stored := repo.storedUsers()
	if len(stored) != 4 {
		t.Fatalf("the store holds %v after three flushes, want the four good entries. One "+
			"unwritable row is retried at the head of the batch forever, so every event behind "+
			"it is lost and the audit log for this process never drains again.", stored)
	}
	for _, u := range stored {
		if !strings.HasPrefix(u, "good-") {
			t.Errorf("stored %q, which the store rejects: the isolation pass wrote a row the "+
				"store said no to", u)
		}
	}

	if got := l.QuarantinedTotal(); got != 1 {
		t.Errorf("QuarantinedTotal = %d, want 1: the row that cannot be written has to be "+
			"counted, or the pipeline recovers by silently losing records", got)
	}

	// The pipeline keeps working afterwards, which is the other half of "not
	// wedged": the quarantined row must not still be in the buffer.
	logSeries(t, l, "after", 2)
	if err := l.Flush(context.Background()); err != nil {
		t.Fatalf("Flush after the poison row was quarantined: %v", err)
	}
	if got := len(repo.storedUsers()); got != 6 {
		t.Errorf("the store holds %d entries, want 6: the quarantined row was put back and is "+
			"still blocking the batch", got)
	}
}

// TestAQuarantinedRowIsLoud is the operator half of the fix.
//
// Quarantining is still a loss of an audit record, and a security control that
// drops evidence quietly is the failure mode this whole finding is about. The
// row that could not be written has to name itself in the process log, with the
// store's own error, so the malformed actor id can be traced back to the caller
// that produced it.
func TestAQuarantinedRowIsLoud(t *testing.T) {
	var out lockedBuffer
	prev := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prev) })

	repo := &poisonAuditRepo{
		reject: func(e *model.AuditEntry) bool { return e.UserID == "not-a-uuid" },
	}
	l := NewLoggerWithBufferSize(repo, time.Hour, 100)

	if err := l.Log(context.Background(), TokenMinted, "not-a-uuid", "svc-evil", "10.0.0.9", "ua", "", "", nil, 0); err != nil {
		t.Fatalf("Log poison: %v", err)
	}
	logSeries(t, l, "good", 1)

	_ = l.Flush(context.Background()) // #nosec G104 -- the rejection is the condition under test

	logged := out.String()
	for _, want := range []string{"audit: quarantined", TokenMinted, "22P02"} {
		if !strings.Contains(logged, want) {
			t.Errorf("the process log does not mention %q after an audit row was discarded. A "+
				"record the audit trail lost and nobody was told about is the failure this fix "+
				"exists to stop. Captured output: %q", want, logged)
		}
	}
}
