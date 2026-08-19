package service

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/repository"
)

// lockRecordingSvcDocs records whether the erasure cascade's delete ran inside
// the per-subject write lock, and under which subject hash. The embedded
// interface supplies the methods this test does not exercise; calling one would
// panic, which is the correct outcome for a cascade that started touching
// something it should not.
type lockRecordingSvcDocs struct {
	repository.ServiceDocumentRepository

	lockedSubject string
	deletedAt     string
	deletedInLock bool
	inLock        bool
}

func (r *lockRecordingSvcDocs) WithSubjectWriteLock(ctx context.Context, subjectHash string, fn func(context.Context) error) error {
	r.lockedSubject = subjectHash
	r.inLock = true
	defer func() { r.inLock = false }()
	return fn(ctx)
}

func (r *lockRecordingSvcDocs) DeleteAllForSubject(_ context.Context, subjectHash string) error {
	r.deletedAt = subjectHash
	r.deletedInLock = r.inLock
	return nil
}

// The erasure cascade's service-document delete must take the same per-subject
// write lock a Put takes.
//
// Without it the two race. Put now holds that lock across load, quota decision
// and write, so a Put that passed its check just before the delete ran commits
// its row just after: a document survives for an account that no longer exists,
// while the erasure reports success and writes an AccountErased audit row. That
// is an Art. 17 failure with a small window, which is a reason to close it
// rather than to accept it.
//
// The lock is asserted to be taken under the SAME subject hash the delete uses.
// A lock on any other key would satisfy a naive "was the lock called" check and
// serialize nothing at all.
func TestErasureDeletesServiceDocumentsUnderTheSubjectLock(t *testing.T) {
	repo := &lockRecordingSvcDocs{}
	m := newErasureMocks()
	svc := newErasureService(t, nil, m)
	svc.SetServiceDocs(repo)

	const userID = "user-lock-1"
	want := svc.svcDocPseudonym(userID)

	if err := svc.DeleteAccount(context.Background(), userID, "self", "user request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if repo.deletedAt != want {
		t.Fatalf("deleted subject %q, want %q", repo.deletedAt, want)
	}
	if !repo.deletedInLock {
		t.Error("the erasure delete ran outside the per-subject write lock, so a " +
			"concurrent Put can commit a document for an erased account")
	}
	if repo.lockedSubject != want {
		t.Errorf("locked subject %q but deleted %q; a lock on a different key "+
			"serializes nothing", repo.lockedSubject, repo.deletedAt)
	}
}

// A repository that does not implement the serialiser must still have its
// documents deleted. The lock is an upgrade, and an erasure that silently
// skipped the delete because a capability was missing would be far worse than
// the race it was added to close.
func TestErasureDeletesServiceDocumentsWithoutTheSerialiser(t *testing.T) {
	repo := &plainSvcDocs{}
	m := newErasureMocks()
	svc := newErasureService(t, nil, m)
	svc.SetServiceDocs(repo)

	const userID = "user-lock-2"
	if err := svc.DeleteAccount(context.Background(), userID, "self", "user request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if repo.deletedAt != svc.svcDocPseudonym(userID) {
		t.Errorf("deleted subject %q, want %q", repo.deletedAt, svc.svcDocPseudonym(userID))
	}
}

// plainSvcDocs deliberately does NOT implement SubjectWriteSerializer.
type plainSvcDocs struct {
	repository.ServiceDocumentRepository
	deletedAt string
}

func (r *plainSvcDocs) DeleteAllForSubject(_ context.Context, subjectHash string) error {
	r.deletedAt = subjectHash
	return nil
}
