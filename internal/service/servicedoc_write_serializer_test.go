package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/repository"
)

// serializingSvcDocRepo is a repository that advertises the optional
// cross-process lock. The service discovers it with a type assertion, so the
// only thing that makes this repository different from the plain fake is that
// the method exists.
type serializingSvcDocRepo struct {
	*fakeSvcDocRepo

	locked   []string
	refuse   error
	inLockOn map[string]bool
}

// svcDocLockMarker is put into the context the lock hands the closure. A real
// repository puts its transaction there; what matters to the service is that
// whatever the lock supplies is the context the closure's repository calls run
// on, so the marker stands in for the transaction.
type svcDocLockMarker struct{}

func newSerializingSvcDocRepo() *serializingSvcDocRepo {
	return &serializingSvcDocRepo{fakeSvcDocRepo: newFakeSvcDocRepo(), inLockOn: map[string]bool{}}
}

func (r *serializingSvcDocRepo) WithSubjectWriteLock(ctx context.Context, subjectHash string, fn func(context.Context) error) error {
	r.locked = append(r.locked, subjectHash)
	if r.refuse != nil {
		return r.refuse
	}
	return fn(context.WithValue(ctx, svcDocLockMarker{}, true))
}

func (r *serializingSvcDocRepo) Get(ctx context.Context, clientID, subjectHash, docKey string) (*repository.ServiceDocument, error) {
	r.inLockOn["get"] = ctx.Value(svcDocLockMarker{}) != nil
	return r.fakeSvcDocRepo.Get(ctx, clientID, subjectHash, docKey)
}

func (r *serializingSvcDocRepo) CountForOwner(ctx context.Context, clientID, subjectHash string) (int, error) {
	r.inLockOn["count"] = ctx.Value(svcDocLockMarker{}) != nil
	return r.fakeSvcDocRepo.CountForOwner(ctx, clientID, subjectHash)
}

func (r *serializingSvcDocRepo) Upsert(ctx context.Context, doc *repository.ServiceDocument) (bool, error) {
	r.inLockOn["upsert"] = ctx.Value(svcDocLockMarker{}) != nil
	return r.fakeSvcDocRepo.Upsert(ctx, doc)
}

// A quota is a rule about a set of rows, and the service enforces it by reading
// the set and then adding to it. Those stay one decision only if the repository
// that can serialize them is actually used, and used for the whole of it: the
// count, and the write it authorized, on the context the lock supplied. A
// service that took the lock and then ran the closure on its own context would
// satisfy the interface and protect nothing, because the reads would run outside
// the transaction the lock was taken in.
func TestPutRunsTheQuotaDecisionInsideTheRepositoryLock(t *testing.T) {
	repo := newSerializingSvcDocRepo()
	svc := NewDocumentService(repo, svcDocRegisteredClients(),
		svcDocMasterKey(32), svcDocHMACSecret(), defaultSvcDocConfig(), nil)

	const subject = "user-1"
	if _, _, err := svc.Put(context.Background(), svcDocClientA, subject, "prefs",
		[]byte(`{"theme":"dark"}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if len(repo.locked) != 1 {
		t.Fatalf("the repository lock was taken %d times, want exactly 1; a write outside it is a write that can breach the quota", len(repo.locked))
	}
	for _, step := range []string{"get", "count", "upsert"} {
		if !repo.inLockOn[step] {
			t.Errorf("the %s the write depends on ran outside the context the lock supplied, so it was not part of the locked transaction", step)
		}
	}

	// The lock word is the pseudonym, never the subject the caller named. The
	// argument is visible to the store, and on PostgreSQL it reaches pg_locks and
	// the statement log.
	if repo.locked[0] == subject {
		t.Error("the plaintext subject was handed to the repository as the lock word")
	}
	if want := svc.SubjectPseudonym(subject); repo.locked[0] != want {
		t.Errorf("lock word = %q, want the subject pseudonym; the lock and the rows it protects must be keyed the same way", repo.locked[0])
	}
}

// A repository that cannot take the lock has not serialized anything, so the
// write must not happen. Falling back to the unserialized path here would be the
// worst of both: the quota check would run exactly when the store is under the
// contention that makes the race likely.
func TestPutFailsWhenTheRepositoryLockIsRefused(t *testing.T) {
	repo := newSerializingSvcDocRepo()
	repo.refuse = errors.New("lock service document subject: canceling statement due to lock timeout")
	svc := NewDocumentService(repo, svcDocRegisteredClients(),
		svcDocMasterKey(32), svcDocHMACSecret(), defaultSvcDocConfig(), nil)

	meta, created, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs",
		[]byte(`{"theme":"dark"}`), repository.VisibilityPrivate)
	if err == nil {
		t.Fatal("Put reported the document stored after the subject lock was refused")
	}
	if !strings.Contains(err.Error(), "lock service document subject") {
		t.Errorf("err = %v, want the repository's own refusal", err)
	}
	if meta != nil || created {
		t.Errorf("a refused write returned meta=%+v created=%v", meta, created)
	}
	if len(repo.rows) != 0 {
		t.Errorf("%d document(s) were written without the lock", len(repo.rows))
	}
}
