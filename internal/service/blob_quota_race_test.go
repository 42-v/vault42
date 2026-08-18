package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
)

// arrivalBarrier holds every caller that reaches it until n have arrived or the
// wait times out.
//
// It is what makes the TOCTOU deterministic in both directions. With the quota
// decision unserialised all n uploaders reach the quota read together, the
// barrier releases immediately, and every one of them reads the same
// pre-write total. With the decision serialized only one can be inside at a
// time, so the barrier never fills, each uploader pays the timeout, and the
// second one reads the total the first produced. No sleeps in the test body and
// no dependence on the scheduler.
func arrivalBarrier(n int, timeout time.Duration) func() {
	var (
		mu      sync.Mutex
		arrived int
		full    = make(chan struct{})
		closed  bool
	)
	return func() {
		mu.Lock()
		arrived++
		if arrived >= n && !closed {
			closed = true
			close(full)
		}
		mu.Unlock()

		select {
		case <-full:
		case <-time.After(timeout):
		}
	}
}

// TestConcurrentUploadsCannotAllPassOneQuotaRead is the blob store's half of a
// bug the document store already fixed.
//
// GetQuota and Create are separated by compression and encryption with no
// transaction, no SELECT ... FOR UPDATE and no advisory lock, and there is no
// aggregate constraint on objects.blobs to catch what gets through. N concurrent
// uploads therefore each read the pre-write total, each decide they fit, and
// each land. The per-IP limiter is the only bound, so the overshoot is up to ten
// times the maximum blob size per IP per minute, and it recurs every minute
// because each batch races against a stale total.
//
// The document store closed exactly this with a per-subject write lock around
// load-decide-write (WithSubjectWriteLock, pinned by
// tests/attack/atk_api_svcdoc_quota_test.go). This is the same fix keyed on the
// blob owner's pseudonym.
func TestConcurrentUploadsCannotAllPassOneQuotaRead(t *testing.T) {
	const uploaders = 8

	repo := &statefulBlobRepo{beforeQuotaRead: arrivalBarrier(uploaders, 50*time.Millisecond)}
	cfg := BlobConfig{MaxBlobSize: 1 << 20, MaxBlobsPerUser: 1, QuotaBytes: 1 << 20}
	svc := NewBlobService(repo, testKey, testHMAC, cfg)

	var wg sync.WaitGroup
	errs := make([]error, uploaders)
	for i := 0; i < uploaders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.Upload(context.Background(), "user-1", []byte("payload"), "")
		}(i)
	}
	wg.Wait()

	accepted := 0
	for _, err := range errs {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrQuotaExceeded):
		default:
			t.Fatalf("unexpected upload error: %v", err)
		}
	}

	if accepted != cfg.MaxBlobsPerUser {
		t.Errorf("%d of %d concurrent uploads were accepted against a cap of %d. Every one of "+
			"them read the same pre-write total and decided it had room, so the quota bounds a "+
			"sequential caller and nothing else.", accepted, uploaders, cfg.MaxBlobsPerUser)
	}
	if got := repo.count(); got != cfg.MaxBlobsPerUser {
		t.Errorf("the store holds %d blobs against a cap of %d", got, cfg.MaxBlobsPerUser)
	}
}

// lockingBlobRepo is a blob repository that can also serialize a write section
// across processes, the way the document repository does with
// pg_advisory_xact_lock. The in-process stripe alone only orders the goroutines
// of one pod.
type lockingBlobRepo struct {
	*statefulBlobRepo
	mu          sync.Mutex
	keys        []string
	depth       int
	createsHeld int
	held        bool
}

func (r *lockingBlobRepo) Create(ctx context.Context, blob *model.Blob) error {
	r.mu.Lock()
	if r.held {
		r.createsHeld++
	}
	r.mu.Unlock()
	return r.statefulBlobRepo.Create(ctx, blob)
}

func (r *lockingBlobRepo) WithSubjectWriteLock(ctx context.Context, subjectHash string, fn func(context.Context) error) error {
	r.mu.Lock()
	r.keys = append(r.keys, subjectHash)
	r.depth++
	r.held = true
	r.mu.Unlock()

	err := fn(ctx)

	r.mu.Lock()
	r.held = false
	r.mu.Unlock()
	return err
}

// TestBlobWritesUseTheRepositoryLockWhenTheStoreOffersOne pins the seam.
//
// The in-process stripe orders the goroutines of one pod and nothing else, so
// with three replicas the quota is still check-then-act across the fleet. The
// service therefore asks the repository for a cross-process lock exactly the way
// the document service does, and uses it when the repository offers one. A
// PostgreSQL blob repository that grows a WithSubjectWriteLock method is picked
// up here with no further change.
func TestBlobWritesUseTheRepositoryLockWhenTheStoreOffersOne(t *testing.T) {
	repo := &lockingBlobRepo{statefulBlobRepo: &statefulBlobRepo{}}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	if _, err := svc.Upload(context.Background(), "user-1", []byte("payload"), ""); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if repo.depth != 1 {
		t.Fatalf("the repository lock was taken %d times, want once per write", repo.depth)
	}
	if repo.createsHeld != 1 {
		t.Errorf("%d of the writes happened inside the repository lock, want 1: a lock the write "+
			"does not run inside serializes nothing", repo.createsHeld)
	}
	if want := svc.Pseudonym("user-1"); repo.keys[0] != want {
		t.Errorf("locked on %q, want the owner pseudonym %q: a lock on any other key does not "+
			"serialize the writers that share a quota", repo.keys[0], want)
	}
}
