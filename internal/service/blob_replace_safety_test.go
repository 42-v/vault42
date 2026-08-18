package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// statefulBlobRepo is a working blob store rather than a set of stubs.
//
// The defect under test is an ordering defect: what matters is what is left in
// the store after a rejected upload, which a repository built from per-call
// function hooks cannot answer. This one holds rows, so a test can delete from
// it, read back through the real decrypt path, and see whether the user's data
// is still there.
type statefulBlobRepo struct {
	mu    sync.Mutex
	blobs []*model.Blob

	// beforeQuotaRead runs inside GetQuota, before the totals are computed. The
	// concurrency test uses it to hold every uploader at the moment they read
	// the quota, which is the window a check-then-act quota leaves open.
	beforeQuotaRead func()
	// createErr fails the NEXT Create and then clears itself. It models the
	// process losing one write after the old row has already been deleted, so a
	// compensating write that follows is still allowed to land.
	createErr error
}

func (s *statefulBlobRepo) Create(_ context.Context, blob *model.Blob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createErr != nil {
		err := s.createErr
		s.createErr = nil
		return err
	}
	cp := *blob
	s.blobs = append(s.blobs, &cp)
	return nil
}

func (s *statefulBlobRepo) GetByIDAndPseudonym(_ context.Context, id, pseudonymID string) (*model.Blob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.blobs {
		if b.ID == id && b.PseudonymID == pseudonymID {
			return b, nil
		}
	}
	return nil, nil
}

func (s *statefulBlobRepo) GetByRefAndPseudonym(_ context.Context, refHash, pseudonymID string) (*model.Blob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.blobs {
		if b.RefHash == refHash && b.PseudonymID == pseudonymID {
			return b, nil
		}
	}
	return nil, nil
}

func (s *statefulBlobRepo) DeleteByRefAndPseudonym(_ context.Context, refHash, pseudonymID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.blobs[:0]
	for _, b := range s.blobs {
		if b.RefHash == refHash && b.PseudonymID == pseudonymID {
			continue
		}
		kept = append(kept, b)
	}
	s.blobs = kept
	return nil
}

func (s *statefulBlobRepo) ListByPseudonym(_ context.Context, pseudonymID string) ([]*model.Blob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*model.Blob
	for _, b := range s.blobs {
		if b.PseudonymID == pseudonymID {
			out = append(out, b)
		}
	}
	return out, nil
}

func (s *statefulBlobRepo) GetQuota(_ context.Context, pseudonymID string) (*model.BlobQuota, error) {
	if s.beforeQuotaRead != nil {
		s.beforeQuotaRead()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	q := &model.BlobQuota{}
	for _, b := range s.blobs {
		if b.PseudonymID == pseudonymID {
			q.UsedCount++
			q.UsedBytes += b.StoredBytes
		}
	}
	return q, nil
}

func (s *statefulBlobRepo) Delete(_ context.Context, id, pseudonymID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.blobs[:0]
	for _, b := range s.blobs {
		if b.ID == id && b.PseudonymID == pseudonymID {
			continue
		}
		kept = append(kept, b)
	}
	s.blobs = kept
	return nil
}

func (s *statefulBlobRepo) DeleteAllForPseudonym(_ context.Context, pseudonymID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.blobs[:0]
	for _, b := range s.blobs {
		if b.PseudonymID == pseudonymID {
			continue
		}
		kept = append(kept, b)
	}
	s.blobs = kept
	return nil
}

func (s *statefulBlobRepo) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.blobs)
}

// incompressible returns n bytes deflate cannot shrink, so a test can size an
// upload against a byte quota without guessing at the compressor.
func incompressible(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// TestUploadNamedQuotaRejectionLeavesTheExistingBlobIntact is the regression for
// silent, unrecoverable user-data loss behind an error that reads as harmless.
//
// UploadNamed deleted the existing row BEFORE the quota was checked, under a
// comment explaining that a replacement should not be charged twice. So a
// replacement that was then refused had already destroyed the blob it was
// replacing: the user sent an oversized backup, got back "409 quota_exceeded",
// and their previous backup was gone. Nothing in the response says data was
// destroyed, and there is no second copy — the bytes only ever existed in this
// store, encrypted under a key the user cannot use to recover them from
// anywhere else.
//
// The discount the delete was there to provide is arithmetic, not an
// operation: the row being replaced is subtracted from the totals, and nothing
// is deleted until the replacement is about to land.
func TestUploadNamedQuotaRejectionLeavesTheExistingBlobIntact(t *testing.T) {
	repo := &statefulBlobRepo{}

	original := []byte("the only copy of alice's backup")
	roomy := BlobConfig{MaxBlobSize: 1 << 20, MaxBlobsPerUser: 10, QuotaBytes: 1 << 20}
	if _, err := NewBlobService(repo, testKey, testHMAC, roomy).
		UploadNamed(context.Background(), "user-1", original, "backup"); err != nil {
		t.Fatalf("seed the original: %v", err)
	}

	// The same store, now with a byte budget the replacement cannot fit in.
	tight := BlobConfig{MaxBlobSize: 1 << 20, MaxBlobsPerUser: 10, QuotaBytes: 4096}
	svc := NewBlobService(repo, testKey, testHMAC, tight)

	_, err := svc.UploadNamed(context.Background(), "user-1", incompressible(t, 8192), "backup")
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("replacement error = %v, want ErrQuotaExceeded", err)
	}

	got, _, _, err := svc.DownloadNamed(context.Background(), "user-1", "backup")
	if err != nil {
		t.Fatalf("reading the original back after a refused replacement: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("after a replacement was refused for quota the stored blob is %q, want %q. The "+
			"refusal destroyed the data it refused to replace, and the caller was told only that "+
			"they were over quota.", got, original)
	}
}

// TestUploadNamedRestoresTheReplacedBlobWhenTheWriteFails is the rest of the
// window.
//
// Ordering the quota check first leaves exactly one step that can still fail
// after the old row is gone: the insert of the new one. The replacement is
// therefore compensated — the row that was deleted is put back — so a failed
// write leaves the store as it was rather than empty.
func TestUploadNamedRestoresTheReplacedBlobWhenTheWriteFails(t *testing.T) {
	repo := &statefulBlobRepo{}
	cfg := BlobConfig{MaxBlobSize: 1 << 20, MaxBlobsPerUser: 10, QuotaBytes: 1 << 20}
	svc := NewBlobService(repo, testKey, testHMAC, cfg)

	original := []byte("alice's only backup")
	if _, err := svc.UploadNamed(context.Background(), "user-1", original, "backup"); err != nil {
		t.Fatalf("seed the original: %v", err)
	}

	repo.createErr = errors.New("connection reset by peer")
	if _, err := svc.UploadNamed(context.Background(), "user-1", []byte("the replacement"), "backup"); err == nil {
		t.Fatal("UploadNamed reported success while the store refused the write")
	}
	got, _, _, err := svc.DownloadNamed(context.Background(), "user-1", "backup")
	if err != nil {
		t.Fatalf("reading the original back after a failed replacement: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("the store holds %q after a failed replacement, want the original %q", got, original)
	}
}

// failingRestoreRepo lets the compensating write fail too, which is the point at
// which the loss is real and the process log is the only place it can be
// recorded.
type failingRestoreRepo struct {
	*statefulBlobRepo
	creates int
}

func (f *failingRestoreRepo) Create(ctx context.Context, blob *model.Blob) error {
	f.creates++
	if f.creates > 1 {
		return errors.New("store unavailable")
	}
	return f.statefulBlobRepo.Create(ctx, blob)
}

// TestUploadNamedReportsARestoreItCouldNotComplete keeps the last failure loud.
//
// If the compensating write fails as well the blob really is gone, and the
// caller is about to be told only that their upload failed. That is the one
// case where the store cannot repair itself, so it has to say so where an
// operator will find it.
func TestUploadNamedReportsARestoreItCouldNotComplete(t *testing.T) {
	var out logCapture
	prev := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prev) })

	base := &statefulBlobRepo{}
	repo := &failingRestoreRepo{statefulBlobRepo: base}
	cfg := BlobConfig{MaxBlobSize: 1 << 20, MaxBlobsPerUser: 10, QuotaBytes: 1 << 20}
	svc := NewBlobService(repo, testKey, testHMAC, cfg)

	if _, err := svc.UploadNamed(context.Background(), "user-1", []byte("original"), "backup"); err != nil {
		t.Fatalf("seed the original: %v", err)
	}

	if _, err := svc.UploadNamed(context.Background(), "user-1", []byte("replacement"), "backup"); err == nil {
		t.Fatal("UploadNamed reported success while the store refused both the write and the restore")
	}
	if got := base.count(); got != 0 {
		t.Fatalf("store holds %d blobs, want 0: the test did not reach the failed-restore path", got)
	}
	if logged := out.String(); !strings.Contains(logged, "blob: FAILED to restore") {
		t.Errorf("a replaced blob was deleted, the replacement failed, the restore failed too, and "+
			"nothing said so. Captured output: %q", logged)
	}
}

// logCapture collects process log output for a test that asserts on it.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// TestUploadNamedFailsClosedWhenTheReplacedRowCannotBeRead pins the direction
// the new lookup fails in.
//
// The row being replaced is what the quota discount is computed from, so a
// lookup that errors leaves the service unable to say whether the upload fits.
// Carrying on would either charge the replacement twice or, worse, delete a row
// it never managed to read. It refuses instead, and it refuses before anything
// has been removed.
func TestUploadNamedFailsClosedWhenTheReplacedRowCannotBeRead(t *testing.T) {
	deleted := false
	repo := &mockBlobRepo{
		getByRefAndPseudonymFn: func(context.Context, string, string) (*model.Blob, error) {
			return nil, errors.New("connection refused")
		},
		deleteByRefAndPseudonymFn: func(context.Context, string, string) error {
			deleted = true
			return nil
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	if _, err := svc.UploadNamed(context.Background(), "user-1", []byte("payload"), "backup"); err == nil {
		t.Fatal("UploadNamed reported success while it could not read the row it would replace")
	}
	if deleted {
		t.Error("the existing blob was deleted on a path that never established what it was")
	}
}
