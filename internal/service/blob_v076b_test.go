package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// UploadNamed deletes any existing same-name blob, then stores a named replacement.
func TestBlobService_UploadNamed_Replaces(t *testing.T) {
	var deletedRef string
	var stored *model.Blob
	repo := &mockBlobRepo{
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		deleteByRefAndPseudonymFn: func(_ context.Context, refHash, _ string) error {
			deletedRef = refHash
			return nil
		},
		createFn: func(_ context.Context, b *model.Blob) error {
			stored = b
			return nil
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	blob, err := svc.UploadNamed(context.Background(), "user-1", []byte("named payload"), "config.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deletedRef == "" {
		t.Error("named upload should delete any existing blob with the same ref first")
	}
	if stored == nil || stored.RefHash == "" {
		t.Fatal("named blob should be stored with a non-empty RefHash")
	}
	if blob.RefHash != deletedRef {
		t.Errorf("stored RefHash %q should match the pre-delete ref %q", blob.RefHash, deletedRef)
	}
}

// DownloadNamed round-trips a named blob created via UploadNamed.
func TestBlobService_DownloadNamed_Success(t *testing.T) {
	var stored *model.Blob
	upRepo := &mockBlobRepo{
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		createFn: func(_ context.Context, b *model.Blob) error {
			stored = b
			return nil
		},
	}
	svc := NewBlobService(upRepo, testKey, testHMAC, defaultBlobConfig())
	if _, err := svc.UploadNamed(context.Background(), "user-1", []byte("named secret"), "doc.txt"); err != nil {
		t.Fatalf("upload-named: %v", err)
	}

	dlRepo := &mockBlobRepo{
		getByRefAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return stored, nil
		},
	}
	svc2 := NewBlobService(dlRepo, testKey, testHMAC, defaultBlobConfig())

	data, label, checksum, err := svc2.DownloadNamed(context.Background(), "user-1", "doc.txt")
	if err != nil {
		t.Fatalf("download-named: %v", err)
	}
	if string(data) != "named secret" {
		t.Errorf("expected round-tripped payload, got %q", string(data))
	}
	if label != "doc.txt" {
		t.Errorf("named blob label should equal its name, got %q", label)
	}
	if checksum == "" {
		t.Error("expected a non-empty checksum")
	}
}

// DownloadNamed wraps a repository lookup error.
func TestBlobService_DownloadNamed_RepoError(t *testing.T) {
	repo := &mockBlobRepo{
		getByRefAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return nil, errors.New("db down")
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	if _, _, _, err := svc.DownloadNamed(context.Background(), "user-1", "x"); err == nil {
		t.Fatal("expected a wrapped repo error")
	}
}

// DownloadNamed for an absent name yields empty results without error.
func TestBlobService_DownloadNamed_NotFound(t *testing.T) {
	svc := NewBlobService(&mockBlobRepo{}, testKey, testHMAC, defaultBlobConfig())

	data, label, checksum, err := svc.DownloadNamed(context.Background(), "user-1", "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != nil || label != "" || checksum != "" {
		t.Error("absent named blob should return empty results")
	}
}
