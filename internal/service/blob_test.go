package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// ---------------------------------------------------------------------------
// Mock repo for blob tests
// ---------------------------------------------------------------------------

type mockBlobRepo struct {
	createFn                  func(ctx context.Context, blob *model.Blob) error
	getByIDAndPseudonymFn     func(ctx context.Context, id, pseudonymID string) (*model.Blob, error)
	getByRefAndPseudonymFn    func(ctx context.Context, refHash, pseudonymID string) (*model.Blob, error)
	deleteByRefAndPseudonymFn func(ctx context.Context, refHash, pseudonymID string) error
	listByPseudonymFn         func(ctx context.Context, pseudonymID string) ([]*model.Blob, error)
	getQuotaFn                func(ctx context.Context, pseudonymID string) (*model.BlobQuota, error)
	deleteFn                  func(ctx context.Context, id, pseudonymID string) error
	deleteAllForPseudonymFn   func(ctx context.Context, pseudonymID string) error
}

func (m *mockBlobRepo) Create(ctx context.Context, blob *model.Blob) error {
	if m.createFn != nil {
		return m.createFn(ctx, blob)
	}
	return nil
}

func (m *mockBlobRepo) GetByIDAndPseudonym(ctx context.Context, id, pseudonymID string) (*model.Blob, error) {
	if m.getByIDAndPseudonymFn != nil {
		return m.getByIDAndPseudonymFn(ctx, id, pseudonymID)
	}
	return nil, nil
}

func (m *mockBlobRepo) GetByRefAndPseudonym(ctx context.Context, refHash, pseudonymID string) (*model.Blob, error) {
	if m.getByRefAndPseudonymFn != nil {
		return m.getByRefAndPseudonymFn(ctx, refHash, pseudonymID)
	}
	return nil, nil
}

func (m *mockBlobRepo) DeleteByRefAndPseudonym(ctx context.Context, refHash, pseudonymID string) error {
	if m.deleteByRefAndPseudonymFn != nil {
		return m.deleteByRefAndPseudonymFn(ctx, refHash, pseudonymID)
	}
	return nil
}

func (m *mockBlobRepo) ListByPseudonym(ctx context.Context, pseudonymID string) ([]*model.Blob, error) {
	if m.listByPseudonymFn != nil {
		return m.listByPseudonymFn(ctx, pseudonymID)
	}
	return nil, nil
}

func (m *mockBlobRepo) GetQuota(ctx context.Context, pseudonymID string) (*model.BlobQuota, error) {
	if m.getQuotaFn != nil {
		return m.getQuotaFn(ctx, pseudonymID)
	}
	return &model.BlobQuota{}, nil
}

func (m *mockBlobRepo) Delete(ctx context.Context, id, pseudonymID string) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id, pseudonymID)
	}
	return nil
}

func (m *mockBlobRepo) DeleteAllForPseudonym(ctx context.Context, pseudonymID string) error {
	if m.deleteAllForPseudonymFn != nil {
		return m.deleteAllForPseudonymFn(ctx, pseudonymID)
	}
	return nil
}

func defaultBlobConfig() BlobConfig {
	return BlobConfig{
		MinBlobSize:     0,
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	}
}

// ---------------------------------------------------------------------------
// Pseudonym
// ---------------------------------------------------------------------------

func TestBlobService_Pseudonym(t *testing.T) {
	svc := NewBlobService(&mockBlobRepo{}, testKey, testHMAC, defaultBlobConfig())

	p1 := svc.Pseudonym("user-1")
	p2 := svc.Pseudonym("user-2")
	p1Again := svc.Pseudonym("user-1")

	if p1 == "" {
		t.Fatal("expected non-empty pseudonym")
	}
	if p1 == p2 {
		t.Fatal("different users should have different pseudonyms")
	}
	if p1 != p1Again {
		t.Fatal("same user should always get the same pseudonym")
	}
}

func TestBlobService_PseudonymDiffersFromIdentity(t *testing.T) {
	blobSvc := NewBlobService(&mockBlobRepo{}, testKey, testHMAC, defaultBlobConfig())
	identitySvc := NewIdentityService(&mockIdentityRepo{}, testKey, testHMAC)

	blobPseudo := blobSvc.Pseudonym("user-123")
	identityPseudo := identitySvc.Pseudonym("user-123")

	if blobPseudo == identityPseudo {
		t.Fatal("blob and identity pseudonyms should differ (different HMAC inputs)")
	}
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

func TestBlobService_Upload_Success(t *testing.T) {
	var captured *model.Blob
	repo := &mockBlobRepo{
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{UsedCount: 0, UsedBytes: 0}, nil
		},
		createFn: func(_ context.Context, b *model.Blob) error {
			captured = b
			return nil
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	data := []byte("hello world test data")
	blob, err := svc.Upload(context.Background(), "user-123", data, "test-label")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if blob.ID == "" {
		t.Error("expected non-empty blob ID")
	}
	if blob.PseudonymID == "" {
		t.Error("expected non-empty pseudonym ID")
	}
	if blob.SizeBytes != len(data) {
		t.Errorf("expected SizeBytes=%d, got %d", len(data), blob.SizeBytes)
	}
	if !strings.HasPrefix(blob.Checksum, "sha256:") {
		t.Errorf("expected sha256: prefixed checksum, got %q", blob.Checksum)
	}
	if captured == nil {
		t.Fatal("expected blob to be stored")
	}
	if len(captured.DataEnc) == 0 {
		t.Error("expected non-empty encrypted data")
	}
	if len(captured.LabelEnc) == 0 {
		t.Error("expected non-empty encrypted label")
	}
}

func TestBlobService_Upload_NoLabel(t *testing.T) {
	repo := &mockBlobRepo{
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		createFn: func(_ context.Context, b *model.Blob) error {
			if len(b.LabelEnc) != 0 {
				t.Error("expected empty label_enc for no label")
			}
			return nil
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	_, err := svc.Upload(context.Background(), "user-123", []byte("data"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBlobService_Upload_TooLarge(t *testing.T) {
	svc := NewBlobService(&mockBlobRepo{}, testKey, testHMAC, BlobConfig{
		MaxBlobSize:     100,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10000,
	})

	_, err := svc.Upload(context.Background(), "user-123", make([]byte, 200), "big")
	if !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("expected ErrBlobTooLarge, got %v", err)
	}
}

func TestBlobService_Upload_TooSmall(t *testing.T) {
	svc := NewBlobService(&mockBlobRepo{}, testKey, testHMAC, BlobConfig{
		MinBlobSize:     1024,
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})

	_, err := svc.Upload(context.Background(), "user-123", []byte("tiny"), "small")
	if !errors.Is(err, ErrBlobTooSmall) {
		t.Fatalf("expected ErrBlobTooSmall, got %v", err)
	}
}

func TestBlobService_Upload_CountQuotaExceeded(t *testing.T) {
	repo := &mockBlobRepo{
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{UsedCount: 10, UsedBytes: 0}, nil
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	_, err := svc.Upload(context.Background(), "user-123", []byte("data"), "")
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected ErrQuotaExceeded, got %v", err)
	}
}

func TestBlobService_Upload_ByteQuotaExceeded(t *testing.T) {
	repo := &mockBlobRepo{
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{UsedCount: 0, UsedBytes: 10*1024*1024 - 10}, nil // almost full
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	_, err := svc.Upload(context.Background(), "user-123", []byte(strings.Repeat("x", 1024)), "")
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected ErrQuotaExceeded, got %v", err)
	}
}

func TestBlobService_Upload_QuotaCheckError(t *testing.T) {
	repo := &mockBlobRepo{
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return nil, errors.New("db error")
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	_, err := svc.Upload(context.Background(), "user-123", []byte("data"), "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBlobService_Upload_CreateError(t *testing.T) {
	repo := &mockBlobRepo{
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		createFn: func(_ context.Context, _ *model.Blob) error {
			return errors.New("db insert error")
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	_, err := svc.Upload(context.Background(), "user-123", []byte("data"), "")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

func TestBlobService_Download_Success(t *testing.T) {
	// Upload first, then download
	var stored *model.Blob
	uploadRepo := &mockBlobRepo{
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		createFn: func(_ context.Context, b *model.Blob) error {
			stored = b
			return nil
		},
	}

	svc := NewBlobService(uploadRepo, testKey, testHMAC, defaultBlobConfig())
	_, err := svc.Upload(context.Background(), "user-123", []byte("secret data"), "my-label")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	downloadRepo := &mockBlobRepo{
		getByIDAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return stored, nil
		},
	}
	svc2 := NewBlobService(downloadRepo, testKey, testHMAC, defaultBlobConfig())

	data, label, checksum, err := svc2.Download(context.Background(), "user-123", stored.ID)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if string(data) != "secret data" {
		t.Errorf("expected 'secret data', got %q", string(data))
	}
	if label != "my-label" {
		t.Errorf("expected label='my-label', got %q", label)
	}
	if !strings.HasPrefix(checksum, "sha256:") {
		t.Errorf("expected sha256: prefix, got %q", checksum)
	}
}

func TestBlobService_Download_NotFound(t *testing.T) {
	svc := NewBlobService(&mockBlobRepo{}, testKey, testHMAC, defaultBlobConfig())

	data, label, checksum, err := svc.Download(context.Background(), "user-123", "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != nil {
		t.Error("expected nil data for not-found")
	}
	if label != "" || checksum != "" {
		t.Error("expected empty label and checksum for not-found")
	}
}

func TestBlobService_Download_RepoError(t *testing.T) {
	repo := &mockBlobRepo{
		getByIDAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return nil, errors.New("db error")
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	_, _, _, err := svc.Download(context.Background(), "user-123", "blob-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestBlobService_List_Success(t *testing.T) {
	// Upload 2 blobs first to get proper encrypted data
	var blobs []*model.Blob
	uploadRepo := &mockBlobRepo{
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{UsedCount: len(blobs)}, nil
		},
		createFn: func(_ context.Context, b *model.Blob) error {
			blobs = append(blobs, b)
			return nil
		},
	}
	svc := NewBlobService(uploadRepo, testKey, testHMAC, defaultBlobConfig())
	svc.Upload(context.Background(), "user-123", []byte("data1"), "label1")
	svc.Upload(context.Background(), "user-123", []byte("data2"), "label2")

	listRepo := &mockBlobRepo{
		listByPseudonymFn: func(_ context.Context, _ string) ([]*model.Blob, error) {
			return blobs, nil
		},
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{UsedCount: 2, UsedBytes: 2000}, nil
		},
	}
	svc2 := NewBlobService(listRepo, testKey, testHMAC, defaultBlobConfig())

	metas, quota, err := svc2.List(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("expected 2 blobs, got %d", len(metas))
	}
	if metas[0].Label != "label1" {
		t.Errorf("expected label1, got %q", metas[0].Label)
	}
	if metas[1].Label != "label2" {
		t.Errorf("expected label2, got %q", metas[1].Label)
	}
	if quota.UsedCount != 2 {
		t.Errorf("expected UsedCount=2, got %d", quota.UsedCount)
	}
	if quota.MaxCount != 10 {
		t.Errorf("expected MaxCount=10, got %d", quota.MaxCount)
	}
}

func TestBlobService_List_Empty(t *testing.T) {
	repo := &mockBlobRepo{
		listByPseudonymFn: func(_ context.Context, _ string) ([]*model.Blob, error) {
			return nil, nil
		},
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	metas, quota, err := svc.List(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metas) != 0 {
		t.Errorf("expected 0 blobs, got %d", len(metas))
	}
	if quota == nil {
		t.Fatal("expected non-nil quota info")
	}
}

func TestBlobService_List_RepoError(t *testing.T) {
	repo := &mockBlobRepo{
		listByPseudonymFn: func(_ context.Context, _ string) ([]*model.Blob, error) {
			return nil, errors.New("db error")
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	_, _, err := svc.List(context.Background(), "user-123")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBlobService_List_QuotaError(t *testing.T) {
	repo := &mockBlobRepo{
		listByPseudonymFn: func(_ context.Context, _ string) ([]*model.Blob, error) {
			return nil, nil
		},
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return nil, errors.New("db error")
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	_, _, err := svc.List(context.Background(), "user-123")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestBlobService_Delete_Success(t *testing.T) {
	var deletedID, deletedPseudo string
	repo := &mockBlobRepo{
		deleteFn: func(_ context.Context, id, pseudo string) error {
			deletedID = id
			deletedPseudo = pseudo
			return nil
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	err := svc.Delete(context.Background(), "user-123", "blob-456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deletedID != "blob-456" {
		t.Errorf("expected blob-456, got %q", deletedID)
	}
	if deletedPseudo == "" {
		t.Error("expected non-empty pseudonym")
	}
}

func TestBlobService_Delete_NotFound(t *testing.T) {
	repo := &mockBlobRepo{
		deleteFn: func(_ context.Context, _, _ string) error {
			return ErrBlobNotFound
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	err := svc.Delete(context.Background(), "user-123", "nonexistent")
	if !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("expected ErrBlobNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Compression round-trip
// ---------------------------------------------------------------------------

func TestBlobService_CompressionRoundTrip(t *testing.T) {
	// Upload data that compresses well
	var stored *model.Blob
	repo := &mockBlobRepo{
		getQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		createFn: func(_ context.Context, b *model.Blob) error {
			stored = b
			return nil
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	original := []byte(strings.Repeat("compressible data pattern ", 100))
	_, err := svc.Upload(context.Background(), "user-1", original, "")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	// 2600-byte highly compressible data should compress to well under 50% of original
	if stored.StoredBytes >= len(original)/2 {
		t.Errorf("stored=%d should be less than 50%% of original=%d for compressible data", stored.StoredBytes, len(original))
	}

	// Now download and verify round-trip
	svc2 := NewBlobService(&mockBlobRepo{
		getByIDAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return stored, nil
		},
	}, testKey, testHMAC, defaultBlobConfig())

	data, _, _, err := svc2.Download(context.Background(), "user-1", stored.ID)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if string(data) != string(original) {
		t.Fatal("round-trip data mismatch")
	}
}
