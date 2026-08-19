package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// Test helpers for blob
// ---------------------------------------------------------------------------

func newTestBlobService(repo *mocks.MockBlobRepo) *service.BlobService {
	return service.NewBlobService(repo, identityMasterKey(), identityHMACSecret(), service.BlobConfig{
		MinBlobSize:     0, // no min for tests by default
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})
}

func newTestBlobHandler(repo *mocks.MockBlobRepo) *BlobHandler {
	svc := newTestBlobService(repo)
	return NewBlobHandler(svc, newTestAuditLogger(), 0, 1024*1024)
}

func newTestBlobHandlerWithMinSize(repo *mocks.MockBlobRepo, minSize int) *BlobHandler {
	svc := service.NewBlobService(repo, identityMasterKey(), identityHMACSecret(), service.BlobConfig{
		MinBlobSize:     minSize,
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})
	return NewBlobHandler(svc, newTestAuditLogger(), minSize, 1024*1024)
}

// ---------------------------------------------------------------------------
// Upload - raw body
// ---------------------------------------------------------------------------

func TestBlobUpload_RawSuccess(t *testing.T) {
	var created bool
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{UsedCount: 0, UsedBytes: 0}, nil
		},
		CreateFn: func(_ context.Context, b *model.Blob) error {
			created = true
			if b.PseudonymID == "" {
				t.Error("expected non-empty pseudonym ID")
			}
			if len(b.DataEnc) == 0 {
				t.Error("expected non-empty encrypted data")
			}
			return nil
		},
	}
	h := newTestBlobHandler(repo)

	data := strings.Repeat("x", 1024)
	req := httptest.NewRequest(http.MethodPost, "/user/blobs", strings.NewReader(data))
	req.Header.Set("X-Blob-Label", "test-file")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if !created {
		t.Error("expected blob to be created")
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["id"] == nil || result["id"] == "" {
		t.Error("expected non-empty blob ID in response")
	}
	if result["checksum"] == nil || result["checksum"] == "" {
		t.Error("expected checksum in response")
	}
}

// ---------------------------------------------------------------------------
// Upload - multipart
// ---------------------------------------------------------------------------

func TestBlobUpload_MultipartSuccess(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	h := newTestBlobHandler(repo)

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("file", "test.bin")
	fw.Write([]byte(strings.Repeat("y", 512)))
	w.WriteField("label", "my-file")
	w.Close()

	req := httptest.NewRequest(http.MethodPost, "/user/blobs", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Upload - errors
// ---------------------------------------------------------------------------

func TestBlobUpload_Unauthorized(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodPost, "/user/blobs", strings.NewReader("data"))
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBlobUpload_EmptyBody(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodPost, "/user/blobs", strings.NewReader(""))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBlobUpload_TooSmall(t *testing.T) {
	repo := &mocks.MockBlobRepo{}
	h := newTestBlobHandlerWithMinSize(repo, 1024) // 1KB min

	req := httptest.NewRequest(http.MethodPost, "/user/blobs", strings.NewReader("tiny"))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["error"] != "blob_too_small" {
		t.Fatalf("expected blob_too_small error, got %v", result["error"])
	}
}

func TestBlobUpload_QuotaExceeded(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{UsedCount: 10, UsedBytes: 10 * 1024 * 1024}, nil
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodPost, "/user/blobs", strings.NewReader(strings.Repeat("x", 1024)))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBlobUpload_DBError(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error {
			return errors.New("db insert error")
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodPost, "/user/blobs", strings.NewReader(strings.Repeat("x", 1024)))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestBlobList_Success(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		ListByPseudonymFn: func(_ context.Context, _ string) ([]*model.Blob, error) {
			return []*model.Blob{
				{ID: "blob-1", SizeBytes: 1024, StoredBytes: 800, Checksum: "sha256:abc", CreatedAt: time.Now()},
				{ID: "blob-2", SizeBytes: 2048, StoredBytes: 1600, Checksum: "sha256:def", CreatedAt: time.Now()},
			}, nil
		},
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{UsedCount: 2, UsedBytes: 2400}, nil
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/user/blobs", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	blobs, ok := result["blobs"].([]interface{})
	if !ok {
		t.Fatal("expected blobs array")
	}
	if len(blobs) != 2 {
		t.Fatalf("expected 2 blobs, got %d", len(blobs))
	}
	// total is the standard list-envelope key; count is the pre-1.0.0 name the
	// published Vue SDK reads and is kept until the next major version. Both
	// must be present and must agree.
	total, ok := result["total"].(float64)
	if !ok {
		t.Fatalf("expected a total key in the list envelope, got %v", result)
	}
	if total != 2 {
		t.Fatalf("expected total=2, got %v", total)
	}
	count, ok := result["count"].(float64)
	if !ok {
		t.Fatalf("the deprecated count alias is gone, which breaks the published SDK: %v", result)
	}
	if count != total {
		t.Fatalf("count=%v disagrees with total=%v", count, total)
	}
}

func TestBlobList_Empty(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		ListByPseudonymFn: func(_ context.Context, _ string) ([]*model.Blob, error) {
			return nil, nil
		},
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/user/blobs", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBlobList_Unauthorized(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodGet, "/user/blobs", nil)
	rec := httptest.NewRecorder()

	h.List(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBlobList_DBError(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		ListByPseudonymFn: func(_ context.Context, _ string) ([]*model.Blob, error) {
			return nil, errors.New("db error")
		},
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/user/blobs", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.List(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

func TestBlobDownload_Success(t *testing.T) {
	// We need a properly encrypted + compressed blob
	svc := service.NewBlobService(&mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}, identityMasterKey(), identityHMACSecret(), service.BlobConfig{
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})

	// Upload via service to get properly encrypted blob
	blob, err := svc.Upload(context.Background(), "user-123", []byte("hello world test data"), "test-label")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	repo := &mocks.MockBlobRepo{
		GetByIDAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return blob, nil
		},
	}

	downloadSvc := service.NewBlobService(repo, identityMasterKey(), identityHMACSecret(), service.BlobConfig{
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})
	h := NewBlobHandler(downloadSvc, newTestAuditLogger(), 0, 1024*1024)

	req := httptest.NewRequest(http.MethodGet, "/user/blobs/"+blob.ID, nil)
	req.SetPathValue("id", blob.ID)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Download(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if rec.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("expected Content-Type=application/octet-stream, got %q", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("X-Blob-Checksum") == "" {
		t.Fatal("expected non-empty X-Blob-Checksum header")
	}
	if rec.Header().Get("X-Blob-Label") != "test-label" {
		t.Fatalf("expected X-Blob-Label=test-label, got %q", rec.Header().Get("X-Blob-Label"))
	}
	if rec.Body.String() != "hello world test data" {
		t.Fatalf("expected original data, got %q", rec.Body.String())
	}
}

func TestBlobDownload_NotFound(t *testing.T) {
	repo := &mocks.MockBlobRepo{} // default returns nil, nil
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/user/blobs/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Download(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBlobDownload_MissingID(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodGet, "/user/blobs/", nil)
	// No path value set
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Download(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBlobDownload_Unauthorized(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodGet, "/user/blobs/some-id", nil)
	req.SetPathValue("id", "some-id")
	rec := httptest.NewRecorder()

	h.Download(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBlobDownload_DBError(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetByIDAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return nil, errors.New("db error")
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/user/blobs/blob-123", nil)
	req.SetPathValue("id", "blob-123")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Download(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestBlobDelete_Success(t *testing.T) {
	var deleted bool
	repo := &mocks.MockBlobRepo{
		DeleteFn: func(_ context.Context, id, _ string) error {
			deleted = true
			if id != "blob-456" {
				t.Errorf("expected blob-456, got %q", id)
			}
			return nil
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodDelete, "/user/blobs/blob-456", nil)
	req.SetPathValue("id", "blob-456")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !deleted {
		t.Error("expected delete to be called")
	}
}

func TestBlobDelete_NotFound(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		DeleteFn: func(_ context.Context, _, _ string) error {
			return fmt.Errorf("blob not found")
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodDelete, "/user/blobs/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBlobDelete_MissingID(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodDelete, "/user/blobs/", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBlobDelete_Unauthorized(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodDelete, "/user/blobs/blob-123", nil)
	req.SetPathValue("id", "blob-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBlobDelete_DBError(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		DeleteFn: func(_ context.Context, _, _ string) error {
			return errors.New("db error")
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodDelete, "/user/blobs/blob-123", nil)
	req.SetPathValue("id", "blob-123")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestBlobUpload_MultipartMissingFile(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("label", "test") // no file field
	w.Close()

	req := httptest.NewRequest(http.MethodPost, "/user/blobs", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["error"] != "missing_file" {
		t.Fatalf("expected missing_file error, got %v", result["error"])
	}
}

func TestBlobUpload_MultipartTooLarge(t *testing.T) {
	repo := &mocks.MockBlobRepo{}
	// Create handler with very small max
	svc := service.NewBlobService(repo, identityMasterKey(), identityHMACSecret(), service.BlobConfig{
		MaxBlobSize:     10, // 10 bytes max
		MaxBlobsPerUser: 10,
		QuotaBytes:      100,
	})
	h := NewBlobHandler(svc, newTestAuditLogger(), 0, 10)

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("file", "big.bin")
	fw.Write([]byte(strings.Repeat("x", 1000))) // way over 10 bytes
	w.Close()

	req := httptest.NewRequest(http.MethodPost, "/user/blobs", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	// Should get 413 or 400 (multipart parse or blob_too_large)
	if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 413 or 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBlobUpload_ServiceBlobTooSmall(t *testing.T) {
	// Test the service-layer minimum size check
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
	}
	svc := service.NewBlobService(repo, identityMasterKey(), identityHMACSecret(), service.BlobConfig{
		MinBlobSize:     1024,
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})
	h := NewBlobHandler(svc, newTestAuditLogger(), 1024, 1024*1024)

	// Data is below handler min check too, but let's test with data that passes handler but fails service
	data := strings.Repeat("x", 500) // below 1024 min
	req := httptest.NewRequest(http.MethodPost, "/user/blobs", strings.NewReader(data))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBlobUpload_LabelTruncation(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	h := newTestBlobHandler(repo)

	longLabel := strings.Repeat("L", 300) // over 255 limit
	data := strings.Repeat("x", 1024)
	req := httptest.NewRequest(http.MethodPost, "/user/blobs", strings.NewReader(data))
	req.Header.Set("X-Blob-Label", longLabel)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestBlobDeleteNamed_Table covers DeleteNamed paths (auth, missing name, not found, success, repo err).
func TestBlobDeleteNamed_Table(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		path      string
		setup     func(*mocks.MockBlobRepo)
		setClaims bool
		nameParam string // if non-empty, SetPathValue("name", nameParam) to populate for handler
		wantCode  int
		wantErr   string
	}{
		{
			name:      "unauth",
			method:    http.MethodDelete,
			path:      "/user/blobs/named/foo",
			setClaims: false,
			nameParam: "foo",
			wantCode:  http.StatusUnauthorized,
			wantErr:   "unauthorized",
		},
		{
			name:      "missing name",
			method:    http.MethodDelete,
			path:      "/user/blobs/named/",
			setClaims: true,
			// nameParam empty => no SetPathValue => handler sees "" => missing_name
			wantCode: http.StatusBadRequest,
			wantErr:  "missing_name",
		},
		{
			name:   "repo not found",
			method: http.MethodDelete,
			path:   "/user/blobs/named/missing",
			setup: func(m *mocks.MockBlobRepo) {
				m.DeleteByRefAndPseudonymFn = func(context.Context, string, string) error {
					return errors.New("blob not found")
				}
			},
			setClaims: true,
			nameParam: "missing",
			wantCode:  http.StatusNotFound,
			wantErr:   "blob_not_found",
		},
		{
			name:   "repo other err",
			method: http.MethodDelete,
			path:   "/user/blobs/named/x",
			setup: func(m *mocks.MockBlobRepo) {
				m.DeleteByRefAndPseudonymFn = func(context.Context, string, string) error {
					return errors.New("db boom")
				}
			},
			setClaims: true,
			nameParam: "x",
			wantCode:  http.StatusInternalServerError,
			wantErr:   "internal_error",
		},
		{
			name:   "success",
			method: http.MethodDelete,
			path:   "/user/blobs/named/myref",
			setup: func(m *mocks.MockBlobRepo) {
				m.DeleteByRefAndPseudonymFn = func(context.Context, string, string) error { return nil }
			},
			setClaims: true,
			nameParam: "myref",
			wantCode:  http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mocks.MockBlobRepo{}
			if tt.setup != nil {
				tt.setup(repo)
			}
			h := newTestBlobHandler(repo)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.setClaims {
				req = setAuthContext(req, "u-1")
			}
			if tt.nameParam != "" {
				req.SetPathValue("name", tt.nameParam)
			}
			rec := httptest.NewRecorder()

			h.DeleteNamed(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("code=%d want=%d body=%s", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantErr != "" {
				var m map[string]string
				_ = json.Unmarshal(rec.Body.Bytes(), &m) // ignore err for test decode
				if m["error"] != tt.wantErr {
					t.Errorf("error=%q want=%q", m["error"], tt.wantErr)
				}
			}
		})
	}
}
