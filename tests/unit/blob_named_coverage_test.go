package unit_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

func TestBlobHandler_UploadNamed_NameTooLong(t *testing.T) {
	repo := &mocks.MockBlobRepo{}
	h := newBlobTestHandler(repo, 0, 1024*1024)
	longName := strings.Repeat("n", 256)

	req, w, keys := authedRequest(t, http.MethodPut, "/user/blobs/named/"+longName, nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader("data")}
	req.ContentLength = 4
	serveWithAuth(t, "PUT /user/blobs/named/{name}", h.UploadNamed, keys, w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 name_too_long, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBlobHandler_UploadNamed_EmptyBody(t *testing.T) {
	repo := &mocks.MockBlobRepo{}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	req, w, keys := authedRequest(t, http.MethodPut, "/user/blobs/named/foo", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader("")}
	req.ContentLength = 0
	serveWithAuth(t, "PUT /user/blobs/named/{name}", h.UploadNamed, keys, w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 empty_blob, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBlobHandler_UploadNamed_TooSmall(t *testing.T) {
	repo := &mocks.MockBlobRepo{}
	h := newBlobTestHandler(repo, 64, 1024*1024)

	body := strings.Repeat("x", 16)
	req, w, keys := authedRequest(t, http.MethodPut, "/user/blobs/named/tiny", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(body)}
	req.ContentLength = int64(len(body))
	serveWithAuth(t, "PUT /user/blobs/named/{name}", h.UploadNamed, keys, w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 blob_too_small, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBlobHandler_UploadNamed_Success(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	body := strings.Repeat("x", 128)
	req, w, keys := authedRequest(t, http.MethodPut, "/user/blobs/named/photo-png", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(body)}
	req.ContentLength = int64(len(body))
	serveWithAuth(t, "PUT /user/blobs/named/{name}", h.UploadNamed, keys, w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBlobHandler_DownloadNamed_NoClaims401(t *testing.T) {
	h := &handler.BlobHandler{}
	req := httptest.NewRequest(http.MethodGet, "/user/blobs/named/x", nil)
	rec := httptest.NewRecorder()
	h.DownloadNamed(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBlobHandler_DownloadNamed_NotFound(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetByRefAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return nil, nil
		},
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	req, w, keys := authedRequest(t, http.MethodGet, "/user/blobs/named/missing", nil)
	serveWithAuth(t, "GET /user/blobs/named/{name}", h.DownloadNamed, keys, w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBlobHandler_DownloadNamed_InternalError(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetByRefAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return nil, errors.New("db boom")
		},
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	req, w, keys := authedRequest(t, http.MethodGet, "/user/blobs/named/x", nil)
	serveWithAuth(t, "GET /user/blobs/named/{name}", h.DownloadNamed, keys, w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBlobHandler_DeleteNamed_NoClaims401(t *testing.T) {
	h := &handler.BlobHandler{}
	req := httptest.NewRequest(http.MethodDelete, "/user/blobs/named/x", nil)
	rec := httptest.NewRecorder()
	h.DeleteNamed(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBlobHandler_DeleteNamed_NotFound(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		DeleteByRefAndPseudonymFn: func(_ context.Context, _, _ string) error {
			return errors.New("blob not found")
		},
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	req, w, keys := authedRequest(t, http.MethodDelete, "/user/blobs/named/missing", nil)
	serveWithAuth(t, "DELETE /user/blobs/named/{name}", h.DeleteNamed, keys, w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBlobHandler_DeleteNamed_InternalError(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		DeleteByRefAndPseudonymFn: func(_ context.Context, _, _ string) error {
			return errors.New("db boom")
		},
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	req, w, keys := authedRequest(t, http.MethodDelete, "/user/blobs/named/x", nil)
	serveWithAuth(t, "DELETE /user/blobs/named/{name}", h.DeleteNamed, keys, w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBlobHandler_DeleteNamed_Success(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		DeleteByRefAndPseudonymFn: func(_ context.Context, _, _ string) error { return nil },
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	req, w, keys := authedRequest(t, http.MethodDelete, "/user/blobs/named/photo.png", nil)
	serveWithAuth(t, "DELETE /user/blobs/named/{name}", h.DeleteNamed, keys, w, req)
	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Fatalf("expected 200/204, got %d: %s", w.Code, w.Body.String())
	}
}

// Service-level coverage: exercises refHash, UploadNamed wrapper, DownloadNamed,
// DeleteNamed, and the success-path decryption through decryptBlob.
func TestBlobService_NamedRoundTrip(t *testing.T) {
	stored := map[string]*model.Blob{}
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, b *model.Blob) error {
			stored[b.RefHash] = b
			return nil
		},
		GetByRefAndPseudonymFn: func(_ context.Context, ref, _ string) (*model.Blob, error) {
			return stored[ref], nil
		},
		DeleteByRefAndPseudonymFn: func(_ context.Context, ref, _ string) error {
			if _, ok := stored[ref]; !ok {
				return errors.New("blob not found")
			}
			delete(stored, ref)
			return nil
		},
	}
	svc := service.NewBlobService(repo, blobTestMasterKey(), blobTestHMACSecret(), service.BlobConfig{
		MaxBlobSize:     1 << 20,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 << 20,
	})

	payload := []byte("named-blob-payload-secret")
	blob, err := svc.UploadNamed(context.Background(), "user-1", payload, "notes.txt")
	if err != nil {
		t.Fatalf("UploadNamed: %v", err)
	}
	if blob.RefHash == "" {
		t.Fatal("expected refHash to be populated for named blob")
	}

	got, label, checksum, err := svc.DownloadNamed(context.Background(), "user-1", "notes.txt")
	if err != nil {
		t.Fatalf("DownloadNamed: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}
	if label != "notes.txt" {
		t.Fatalf("label mismatch: %q", label)
	}
	if checksum == "" {
		t.Fatal("expected checksum")
	}

	if err := svc.DeleteNamed(context.Background(), "user-1", "notes.txt"); err != nil {
		t.Fatalf("DeleteNamed: %v", err)
	}
	// Second delete should produce ErrBlobNotFound.
	if err := svc.DeleteNamed(context.Background(), "user-1", "notes.txt"); !errors.Is(err, service.ErrBlobNotFound) {
		t.Fatalf("second DeleteNamed: want ErrBlobNotFound, got %v", err)
	}
}
