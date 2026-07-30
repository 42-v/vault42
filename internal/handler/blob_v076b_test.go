package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// UploadNamed
// ---------------------------------------------------------------------------

func TestBlobUploadNamed_Success(t *testing.T) {
	var created bool
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, b *model.Blob) error {
			created = true
			if b.RefHash == "" {
				t.Error("named blob should carry a RefHash")
			}
			return nil
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodPut, "/user/blobs/named/config-json", strings.NewReader(strings.Repeat("x", 1024)))
	req.SetPathValue("name", "config-json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.UploadNamed(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !created {
		t.Error("expected named blob to be created")
	}
	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["label"] != "config-json" {
		t.Errorf("expected label to echo the name, got %v", result["label"])
	}
}

func TestBlobUploadNamed_Unauthorized(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodPut, "/user/blobs/named/x", strings.NewReader("d"))
	req.SetPathValue("name", "x")
	rec := httptest.NewRecorder()

	h.UploadNamed(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBlobUploadNamed_MissingName(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodPut, "/user/blobs/named/", strings.NewReader("d"))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.UploadNamed(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing name, got %d", rec.Code)
	}
}

func TestBlobUploadNamed_NameTooLong(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	name := strings.Repeat("n", 300)
	req := httptest.NewRequest(http.MethodPut, "/user/blobs/named/"+name, strings.NewReader("d"))
	req.SetPathValue("name", name)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.UploadNamed(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for over-long name, got %d", rec.Code)
	}
	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["error"] != "name_too_long" {
		t.Errorf("expected name_too_long, got %v", result["error"])
	}
}

func TestBlobUploadNamed_EmptyBody(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodPut, "/user/blobs/named/x", strings.NewReader(""))
	req.SetPathValue("name", "x")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.UploadNamed(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", rec.Code)
	}
}

func TestBlobUploadNamed_TooSmall(t *testing.T) {
	h := newTestBlobHandlerWithMinSize(&mocks.MockBlobRepo{}, 1024)

	req := httptest.NewRequest(http.MethodPut, "/user/blobs/named/x", strings.NewReader("tiny"))
	req.SetPathValue("name", "x")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.UploadNamed(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for too-small named blob, got %d", rec.Code)
	}
}

func TestBlobUploadNamed_QuotaExceeded(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{UsedCount: 10}, nil
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodPut, "/user/blobs/named/x", strings.NewReader(strings.Repeat("x", 1024)))
	req.SetPathValue("name", "x")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.UploadNamed(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for quota exceeded, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// DownloadNamed
// ---------------------------------------------------------------------------

func TestBlobDownloadNamed_Success(t *testing.T) {
	svc := newTestBlobService(&mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	})
	blob, err := svc.UploadNamed(context.Background(), "user-123", []byte("named bytes"), "doc.txt")
	if err != nil {
		t.Fatalf("seed upload-named: %v", err)
	}

	dlRepo := &mocks.MockBlobRepo{
		GetByRefAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return blob, nil
		},
	}
	h := NewBlobHandler(newTestBlobService(dlRepo), newTestAuditLogger(), 0, 1024*1024)

	req := httptest.NewRequest(http.MethodGet, "/user/blobs/named/doc.txt", nil)
	req.SetPathValue("name", "doc.txt")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.DownloadNamed(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "named bytes" {
		t.Errorf("expected round-tripped payload, got %q", rec.Body.String())
	}
	if rec.Header().Get("X-Blob-Checksum") == "" {
		t.Error("expected an X-Blob-Checksum header")
	}
}

func TestBlobDownloadNamed_Unauthorized(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodGet, "/user/blobs/named/x", nil)
	req.SetPathValue("name", "x")
	rec := httptest.NewRecorder()

	h.DownloadNamed(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBlobDownloadNamed_MissingName(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodGet, "/user/blobs/named/", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.DownloadNamed(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing name, got %d", rec.Code)
	}
}

func TestBlobDownloadNamed_NotFound(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{}) // GetByRef defaults to nil, nil

	req := httptest.NewRequest(http.MethodGet, "/user/blobs/named/missing", nil)
	req.SetPathValue("name", "missing")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.DownloadNamed(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestBlobDownloadNamed_DBError(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetByRefAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return nil, errors.New("db down")
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/user/blobs/named/x", nil)
	req.SetPathValue("name", "x")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.DownloadNamed(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Upload — label with a control character is rejected
// ---------------------------------------------------------------------------

func TestBlobUpload_InvalidLabelControlChar(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
	}
	h := newTestBlobHandler(repo)

	req := httptest.NewRequest(http.MethodPost, "/user/blobs", strings.NewReader(strings.Repeat("x", 1024)))
	req.Header.Set("X-Blob-Label", "bad\x01label")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for control-char label, got %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_label" {
		t.Errorf("expected invalid_label, got %v", result["error"])
	}
}

// Multipart parse failure (malformed body) returns 413.
func TestBlobUpload_MultipartParseError(t *testing.T) {
	h := newTestBlobHandler(&mocks.MockBlobRepo{})

	req := httptest.NewRequest(http.MethodPost, "/user/blobs", strings.NewReader("not-a-real-multipart-body"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=nope")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for malformed multipart, got %d: %s", rec.Code, rec.Body.String())
	}
}
