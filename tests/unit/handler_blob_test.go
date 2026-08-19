package unit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// Blob handler test helpers
// ---------------------------------------------------------------------------

func blobTestMasterKey() []byte {
	return []byte("01234567890123456789012345678901") // 32 bytes for AES-256
}

func blobTestHMACSecret() []byte {
	return []byte("test-hmac-secret-key-32-bytes!!")
}

func newBlobTestHandler(repo *mocks.MockBlobRepo, minSize, maxSize int) *handler.BlobHandler {
	svc := service.NewBlobService(repo, blobTestMasterKey(), blobTestHMACSecret(), service.BlobConfig{
		MinBlobSize:     minSize,
		MaxBlobSize:     maxSize,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})
	return handler.NewBlobHandler(svc, newTestAuditLogger(), minSize, maxSize)
}

// ---------------------------------------------------------------------------
// Upload at boundary sizes
// ---------------------------------------------------------------------------

func TestBlobUpload_ExactlyMinSize(t *testing.T) {
	minSize := 64
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	h := newBlobTestHandler(repo, minSize, 1024*1024)

	data := strings.Repeat("x", minSize)
	req, w, keys := authedRequest(t, http.MethodPost, "/user/blobs", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(data)}
	req.ContentLength = int64(len(data))
	serveWithAuth(t, "POST /user/blobs", h.Upload, keys, w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for data at exact min size, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBlobUpload_OneBelowMinSize(t *testing.T) {
	minSize := 64
	repo := &mocks.MockBlobRepo{}
	h := newBlobTestHandler(repo, minSize, 1024*1024)

	data := strings.Repeat("x", minSize-1)
	req, w, keys := authedRequest(t, http.MethodPost, "/user/blobs", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(data)}
	req.ContentLength = int64(len(data))
	serveWithAuth(t, "POST /user/blobs", h.Upload, keys, w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for data below min size, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Label truncation
// ---------------------------------------------------------------------------

func TestBlobUpload_LabelExactly255Runes(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	label255 := strings.Repeat("L", 255)
	data := strings.Repeat("x", 512)
	req, w, keys := authedRequest(t, http.MethodPost, "/user/blobs", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(data)}
	req.ContentLength = int64(len(data))
	req.Header.Set("X-Blob-Label", label255)
	serveWithAuth(t, "POST /user/blobs", h.Upload, keys, w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	respLabel, ok := resp["label"].(string)
	if !ok {
		t.Fatal("expected label in response")
	}
	if utf8.RuneCountInString(respLabel) != 255 {
		t.Fatalf("expected label length 255, got %d", utf8.RuneCountInString(respLabel))
	}
}

func TestBlobUpload_Label256RunesTruncatedTo255(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	label256 := strings.Repeat("M", 256)
	data := strings.Repeat("x", 512)
	req, w, keys := authedRequest(t, http.MethodPost, "/user/blobs", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(data)}
	req.ContentLength = int64(len(data))
	req.Header.Set("X-Blob-Label", label256)
	serveWithAuth(t, "POST /user/blobs", h.Upload, keys, w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	respLabel, ok := resp["label"].(string)
	if !ok {
		t.Fatal("expected label in response")
	}
	if utf8.RuneCountInString(respLabel) != 255 {
		t.Fatalf("expected label truncated to 255, got %d", utf8.RuneCountInString(respLabel))
	}
}

func TestBlobUpload_LabelMultiByteRunesTruncation(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	// 260 CJK runes — should be truncated to 255 runes, not 255 bytes
	label260cjk := strings.Repeat("\u4e16", 260)
	if utf8.RuneCountInString(label260cjk) != 260 {
		t.Fatalf("setup: expected 260 runes, got %d", utf8.RuneCountInString(label260cjk))
	}

	data := strings.Repeat("x", 512)
	req, w, keys := authedRequest(t, http.MethodPost, "/user/blobs", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(data)}
	req.ContentLength = int64(len(data))
	req.Header.Set("X-Blob-Label", label260cjk)
	serveWithAuth(t, "POST /user/blobs", h.Upload, keys, w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	respLabel, ok := resp["label"].(string)
	if !ok {
		t.Fatal("expected label in response")
	}
	if utf8.RuneCountInString(respLabel) != 255 {
		t.Fatalf("expected label truncated to 255 runes, got %d", utf8.RuneCountInString(respLabel))
	}
}

// ---------------------------------------------------------------------------
// Upload with empty label
// ---------------------------------------------------------------------------

func TestBlobUpload_EmptyLabel(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	data := strings.Repeat("x", 512)
	req, w, keys := authedRequest(t, http.MethodPost, "/user/blobs", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(data)}
	req.ContentLength = int64(len(data))
	// No X-Blob-Label header
	serveWithAuth(t, "POST /user/blobs", h.Upload, keys, w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for empty label, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["label"] != "" {
		t.Fatalf("expected empty label, got %q", resp["label"])
	}
}

// ---------------------------------------------------------------------------
// List response structure
// ---------------------------------------------------------------------------

func TestBlobList_ResponseFields(t *testing.T) {
	now := time.Now()
	repo := &mocks.MockBlobRepo{
		ListByPseudonymFn: func(_ context.Context, _ string) ([]*model.Blob, error) {
			return []*model.Blob{
				{
					ID:          "blob-abc",
					PseudonymID: "pseudo-1",
					SizeBytes:   2048,
					StoredBytes: 1600,
					Checksum:    "sha256:deadbeef",
					CreatedAt:   now,
				},
			}, nil
		},
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{UsedCount: 1, UsedBytes: 1600}, nil
		},
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	req, w, keys := authedRequest(t, http.MethodGet, "/user/blobs", nil)
	serveWithAuth(t, "GET /user/blobs", h.List, keys, w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	blobs, ok := resp["blobs"].([]interface{})
	if !ok || len(blobs) != 1 {
		t.Fatalf("expected 1 blob, got %v", resp["blobs"])
	}
	total, ok := resp["total"].(float64)
	if !ok {
		t.Fatalf("expected a total key in the list envelope, got %v", resp)
	}
	if total != 1 {
		t.Fatalf("expected total=1, got %v", total)
	}
	if resp["quota"] == nil {
		t.Fatal("expected quota field in response")
	}

	blob := blobs[0].(map[string]interface{})
	for _, field := range []string{"id", "size_bytes", "stored_bytes", "checksum", "created_at"} {
		if blob[field] == nil {
			t.Errorf("expected field %q in blob, not found", field)
		}
	}
}

// ---------------------------------------------------------------------------
// Download response headers
// ---------------------------------------------------------------------------

func TestBlobDownload_ResponseHeaders(t *testing.T) {
	// Upload via service to get properly encrypted blob
	uploadRepo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	svc := service.NewBlobService(uploadRepo, blobTestMasterKey(), blobTestHMACSecret(), service.BlobConfig{
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})

	blob, err := svc.Upload(context.Background(), "user-123", []byte("test data for headers"), "my-label")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	// Set up download handler
	downloadRepo := &mocks.MockBlobRepo{
		GetByIDAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return blob, nil
		},
	}
	downloadSvc := service.NewBlobService(downloadRepo, blobTestMasterKey(), blobTestHMACSecret(), service.BlobConfig{
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})
	h := handler.NewBlobHandler(downloadSvc, newTestAuditLogger(), 0, 1024*1024)

	req, w, keys := authedRequest(t, http.MethodGet, "/user/blobs/"+blob.ID, nil)
	req.SetPathValue("id", blob.ID)
	serveWithAuth(t, "GET /user/blobs/{id}", h.Download, keys, w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify Content-Type
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("expected Content-Type=application/octet-stream, got %q", ct)
	}

	// Verify Content-Length is set and matches body
	cl := w.Header().Get("Content-Length")
	if cl == "" {
		t.Fatal("expected Content-Length header")
	}
	expectedLen := fmt.Sprintf("%d", w.Body.Len())
	if cl != expectedLen {
		t.Fatalf("Content-Length=%s, body length=%s", cl, expectedLen)
	}

	// Verify X-Blob-Checksum
	if cs := w.Header().Get("X-Blob-Checksum"); cs == "" {
		t.Fatal("expected non-empty X-Blob-Checksum header")
	}

	// Verify X-Blob-Label
	if lbl := w.Header().Get("X-Blob-Label"); lbl != "my-label" {
		t.Fatalf("expected X-Blob-Label=my-label, got %q", lbl)
	}

	// Verify body contains the original data
	if w.Body.String() != "test data for headers" {
		t.Fatalf("expected original data, got %q", w.Body.String())
	}
}

func TestBlobDownload_EmptyLabelNoHeader(t *testing.T) {
	// Upload with empty label
	uploadRepo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	svc := service.NewBlobService(uploadRepo, blobTestMasterKey(), blobTestHMACSecret(), service.BlobConfig{
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})

	blob, err := svc.Upload(context.Background(), "user-123", []byte("no label data"), "")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	downloadRepo := &mocks.MockBlobRepo{
		GetByIDAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) {
			return blob, nil
		},
	}
	downloadSvc := service.NewBlobService(downloadRepo, blobTestMasterKey(), blobTestHMACSecret(), service.BlobConfig{
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})
	h := handler.NewBlobHandler(downloadSvc, newTestAuditLogger(), 0, 1024*1024)

	req, w, keys := authedRequest(t, http.MethodGet, "/user/blobs/"+blob.ID, nil)
	req.SetPathValue("id", blob.ID)
	serveWithAuth(t, "GET /user/blobs/{id}", h.Download, keys, w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// When label is empty, X-Blob-Label should not be set
	if lbl := w.Header().Get("X-Blob-Label"); lbl != "" {
		t.Fatalf("expected no X-Blob-Label header for empty label, got %q", lbl)
	}
}

// ---------------------------------------------------------------------------
// Multipart label via form field
// ---------------------------------------------------------------------------

func TestBlobUpload_MultipartWithLabel(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "doc.bin")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	fw.Write([]byte(strings.Repeat("z", 256)))
	mw.WriteField("label", "multipart-label")
	mw.Close()

	req, w, keys := authedRequest(t, http.MethodPost, "/user/blobs", nil)
	req.Body = &readCloserBuf{Buffer: &buf}
	req.ContentLength = int64(buf.Len())
	req.Header.Set("Content-Type", mw.FormDataContentType())
	serveWithAuth(t, "POST /user/blobs", h.Upload, keys, w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["label"] != "multipart-label" {
		t.Fatalf("expected label=multipart-label, got %q", resp["label"])
	}
}

type readCloserBuf struct {
	*bytes.Buffer
}

func (r *readCloserBuf) Read(p []byte) (int, error) {
	return r.Buffer.Read(p)
}

func (r *readCloserBuf) Close() error { return nil }

// ---------------------------------------------------------------------------
// Upload response includes expected fields
// ---------------------------------------------------------------------------

func TestBlobUpload_ResponseFields(t *testing.T) {
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	data := strings.Repeat("d", 1024)
	req, w, keys := authedRequest(t, http.MethodPost, "/user/blobs", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(data)}
	req.ContentLength = int64(len(data))
	req.Header.Set("X-Blob-Label", "test-upload")
	serveWithAuth(t, "POST /user/blobs", h.Upload, keys, w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, field := range []string{"id", "label", "size_bytes", "stored_bytes", "checksum", "created_at"} {
		if resp[field] == nil {
			t.Errorf("expected field %q in upload response, not found", field)
		}
	}
}
