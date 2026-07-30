package unit_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// blobClientTornBody is a request body that dies partway through, the way a client
// that goes away mid-upload does.
type blobClientTornBody struct{}

func (blobClientTornBody) Read([]byte) (int, error) {
	return 0, errors.New("connection reset by peer")
}

func (blobClientTornBody) Close() error { return nil }

// A named blob is addressed by name, and uploading over one replaces it: the service
// deletes the existing blob before it stores the new bytes. So a body that fails to
// read is not a harmless no-op. If the read error were ignored, the handler would go
// on with an empty payload and the user's stored document would be replaced by, or
// deleted in favour of, nothing.
//
// The upload has to stop where it is: 413, nothing written, and the blob that is
// already there left alone.
func TestBlobUploadNamed_UnreadableBodyStoresNothing(t *testing.T) {
	stored := false
	replaced := false
	repo := &mocks.MockBlobRepo{
		CreateFn: func(context.Context, *model.Blob) error {
			stored = true
			return nil
		},
		DeleteByRefAndPseudonymFn: func(context.Context, string, string) error {
			replaced = true
			return nil
		},
		GetQuotaFn: func(context.Context, string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	req, w, keys := authedRequest(t, http.MethodPut, "/user/blobs/named/notes.txt", nil)
	req.Body = blobClientTornBody{}
	req.ContentLength = 4096
	serveWithAuth(t, "PUT /user/blobs/named/{name}", h.UploadNamed, keys, w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}
	if stored {
		t.Error("a body that could not be read was stored as a blob")
	}
	if replaced {
		t.Error("the existing named blob was deleted for an upload that never arrived")
	}
}

// Multipart uploads above the in-memory threshold are spooled to a temporary file and
// read back after parsing. That read can fail for reasons the parse never saw: the
// spool file is gone, the disk is failing, the temp directory has been swapped under
// the process. Here the spool is replaced by a directory, so opening it succeeds and
// reading it does not, which is the shape of that class of failure.
//
// Nothing may be stored from a payload the server could not read back. Without the
// error check the handler would carry on with a nil payload and answer 400 empty_blob,
// blaming the client for a failure that happened on this side of the wire.
func TestBlobUpload_UnreadableSpooledPartStoresNothing(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "upload.bin")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write(bytes.Repeat([]byte("a"), 4096)); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	spoolDir := t.TempDir()
	t.Setenv("TMPDIR", spoolDir)

	form, err := multipart.NewReader(bytes.NewReader(body.Bytes()), mw.Boundary()).ReadForm(1)
	if err != nil {
		t.Fatalf("read form: %v", err)
	}

	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatalf("read spool dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("spool dir holds %d entries, want the single spooled part", len(entries))
	}
	spool := filepath.Join(spoolDir, entries[0].Name())
	if err := os.Remove(spool); err != nil {
		t.Fatalf("remove spool file: %v", err)
	}
	if err := os.Mkdir(spool, 0o700); err != nil {
		t.Fatalf("replace spool file with a directory: %v", err)
	}

	stored := false
	repo := &mocks.MockBlobRepo{
		CreateFn: func(context.Context, *model.Blob) error {
			stored = true
			return nil
		},
		GetQuotaFn: func(context.Context, string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
	}
	h := newBlobTestHandler(repo, 0, 1024*1024)

	req, w, keys := authedRequest(t, http.MethodPost, "/user/blobs", nil)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Body = io.NopCloser(bytes.NewReader(nil))
	req.ContentLength = int64(body.Len())
	req.MultipartForm = form
	serveWithAuth(t, "POST /user/blobs", h.Upload, keys, w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}
	if stored {
		t.Error("a part the server could not read back was stored as a blob")
	}
}
