package service

import (
	"bytes"
	"compress/flate"
	"context"
	"errors"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// A decompression bomb is a small stored object that expands to an enormous one. Blobs
// are deflate-compressed before they are encrypted, so what the database holds is the
// *compressed* size — the quota and the upload limit both see a few kilobytes, and the
// expansion only happens in memory, on download, on the server.
//
// 11 MB of zeroes compresses to roughly ten kilobytes. Without the size cap, a handful
// of concurrent downloads of a blob like this would allocate gigabytes and take the
// process down, and every check that would normally stop it (upload size, per-user
// quota) sees a blob small enough to wave through.
//
// The cap exists. This is the test that it actually holds — and, just as importantly,
// that the download fails rather than quietly returning a truncated 10 MB prefix, which
// is what a `LimitReader` gives you if nobody checks whether it hit the limit.
func TestBlobDownload_DecompressionBombIsRefused(t *testing.T) {
	const (
		userID  = "user-1"
		blobID  = "blob-bomb"
		hugeLen = 11 * 1024 * 1024 // one megabyte past the 10 MB ceiling
	)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	hmacSecret := []byte("test-hmac-secret")

	// Deflate 11 MB of zeroes. This is the payload an attacker stores.
	var compressed bytes.Buffer
	zw, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := zw.Write(make([]byte, hugeLen)); err != nil {
		t.Fatalf("compress: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close compressor: %v", err)
	}

	svc := NewBlobService(&mocks.MockBlobRepo{}, masterKey, hmacSecret, BlobConfig{})
	pseudo := svc.Pseudonym(userID)

	// Encrypt it exactly as the upload path would, so the download path has no way to
	// tell this apart from a legitimate blob until it decompresses.
	dataAAD := []byte(blobID + ":" + pseudo)
	enc, err := vaultcrypto.Encrypt(compressed.Bytes(), masterKey, dataAAD)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	t.Logf("stored size %d bytes; expands to %d bytes", compressed.Len(), hugeLen)
	if compressed.Len() > 1<<20 {
		t.Fatalf("the compressed payload (%d bytes) is not small enough to be a bomb", compressed.Len())
	}

	repo := &mocks.MockBlobRepo{
		GetByIDAndPseudonymFn: func(context.Context, string, string) (*model.Blob, error) {
			return &model.Blob{ID: blobID, PseudonymID: pseudo, DataEnc: enc}, nil
		},
	}
	svc = NewBlobService(repo, masterKey, hmacSecret, BlobConfig{})

	data, _, _, err := svc.Download(context.Background(), userID, blobID)

	if err == nil {
		t.Fatalf("the bomb was served: %d bytes returned with no error", len(data))
	}
	if !strings.Contains(err.Error(), "decompress") {
		t.Errorf("err = %v, want a decompression-size failure", err)
	}
	if len(data) != 0 {
		t.Errorf("a refused download still returned %d bytes — a truncated prefix is not a valid blob", len(data))
	}
}

// A blob whose ciphertext does not decrypt must fail, not return an empty document. This
// is the shape of a wrong master key or a tampered row, and silently handing back "" for
// the user's stored data would look like the data was simply gone.
func TestBlobDownload_UndecryptableBlobFails(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x42}, 32)
	svc := NewBlobService(&mocks.MockBlobRepo{}, masterKey, []byte("hmac"), BlobConfig{})
	pseudo := svc.Pseudonym("user-1")

	repo := &mocks.MockBlobRepo{
		GetByIDAndPseudonymFn: func(context.Context, string, string) (*model.Blob, error) {
			return &model.Blob{ID: "b-1", PseudonymID: pseudo, DataEnc: []byte("not ciphertext")}, nil
		},
	}
	svc = NewBlobService(repo, masterKey, []byte("hmac"), BlobConfig{})

	data, _, _, err := svc.Download(context.Background(), "user-1", "b-1")
	if err == nil {
		t.Fatal("an undecryptable blob was returned as if it were the user's data")
	}
	if len(data) != 0 {
		t.Errorf("a failed decrypt returned %d bytes", len(data))
	}
}

// The repository failing is not the same as the blob not existing, and the difference
// matters: "not found" is a 404 the user acts on, a database outage is a 500 they retry.
func TestBlobService_SurfacesRepositoryFailures(t *testing.T) {
	boom := errors.New("db down")
	masterKey := bytes.Repeat([]byte{0x42}, 32)

	repo := &mocks.MockBlobRepo{
		GetByIDAndPseudonymFn: func(context.Context, string, string) (*model.Blob, error) {
			return nil, boom
		},
		ListByPseudonymFn: func(context.Context, string) ([]*model.Blob, error) { return nil, boom },
		CreateFn:          func(context.Context, *model.Blob) error { return boom },
	}
	svc := NewBlobService(repo, masterKey, []byte("hmac"), BlobConfig{MaxBlobSize: 1 << 20, MaxBlobsPerUser: 10})
	ctx := context.Background()

	if _, _, _, err := svc.Download(ctx, "user-1", "b-1"); err == nil {
		t.Error("Download returned no error while the database was down")
	}
	if _, _, err := svc.List(ctx, "user-1"); err == nil {
		t.Error("List returned no error — the user would be shown an empty document list")
	}
	if _, err := svc.Upload(ctx, "user-1", []byte("hello"), "note"); err == nil {
		t.Error("Upload reported success — the user would believe their document was saved")
	}
}
