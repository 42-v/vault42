package handler

import (
	"context"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Both blob download paths return bytes a browser can be navigated straight at,
// and neither said what the bytes were for. Content-Type: application/octet-stream
// and X-Content-Type-Options: nosniff between them stop a browser guessing a
// type, but they do not stop it rendering the one that was declared, and
// "render or download" is a question only Content-Disposition answers.
//
// The attachment disposition type is the control ASVS V3.2.1 names by example,
// the one V5.4.1 requires outright, and the thing V5.1.1's documentation clause
// had nothing to describe until it existed.
func TestBlobDownloadPathsMarkTheResponseAsAnAttachment(t *testing.T) {
	svc := newTestBlobService(&mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, _ *model.Blob) error { return nil },
	})

	byID, err := svc.Upload(context.Background(), "user-123", []byte("bytes by id"), "a-label")
	if err != nil {
		t.Fatalf("seed upload: %v", err)
	}
	byName, err := svc.UploadNamed(context.Background(), "user-123", []byte("bytes by name"), "report")
	if err != nil {
		t.Fatalf("seed upload-named: %v", err)
	}

	for _, tc := range []struct {
		name     string
		serve    func(w http.ResponseWriter, r *http.Request)
		request  func() *http.Request
		filename string
	}{
		{
			name: "download by id",
			serve: NewBlobHandler(newTestBlobService(&mocks.MockBlobRepo{
				GetByIDAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) { return byID, nil },
			}), newTestAuditLogger(), 0, 1024*1024).Download,
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/user/blobs/"+byID.ID, nil)
				req.SetPathValue("id", byID.ID)
				return setAuthContext(req, "user-123")
			},
			filename: byID.ID,
		},
		{
			name: "download by name",
			serve: NewBlobHandler(newTestBlobService(&mocks.MockBlobRepo{
				GetByRefAndPseudonymFn: func(_ context.Context, _, _ string) (*model.Blob, error) { return byName, nil },
			}), newTestAuditLogger(), 0, 1024*1024).DownloadNamed,
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/user/blobs/named/report", nil)
				req.SetPathValue("name", "report")
				return setAuthContext(req, "user-123")
			},
			filename: "report",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.serve(rec, tc.request())

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
			}
			got := rec.Header().Get("Content-Disposition")
			if got == "" {
				t.Fatal("no Content-Disposition header, so a browser navigated at this URL decides for itself what to do with the bytes")
			}

			disposition, params, err := mime.ParseMediaType(got)
			if err != nil {
				t.Fatalf("Content-Disposition %q does not parse: %v", got, err)
			}
			if disposition != "attachment" {
				t.Errorf("Content-Disposition = %q, want the attachment disposition type; inline is the rendering this header exists to prevent", disposition)
			}
			// V5.4.1 requires a filename, not merely the disposition type.
			if params["filename"] != tc.filename {
				t.Errorf("filename = %q, want %q", params["filename"], tc.filename)
			}
		})
	}
}

// The filename lands in a header, so what reaches it has to be what this
// handler chose rather than what a caller typed. DownloadNamed does not run
// validRefName -- only the upload path does -- so the download path cannot
// borrow that guarantee, and a header value assembled from an unvalidated
// path segment is how a quote becomes a second parameter.
func TestContentDispositionFilenameKeepsOnlyWhatIsSafeInAHeader(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"an ordinary name survives", "quarterly-report_2026", "quarterly-report_2026"},
		{"a uuid survives", "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
		{"a dot survives, because an extension is the point of a filename", "notes.txt", "notes.txt"},
		{"a quote cannot close the parameter", `x"; filename="payslip.html`, "xfilenamepayslip.html"},
		{"a path separator cannot suggest a directory", "../../etc/passwd", "....etcpasswd"},
		{"a control character cannot split the header", "a\r\nX-Injected: 1", "aX-Injected1"},
		{"a name with nothing usable left falls back", `"""`, "blob"},
		{"an empty name falls back", "", "blob"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := contentDispositionFilename(tc.in); got != tc.want {
				t.Fatalf("contentDispositionFilename(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A filename long enough to matter is bounded, because the header is written
// before the body and a caller-sized header is a caller-sized allocation.
func TestContentDispositionFilenameIsBounded(t *testing.T) {
	got := contentDispositionFilename(strings.Repeat("a", 4096))
	if len(got) != maxDispositionFilename {
		t.Fatalf("filename length = %d, want it capped at %d", len(got), maxDispositionFilename)
	}
}
