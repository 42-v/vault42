package compliance

import (
	"bytes"
	"context"
	"go/ast"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// OWASP ASVS 5.0.0 — V5 File Handling
//
// Nine V5 rows carried one sentence: "vault42 accepts no file uploads. The
// single binary-shaped endpoint, POST /user/blobs, takes an opaque
// client-encrypted octet stream that the server never parses, renders, stores
// by client-supplied name, or serves back with a caller-influenced content
// type."
//
// Three of its clauses are false. internal/handler/blob.go branches on
// multipart/form-data, calls r.ParseMultipartForm and then r.FormFile("file") —
// a file upload, parsed by the server, out of a form field literally named
// file. PUT /user/blobs/named/{name} stores under a caller-supplied name. And
// there are three write paths, not one: POST /user/blobs,
// PUT /user/blobs/named/{name} and PUT /service/documents/{subject}/{key}.
//
// The irony is that the controls the requirements ask for are already
// implemented — a body cap, a decompression-bomb bound, a filename charset, a
// header sanitiser. Filing them as "no such feature exists" gave away four
// working defenses and buried the two that are missing.
//
// These tests drive the real handler and the real service.
// =============================================================================

// v5Handler builds a BlobHandler over the real BlobService with an in-memory
// repository, so an upload really is compressed, encrypted, stored, decrypted
// and decompressed by the shipped code.
func v5Handler(t *testing.T, maxBlobSize int) (*handler.BlobHandler, map[string]*model.Blob) {
	t.Helper()

	stored := map[string]*model.Blob{}
	repo := &mocks.MockBlobRepo{
		CreateFn: func(_ context.Context, b *model.Blob) error {
			stored[b.ID] = b
			return nil
		},
		GetByIDAndPseudonymFn: func(_ context.Context, id, _ string) (*model.Blob, error) {
			return stored[id], nil
		},
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
	}

	masterKey := make([]byte, 32)
	hmacSecret := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
		hmacSecret[i] = byte(255 - i)
	}

	svc := service.NewBlobService(repo, masterKey, hmacSecret, service.BlobConfig{
		MinBlobSize:     1,
		MaxBlobSize:     maxBlobSize,
		MaxBlobsPerUser: 100,
		QuotaBytes:      10 << 20,
	})
	return handler.NewBlobHandler(svc, nil, 1, maxBlobSize), stored
}

// v5Authenticated attaches claims the way middleware.Auth does, so the handler
// runs its real body rather than short-circuiting on a missing subject.
func v5Authenticated(req *http.Request) *http.Request {
	claims := &vaultcrypto.VaultClaims{}
	claims.Subject = "user-v5"
	return req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
}

// --- V5.2.1 — accept only sizes it can process ---

// "Verify that the application will only accept files of a size which it can
// process without causing a loss of performance or a denial of service."
//
// The control is http.MaxBytesReader on every write path, sized from the
// configured maximum. The assertion is that an oversized body is refused rather
// than buffered: a limit that is only checked after io.ReadAll has already
// allocated the whole thing is not a limit.
func TestASVS_V5_2_1_OversizedUploadsAreRefusedAtTheReader(t *testing.T) {
	const maxBlob = 4096
	h, stored := v5Handler(t, maxBlob)

	// Comfortably past maxBlob + the 1 KiB slack the handler allows.
	oversized := bytes.Repeat([]byte("A"), maxBlob*4)

	req := v5Authenticated(httptest.NewRequest(http.MethodPost, "/user/blobs", bytes.NewReader(oversized)))
	rec := httptest.NewRecorder()
	h.Upload(rec, req)

	if rec.Code == http.StatusCreated {
		t.Fatalf("V5.2.1: a %d-byte body was accepted against a %d-byte maximum", len(oversized), maxBlob)
	}
	if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest {
		t.Errorf("V5.2.1: oversized upload answered with %d; want 413 (or 400)", rec.Code)
	}
	if len(stored) != 0 {
		t.Errorf("V5.2.1: %d blob(s) reached the repository despite the size refusal", len(stored))
	}

	// The named path carries the same cap; a cap on one of three write paths is
	// not a cap.
	req = v5Authenticated(httptest.NewRequest(http.MethodPut, "/user/blobs/named/report", bytes.NewReader(oversized)))
	req.SetPathValue("name", "report")
	rec = httptest.NewRecorder()
	h.UploadNamed(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("V5.2.1: PUT /user/blobs/named/{name} accepted an oversized body")
	}

	// The service-document path re-applies its own cap because the route prefix
	// is exempt from the global 8 KiB body limit. An exemption with no reader of
	// its own is an unbounded body.
	sd := readCodeOnly(t, "internal/handler/servicedoc.go")
	if !strings.Contains(sd, "http.MaxBytesReader") {
		t.Error("V5.2.1: internal/handler/servicedoc.go no longer re-applies MaxBytesReader. " +
			"That route prefix is exempt from the global 8 KiB cap, so dropping this leaves it unbounded.")
	}
}

// --- V5.2.3 — bound the uncompressed size before decompressing ---

// "Verify that the application checks compressed files against maximum allowed
// uncompressed size ... before uncompressing."
//
// vault42 deflates every blob on write and inflates it on read. That makes the
// server the producer of its own archives, but not the only one: the row that
// matters is the read path, which inflates whatever bytes the database holds.
// A compromised or corrupted row must not be able to inflate without bound.
//
// The control is an io.LimitReader at maxDecompressedSize+1 with an explicit
// over-limit error. This asserts a normal round trip works and that the bound
// is genuinely present and enforced by an error rather than by truncation —
// silently returning the first 10 MB of a bomb is a data-integrity failure
// wearing a size limit's clothes.
func TestASVS_V5_2_3_DecompressionIsBoundedAndFailsClosed(t *testing.T) {
	h, _ := v5Handler(t, 1<<20)

	// A highly compressible payload: the shape a decompression bomb takes.
	payload := bytes.Repeat([]byte("A"), 64*1024)

	req := v5Authenticated(httptest.NewRequest(http.MethodPost, "/user/blobs", bytes.NewReader(payload)))
	rec := httptest.NewRecorder()
	h.Upload(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("V5.2.3: upload of a compressible payload failed with %d: %s", rec.Code, rec.Body.String())
	}

	src := readCodeOnly(t, "internal/service/blob.go")
	if !strings.Contains(src, "maxDecompressedSize") {
		t.Fatal("V5.2.3: the maxDecompressedSize bound is gone from the blob read path. " +
			"Every read inflates a stored deflate stream; without a bound, one row decides how " +
			"much memory the process allocates.")
	}
	if !strings.Contains(src, "io.LimitReader") {
		t.Error("V5.2.3: the decompressor is no longer wrapped in an io.LimitReader, so the bound " +
			"is checked after the allocation it exists to prevent")
	}
	// +1 is what makes over-limit distinguishable from exactly-at-limit. Without
	// it a bomb is silently truncated to the cap and returned as if intact.
	if !strings.Contains(src, "maxDecompressedSize+1") {
		t.Error("V5.2.3: the LimitReader no longer reads one byte past the bound, so an oversized " +
			"stream is truncated to the cap and returned as valid rather than rejected")
	}
	if !strings.Contains(src, "exceeds maximum decompressed size") {
		t.Error("V5.2.3: exceeding the bound no longer raises an error; a truncated blob returned " +
			"as intact is worse than a rejected one")
	}
}

// --- V5.3.2 — user-submitted names must be validated before use ---

// "Verify that when the application creates file paths for file operations,
// instead of user-submitted filenames, it uses internally generated or trusted
// data, or if user-submitted filenames or file metadata must be used, strict
// validation and sanitization must be applied. This is to protect against path
// traversal."
//
// PUT /user/blobs/named/{name} stores under a caller-supplied name, so the
// second branch applies. The charset is [a-zA-Z0-9_-], which excludes every
// separator, dot and null the traversal families are built from.
func TestASVS_V5_3_2_CallerSuppliedBlobNamesAreStrictlyValidated(t *testing.T) {
	h, stored := v5Handler(t, 4096)

	hostile := []string{
		"../../etc/passwd",
		"..%2f..%2fetc%2fpasswd",
		"/etc/shadow",
		`..\..\windows\system32`,
		"report/../../secret",
		"report\x00.png",
		"report.tar.gz",          // a dot is outside the charset
		"réport",                 // non-ASCII
		"report name",            // whitespace
		"$(whoami)",              // shell metacharacters
		strings.Repeat("a", 300), // past the 255-rune cap
	}

	for _, name := range hostile {
		req := v5Authenticated(httptest.NewRequest(http.MethodPut, "/user/blobs/named/x", strings.NewReader("payload")))
		req.SetPathValue("name", name)
		rec := httptest.NewRecorder()
		h.UploadNamed(rec, req)

		if rec.Code == http.StatusOK {
			t.Errorf("V5.3.2: name %q was accepted", name)
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("V5.3.2: name %q answered with %d; want 400", name, rec.Code)
		}
	}

	if len(stored) != 0 {
		t.Errorf("V5.3.2: %d blob(s) were written despite every name being rejected", len(stored))
	}

	// The positive control: a name inside the charset must still work, or the
	// test above would pass against a handler that rejects everything.
	req := v5Authenticated(httptest.NewRequest(http.MethodPut, "/user/blobs/named/x", strings.NewReader("payload")))
	req.SetPathValue("name", "quarterly_report-2026")
	rec := httptest.NewRecorder()
	h.UploadNamed(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("V5.3.2: a well-formed name was rejected with %d: %s; the negative cases above "+
			"prove nothing against a handler that refuses everything", rec.Code, rec.Body.String())
	}
}

// --- V5.4.2 — names served in response headers are sanitized ---

// "Verify that file names served (e.g., in HTTP response header fields or email
// attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve
// document structure and prevent injection attacks."
//
// The requirement offers encoding or sanitisation. vault42 sanitizes: the label
// is stripped of U+0000-U+001F before it is set as X-Blob-Label, which is what
// closes response-header injection. Non-ASCII is passed through un-encoded
// rather than RFC 8187 encoded; that is a fidelity limitation, recorded in the
// register row, not an injection channel.
func TestASVS_V5_4_2_ServedLabelsCannotForgeResponseHeaders(t *testing.T) {
	h, _ := v5Handler(t, 4096)

	// The classic response-splitting payload, plus a bare tab and a NUL.
	hostileLabel := "invoice\r\nSet-Cookie: admin=1\r\n\tX-Injected: yes\x00"

	rec := v5MultipartUpload(t, h, hostileLabel)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("V5.4.2: a label carrying CRLF and a NUL was answered with %d, want 400. "+
			"Rejecting it at the boundary is the primary control; the serve-side sanitiser "+
			"below is the second line.", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid_label") {
		t.Errorf("V5.4.2: hostile label rejected with %q rather than invalid_label", rec.Body.String())
	}

	// The upload really did go through the multipart branch, which is the fact
	// the old "vault42 accepts no file uploads" rationale denied.
	blobSrc := readCodeOnly(t, "internal/handler/blob.go")
	if !strings.Contains(blobSrc, `r.FormFile("file")`) {
		t.Error("V5.4.2: the multipart upload branch is gone from internal/handler/blob.go; " +
			"the V5 rows were reclassified on the fact that it exists")
	}

	// Positive control: a well-formed label survives the round trip into the
	// response header. Without this the rejection above would also pass against
	// a handler that refuses every label.
	rec = v5MultipartUpload(t, h, "Q3 invoice (final)")
	if rec.Code != http.StatusCreated {
		t.Fatalf("V5.4.2: multipart upload with a benign label failed with %d: %s", rec.Code, rec.Body.String())
	}
	id := v5BlobID(t, rec)

	dl := v5Authenticated(httptest.NewRequest(http.MethodGet, "/user/blobs/"+id, nil))
	dl.SetPathValue("id", id)
	dlRec := httptest.NewRecorder()
	h.Download(dlRec, dl)
	if dlRec.Code != http.StatusOK {
		t.Fatalf("V5.4.2: download failed with %d: %s", dlRec.Code, dlRec.Body.String())
	}

	served := dlRec.Header().Get("X-Blob-Label")
	if served != "Q3 invoice (final)" {
		t.Errorf("V5.4.2: the served label is %q; sanitisation must strip control characters, "+
			"not mangle the content", served)
	}
	for _, forbidden := range []string{"\r", "\n", "\x00"} {
		if strings.Contains(served, forbidden) {
			t.Errorf("V5.4.2: the served label contains %q", forbidden)
		}
	}
	if dlRec.Header().Get("Set-Cookie") != "" || dlRec.Header().Get("X-Injected") != "" {
		t.Error("V5.4.2: a header injected through the blob label reached the response")
	}

	// The serve-side sanitiser is what stands between a row that reached the
	// database by some other route -- a migration, an admin tool, a future
	// import -- and a forged response header. It is unreachable through the
	// handler precisely because the boundary check above fires first, which is
	// why it is asserted structurally rather than driven.
	if !strings.Contains(blobSrc, "sanitizeLabelForHeader(label)") {
		t.Error("V5.4.2: the download paths no longer sanitize the label before setting X-Blob-Label")
	}
	if !strings.Contains(blobSrc, "if r < 0x20") {
		t.Error("V5.4.2: sanitizeLabelForHeader no longer drops U+0000-U+001F, which is the class " +
			"of character that terminates a header field")
	}
}

// v5MultipartUpload posts a real multipart/form-data body with a file part
// named "file" and the given label, exercising the branch the V5 rationale
// claimed did not exist.
func v5MultipartUpload(t *testing.T, h *handler.BlobHandler, label string) *httptest.ResponseRecorder {
	t.Helper()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", "invoice.bin")
	if err != nil {
		t.Fatalf("build multipart: %v", err)
	}
	if _, err := fw.Write([]byte("ciphertext")); err != nil {
		t.Fatalf("write multipart part: %v", err)
	}
	if err := mw.WriteField("label", label); err != nil {
		t.Fatalf("write label field: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}

	req := v5Authenticated(httptest.NewRequest(http.MethodPost, "/user/blobs", &body))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.Upload(rec, req)
	return rec
}

// --- V5.3.1 / V5.4.3 — what the remaining Not Applicable rows rest on ---

// Two V5 rows stay Not Applicable, and both now rest on a property rather than
// on the false "no uploads" premise.
//
// V5.3.1 asks that uploaded files stored in a public folder are not executed.
// Nothing vault42 receives is written to a filesystem path at all: the blob
// write path goes to the repository and nowhere else.
//
// V5.4.3 asks for antivirus scanning of files from untrusted sources. There is
// no scanner, and what makes that defensible is that the scanner's purpose --
// stopping known-malicious content being *served to someone else* -- has no
// reachable path here: every read is scoped to the pseudonym derived from the
// caller's own subject.
func TestASVS_V5_3_1_And_V5_4_3_StoredBytesTouchNoFilesystemAndReachNoOtherUser(t *testing.T) {
	// V5.3.1: no filesystem write anywhere in the blob path.
	filesystemWriters := []string{
		"os.Create", "os.WriteFile", "os.OpenFile", "os.MkdirAll",
		"ioutil.WriteFile", "io.Copy",
	}
	for _, rel := range []string{"internal/service/blob.go", "internal/handler/blob.go"} {
		src := readCodeOnly(t, rel)
		for _, w := range filesystemWriters {
			if strings.Contains(src, w) {
				t.Errorf("V5.3.1: %s calls %s. Uploaded bytes are supposed to reach the repository "+
					"and nothing else; a filesystem path makes the 'never served from a public "+
					"folder' reason false.", rel, w)
			}
		}
	}

	// V5.4.3: every read is owner-scoped. The service derives a pseudonym from
	// the caller's subject and every repository read is keyed by it, so an
	// uploaded object is only ever returned to the account that uploaded it.
	svcSrc := readCodeOnly(t, "internal/service/blob.go")
	for _, want := range []string{
		"func (s *BlobService) Pseudonym(userID string) string",
		"GetByIDAndPseudonym",
		"GetByRefAndPseudonym",
	} {
		if !strings.Contains(svcSrc, want) {
			t.Errorf("V5.4.3: internal/service/blob.go no longer carries %q. Owner scoping is the "+
				"whole reason a missing antivirus scanner is defensible: without it, a stored "+
				"object can reach a user who did not upload it.", want)
		}
	}

	// And the handler passes the authenticated subject, not a request value.
	handlerSrc := readCodeOnly(t, "internal/handler/blob.go")
	if strings.Count(handlerSrc, "claims.Subject") < 4 {
		t.Error("V5.4.3: the blob handler no longer scopes its service calls by claims.Subject on " +
			"every path")
	}

	// A read must not be keyed by anything the caller can choose other than the
	// object id, which is checked against the caller's own pseudonym anyway.
	var offenders []string
	for _, pf := range productionGoFiles(t) {
		if !strings.HasSuffix(pf.path, "internal/handler/blob.go") {
			continue
		}
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := selectorName(call.Fun)
			if name != "h.svc.Download" && name != "h.svc.DownloadNamed" && name != "h.svc.List" {
				return true
			}
			if len(call.Args) < 2 {
				return true
			}
			if renderNode(t, pf, call.Args[1]) != "claims.Subject" {
				offenders = append(offenders, pf.pos(call))
			}
			return true
		})
	}
	if len(offenders) > 0 {
		t.Errorf("V5.4.3: blob reads at %v are scoped by something other than claims.Subject", offenders)
	}
}

// v5BlobID pulls the blob id out of an upload response.
func v5BlobID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	body := rec.Body.String()
	const key = `"id":"`
	i := strings.Index(body, key)
	if i < 0 {
		t.Fatalf("no blob id in upload response: %s", body)
	}
	rest := body[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("malformed blob id in upload response: %s", body)
	}
	return rest[:j]
}
