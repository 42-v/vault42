package compliance

import (
	"bytes"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// =============================================================================
// OWASP ASVS 5.0.0 — V3.2.1, V5.4.1 and V5.1.1
//
// Three rows pointed at one missing line. V3.2.1 names "the attachment
// disposition type in the Content-Disposition header field" as one of its
// example controls, V5.4.1 requires the header outright, and V5.1.1 requires
// the documentation to say how stored objects are made safe for an end user to
// download — a clause that could not be written while there was nothing to
// describe.
//
// Each row gets its own assertion here rather than one test cited three times.
// V3.2.1 turns on the disposition *type*, V5.4.1 on the *filename parameter*,
// and V5.1.1 on the *documentation*: a single test asserting "the header is
// present" would be evidence for none of them individually and would keep
// passing after a change that broke two.
//
// These drive the real handler through the real service.
// =============================================================================

// v3StoredBlob uploads through the shipped handler and returns the id it was
// stored under, so a download is a download of something this suite really put
// there.
func v3StoredBlob(t *testing.T) (*httptest.ResponseRecorder, string) {
	t.Helper()
	h, stored := v5Handler(t, 1<<20)

	req := v5Authenticated(httptest.NewRequest(http.MethodPost, "/user/blobs", bytes.NewReader([]byte("stored bytes"))))
	rec := httptest.NewRecorder()
	h.Upload(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seeding an upload answered %d: %s", rec.Code, rec.Body.String())
	}
	if len(stored) != 1 {
		t.Fatalf("seeding stored %d blobs, want 1", len(stored))
	}
	var id string
	for k := range stored {
		id = k
	}

	dl := httptest.NewRequest(http.MethodGet, "/user/blobs/"+id, nil)
	dl.SetPathValue("id", id)
	out := httptest.NewRecorder()
	h.Download(out, v5Authenticated(dl))
	if out.Code != http.StatusOK {
		t.Fatalf("downloading the seeded blob answered %d: %s", out.Code, out.Body.String())
	}
	return out, id
}

// --- V3.2.1 — the rendering context ---

// "Verify that security controls are in place to prevent browsers from
// rendering content or functionality in HTTP responses in an incorrect
// context … using the attachment disposition type in the Content-Disposition
// header field."
//
// The assertion is on the disposition type specifically. `inline` would be a
// Content-Disposition header and would be the rendering this requirement is
// about, so "the header exists" is not the control.
func TestASVS_V3_2_1_ABlobDownloadCarriesTheAttachmentDispositionType(t *testing.T) {
	rec, _ := v3StoredBlob(t)

	raw := rec.Header().Get("Content-Disposition")
	if raw == "" {
		t.Fatal("V3.2.1: a blob download sets no Content-Disposition, so a browser navigated at the URL " +
			"decides for itself whether to render the bytes")
	}
	disposition, _, err := mime.ParseMediaType(raw)
	if err != nil {
		t.Fatalf("V3.2.1: Content-Disposition %q does not parse: %v", raw, err)
	}
	if disposition != "attachment" {
		t.Errorf("V3.2.1: disposition type is %q, want \"attachment\"; %q is the rendering context this "+
			"requirement exists to prevent", disposition, disposition)
	}
}

// --- V5.4.1 — a filename in the response ---

// "Verify that the application validates or ignores user-submitted filenames …
// and specifies a filename in the Content-Disposition header field in the
// response."
//
// Two clauses. The first already held through validRefName on the upload path.
// This asserts the second, and asserts that what lands in the parameter is the
// server's own reference rather than anything a caller wrote: the download
// paths do not run validRefName, so the header cannot borrow that guarantee.
func TestASVS_V5_4_1_ABlobDownloadSpecifiesAFilenameChosenByTheServer(t *testing.T) {
	rec, id := v3StoredBlob(t)

	_, params, err := mime.ParseMediaType(rec.Header().Get("Content-Disposition"))
	if err != nil {
		t.Fatalf("V5.4.1: Content-Disposition does not parse: %v", err)
	}
	if params["filename"] == "" {
		t.Fatal("V5.4.1: Content-Disposition names no filename; the requirement asks for one, not " +
			"merely for the header")
	}
	if params["filename"] != id {
		t.Errorf("V5.4.1: filename is %q, want the blob's own id %q", params["filename"], id)
	}

	// A caller-shaped reference must not be able to add a parameter. The name
	// path takes its value straight out of the route, so this is the reachable
	// half rather than a hypothetical one.
	h, _ := v5Handler(t, 1<<20)
	hostile := `x"; filename="payslip.html`
	req := httptest.NewRequest(http.MethodGet, "/user/blobs/named/x", nil)
	req.SetPathValue("name", hostile)
	out := httptest.NewRecorder()
	h.DownloadNamed(out, v5Authenticated(req))

	got := out.Header().Get("Content-Disposition")
	if strings.Contains(got, hostile) {
		t.Errorf("V5.4.1: a caller-supplied reference reached the header verbatim: %q", got)
	}
	if got != "" {
		if _, params, err := mime.ParseMediaType(got); err != nil {
			t.Errorf("V5.4.1: a caller-supplied reference made the header unparseable: %q (%v)", got, err)
		} else if params["filename"] == "payslip.html" {
			t.Errorf("V5.4.1: a caller-supplied reference added a second filename parameter: %q", got)
		}
	}
}

// --- V5.1.1 — the documentation clause ---

// "Verify that the documentation defines the permitted file types, expected
// file extensions, and maximum size … Additionally, ensure that the
// documentation specifies how files are made safe for end-users to download and
// process, such as how the application behaves when a malicious file is
// detected."
//
// The size half was already documented. This asserts the clause that was open,
// and asserts it against the header the documentation now describes rather than
// against the prose alone: a document that describes a control the code does not
// set is the failure mode this register was built to stop.
func TestASVS_V5_1_1_TheDocumentationSaysHowStoredObjectsAreMadeSafeToDownload(t *testing.T) {
	doc := readProductionSource(t, "docs/api.md")

	const heading = "How stored objects are made safe to download"
	if !strings.Contains(doc, heading) {
		t.Fatalf("V5.1.1: docs/api.md has no %q section; the requirement's second clause asks for one", heading)
	}
	for _, clause := range []struct{ what, text string }{
		{"the disposition type the download paths set", "Content-Disposition: attachment"},
		{"the scoping that makes cross-user delivery unreachable", "pseudonym"},
		{"the permitted-types answer the first clause asks for", "Permitted file types and extensions"},
		{"the maximum size", "VAULT_BLOB_MAX_SIZE"},
	} {
		if !strings.Contains(doc, clause.text) {
			t.Errorf("V5.1.1: docs/api.md does not state %s (%q)", clause.what, clause.text)
		}
	}

	// The prose is only worth anything if it is true, so the header it describes
	// is read off the shipped handler rather than trusted.
	rec, _ := v3StoredBlob(t)
	if !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment;") {
		t.Errorf("V5.1.1: docs/api.md documents an attachment disposition the code does not set; "+
			"the header was %q", rec.Header().Get("Content-Disposition"))
	}
}
