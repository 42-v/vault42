package handler

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The blob label is user-supplied and is echoed back in a response header on download. A
// label containing CR or LF would end the header and begin another one — the attacker
// writes their own headers into a response the victim's browser trusts, which is a
// response-splitting bug (set a cookie, poison a cache, forge a redirect).
//
// Stripping every control character, not just CRLF, is the right shape: a bare NUL or a
// tab is enough to confuse an intermediary even when the browser copes.
func TestSanitizeLabelForHeader_StripsControlCharacters(t *testing.T) {
	cases := []struct {
		name  string
		label string
		want  string
	}{
		{"CRLF header injection", "invoice\r\nSet-Cookie: admin=1", "invoiceSet-Cookie: admin=1"},
		{"bare LF", "invoice\nX-Injected: yes", "invoiceX-Injected: yes"},
		{"bare CR", "invoice\rX-Injected: yes", "invoiceX-Injected: yes"},
		{"NUL byte", "invoice\x00.pdf", "invoice.pdf"},
		{"tab", "invoice\tsummary", "invoicesummary"},
		{"a clean label is untouched", "Q3 invoice (final).pdf", "Q3 invoice (final).pdf"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeLabelForHeader(tc.label)

			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if strings.ContainsAny(got, "\r\n\x00\t") {
				t.Errorf("a control character survived into a header value: %q", got)
			}
		})
	}
}

// errReader fails partway through, which is what a client that hangs up mid-upload looks
// like from the server's side.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// A body that cannot be read is not an empty body. If the read error were swallowed, the
// handler would carry on and store a truncated blob — or an empty one — as though the
// user had uploaded it, and the user's real document would be silently replaced by
// nothing.
func TestBlobUpload_UnreadableBodyIsNotStoredAsEmpty(t *testing.T) {
	h := NewBlobHandler(nil, newTestAuditLogger(), 1, 1<<20)

	req := httptest.NewRequest(http.MethodPost, "/user/blobs", io.NopCloser(errReader{}))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
		t.Fatalf("status = %d — an unreadable upload was accepted", rec.Code)
	}
}
