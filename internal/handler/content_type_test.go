package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeJSONRefusesABodySentAsAForm pins the Content-Type check that closes
// login CSRF.
//
// This replaces TestDecodeJSONIgnoresContentType, which recorded that vault42
// did not look at the header and argued SameSite=Strict carried the weight.
// It carries the weight for SENDING the refresh cookie, which is refresh CSRF.
// Login CSRF is the other direction: a cross-site <form enctype="text/plain">
// can submit a valid JSON login body, and a top-level navigation's response is
// allowed to SET a Strict cookie, so the victim's browser came away signed in
// to an attacker's account.
//
// The refusal is a deny-list of the three form encodings rather than an
// allow-list of application/json, because a form can only produce those three
// and a request with no Content-Type at all is how many non-browser clients
// and tests talk to this API.
func TestDecodeJSONRefusesABodySentAsAForm(t *testing.T) {
	// What a text/plain form actually puts on the wire: the input name and
	// value split around the "=" the encoding inserts, and a trailing CRLF.
	const formBody = "{\"email\":\"attacker@evil.example\",\"password\":\"pw=x\"}\r\n"

	for _, contentType := range []string{
		"text/plain",
		"text/plain;charset=UTF-8",
		"Text/Plain",
		"application/x-www-form-urlencoded",
		"multipart/form-data; boundary=x",
		"not a media type;;",
	} {
		t.Run(contentType, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(formBody))
			req.Header.Set("Content-Type", contentType)

			var dst struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}
			err := decodeJSON(req, &dst)
			if !errors.Is(err, errBodyContentType) {
				t.Fatalf("decodeJSON(%q) = %v, want errBodyContentType; a cross-site form can "+
					"send this without a preflight", contentType, err)
			}
			if dst.Email != "" {
				t.Errorf("the body was decoded anyway: email = %q", dst.Email)
			}
		})
	}
}

// TestDecodeJSONStillAcceptsWhatFirstPartyClientsSend is the other half: the
// check must not refuse a labelled JSON body, or a body with no label.
func TestDecodeJSONStillAcceptsWhatFirstPartyClientsSend(t *testing.T) {
	const body = `{"email":"user@example.com"}` + "\n"

	for _, contentType := range []string{
		"application/json",
		"application/json; charset=utf-8",
		"application/merge-patch+json",
		"", // omitted entirely
	} {
		name := contentType
		if name == "" {
			name = "no Content-Type header"
		}
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}

			var dst struct {
				Email string `json:"email"`
			}
			if err := decodeJSON(req, &dst); err != nil {
				t.Fatalf("decodeJSON rejected a JSON body sent as %q: %v", contentType, err)
			}
			if dst.Email != "user@example.com" {
				t.Errorf("email = %q, want user@example.com", dst.Email)
			}
		})
	}
}

// TestDecodeJSONRefusesTrailingData: a body has one reading. The decoder alone
// stops after the first value and would let anything follow it.
func TestDecodeJSONRefusesTrailingData(t *testing.T) {
	for _, body := range []string{
		`{"email":"a@example.com"}=`,
		`{"email":"a@example.com"}{"email":"b@example.com"}`,
		`{"email":"a@example.com"} x`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		var dst struct {
			Email string `json:"email"`
		}
		if err := decodeJSON(req, &dst); err == nil {
			t.Errorf("decodeJSON accepted %q", body)
		}
	}
}
