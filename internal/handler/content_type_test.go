package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeJSONIgnoresContentType pins what vault42 actually does with the
// Content-Type header on a request body: nothing.
//
// This replaces three tests that lived in tests/attack, were named for a
// content-type control, and could not fail. They built their own local
// http.HandlerFunc, decoded a body with encoding/json, and reported the status
// with t.Logf and no assertion. So they proved a property of the Go standard
// library rather than anything about this service, in the suite whose whole
// purpose is to show that an attack does not work.
//
// The behavior is pinned here, against the decoder every route actually uses,
// and stated plainly: vault42 does not enforce Content-Type. Anyone reaching for
// these tests as evidence of a CSRF or content-type defense can see in one line
// that they are not one. The refresh cookie is SameSite=Strict and the API is
// bearer-token authenticated, which is what carries that weight today.
//
// If enforcement is added later, this test is where the decision becomes
// visible: it will fail, and its replacement should assert 415 on everything
// that is not application/json or a +json suffix.
func TestDecodeJSONIgnoresContentType(t *testing.T) {
	const body = `{"email":"user@example.com"}`

	for _, contentType := range []string{
		"application/json",
		"text/plain",
		"application/xml",
		"application/x-www-form-urlencoded",
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
				t.Fatalf("decodeJSON rejected a valid JSON body sent as %q: %v. vault42 does not "+
					"look at Content-Type, so every one of these must decode identically; a "+
					"difference here means enforcement was added and this test is the record of "+
					"it not existing.", contentType, err)
			}
			if dst.Email != "user@example.com" {
				t.Errorf("email = %q, want user@example.com", dst.Email)
			}
		})
	}
}
