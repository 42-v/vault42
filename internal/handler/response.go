package handler

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/42-v/vault42/internal/httputil"
)

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, data any) {
	httputil.WriteJSON(w, status, data)
}

// WriteError writes a JSON error response with the given status code and message.
func WriteError(w http.ResponseWriter, status int, message string) {
	httputil.WriteError(w, status, message)
}

// errBodyContentType is decodeJSON's refusal of a body labelled as an HTML form,
// or labelled with something that does not parse as a media type at all.
var errBodyContentType = errors.New("request body content type is a form type or malformed")

// decodeJSON decodes a JSON request body into dst. Unknown fields are rejected
// to enforce strict API contracts — clients must not send unrecognized fields.
//
// A body labelled with one of the three content types an HTML form can submit
// is refused. That is what closes login CSRF: a cross-site
// <form enctype="text/plain"> whose input name and value split a JSON object
// around the "=" the encoding inserts -- name {"email":"a@evil","password":"pw
// and value x"} -- submits {"email":"a@evil","password":"pw=x"} plus a CRLF the
// decoder reads as whitespace. It needs no preflight and is a top-level
// navigation, so the browser stores the __Host-refresh_token cookie the
// response sets even though it is SameSite=Strict (SameSite governs sending, and
// storing on a navigation is allowed), and the victim's browser is signed in to
// the attacker's account. A cross-site fetch cannot do the same: it is not a
// navigation, so the response may not set a SameSite cookie. A request with no
// Content-Type is still decoded, since no form submission omits one and the
// first-party clients always label their JSON.
//
// Anything after the JSON value is refused too, so a body has one reading.
func decodeJSON(r *http.Request, dst any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil {
			return errBodyContentType
		}
		switch mt {
		case "text/plain", "application/x-www-form-urlencoded", "multipart/form-data":
			return errBodyContentType
		}
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON body")
	}
	return nil
}
