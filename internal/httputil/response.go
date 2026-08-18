// Package httputil provides HTTP response helper functions for writing JSON responses.
package httputil

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("httputil: failed to encode response: %v", err)
	}
}

// WriteError writes a JSON error response with the given status code and message.
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"error": message})
}

// BearerRealm names the RFC 7235 protection space that vault42's bearer-token
// endpoints share. Every access token is minted for the same issuer and
// audience, so there is exactly one realm and it is a constant rather than a
// per-route string.
const BearerRealm = "vault42"

// RFC 6750 §3.1 error codes. These are the whole registry that section defines;
// nothing else may appear in the "error" attribute of a Bearer challenge.
const (
	// BearerErrInvalidRequest — the request is malformed: the credential was
	// sent more than one way, or a required parameter is missing.
	BearerErrInvalidRequest = "invalid_request"
	// BearerErrInvalidToken — the credential presented is expired, revoked,
	// malformed, or otherwise unusable.
	BearerErrInvalidToken = "invalid_token"
	// BearerErrInsufficientScope — the credential is valid but does not carry
	// the scope this resource requires.
	BearerErrInsufficientScope = "insufficient_scope"
)

// authParamSanitizer strips the characters that would end an auth-param's
// quoted string early and let a value forge a second parameter or a header.
// Every value vault42 puts in a challenge today is a compile-time constant, so
// this replaces nothing in practice; it is here so that stops being load-bearing.
var authParamSanitizer = strings.NewReplacer(`"`, "", `\`, "", "\r", "", "\n", "")

// BearerChallenge is the WWW-Authenticate value RFC 6750 §3 requires on a 401
// or 403 from a bearer-protected resource.
//
// An empty Error means a bare challenge, which is what §3 mandates when the
// request presented no bearer credential at all: naming an error code would
// describe a credential the client never sent, and leaks whether a guessed
// token was well-formed. Scope is set only alongside insufficient_scope, where
// §3 defines it as the scope required to reach the resource.
type BearerChallenge struct {
	Error       string
	Description string
	Scope       string
}

// String renders the challenge as a WWW-Authenticate header value.
func (c BearerChallenge) String() string {
	v := `Bearer realm="` + BearerRealm + `"`
	if c.Error != "" {
		v += `, error="` + authParamSanitizer.Replace(c.Error) +
			`", error_description="` + authParamSanitizer.Replace(c.Description) + `"`
	}
	if c.Scope != "" {
		v += `, scope="` + authParamSanitizer.Replace(c.Scope) + `"`
	}
	return v
}

// WriteBearerError writes the RFC 6750 challenge header and the JSON error body
// together, so a rejection cannot ship one without the other.
func WriteBearerError(w http.ResponseWriter, status int, message string, c BearerChallenge) {
	w.Header().Set("WWW-Authenticate", c.String())
	WriteError(w, status, message)
}
