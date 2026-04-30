package handler

import (
	"encoding/json"
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

// decodeJSON decodes a JSON request body into dst. Unknown fields are rejected
// to enforce strict API contracts — clients must not send unrecognized fields.
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
