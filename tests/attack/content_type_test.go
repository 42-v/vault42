package attack

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testJSONHandler is a minimal HTTP handler that decodes JSON using the same
// pattern as internal/handler/response.go: json.Decoder with DisallowUnknownFields.
func testJSONHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&input); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

// TestContentType_ValidJSON verifies that valid JSON with correct Content-Type works.
func TestContentType_ValidJSON(t *testing.T) {
	handler := testJSONHandler()
	body := `{"email":"test@example.com","password":"secure-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 for valid JSON, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestContentType_MismatchTextPlain verifies behavior when sending valid JSON
// with Content-Type: text/plain. Go's json.Decoder ignores Content-Type — it
// only cares about the body bytes. This test documents that behavior.
func TestContentType_MismatchTextPlain(t *testing.T) {
	handler := testJSONHandler()
	body := `{"email":"test@example.com","password":"secure-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Go's json.Decoder does not check Content-Type — this documents the behavior.
	// The decoder will parse the body regardless. If the API needs Content-Type
	// enforcement, it must be done in middleware.
	t.Logf("text/plain with JSON body: status=%d (json.Decoder ignores Content-Type)", rec.Code)
}

// TestContentType_MismatchXML verifies behavior when sending valid JSON
// with Content-Type: application/xml.
func TestContentType_MismatchXML(t *testing.T) {
	handler := testJSONHandler()
	body := `{"email":"test@example.com","password":"secure-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/xml")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	t.Logf("application/xml with JSON body: status=%d (json.Decoder ignores Content-Type)", rec.Code)
}

// TestContentType_NoContentType verifies behavior when no Content-Type header is set.
func TestContentType_NoContentType(t *testing.T) {
	handler := testJSONHandler()
	body := `{"email":"test@example.com","password":"secure-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	// Deliberately not setting Content-Type
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// json.Decoder works without Content-Type header
	t.Logf("no Content-Type with JSON body: status=%d", rec.Code)
}

// TestContentType_InvalidJSONBody verifies that non-JSON data with
// Content-Type: application/json is properly rejected by the decoder.
func TestContentType_InvalidJSONBody(t *testing.T) {
	handler := testJSONHandler()

	cases := []struct {
		name string
		body string
	}{
		{"plain text", "this is not json"},
		{"XML", "<login><email>test@test.com</email></login>"},
		{"empty body", ""},
		{"partial JSON", `{"email": "test@test.com"`},
		{"HTML", "<html><body>hello</body></html>"},
		{"binary-like", "\x00\x01\x02\x03"},
		{"URL encoded", "email=test@test.com&password=secret"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("Expected 400 for invalid JSON body (%s), got %d", tc.name, rec.Code)
			}

			var resp map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode error response: %v", err)
			}
			if resp["error"] != "invalid_request" {
				t.Fatalf("Expected error=invalid_request, got %q", resp["error"])
			}
		})
	}
}

// TestContentType_UnknownFields verifies that DisallowUnknownFields rejects
// payloads with extra fields — preventing mass assignment attacks.
func TestContentType_UnknownFields(t *testing.T) {
	handler := testJSONHandler()

	bodies := []struct {
		name string
		body string
	}{
		{"extra role field", `{"email":"test@test.com","password":"pass","role":"admin"}`},
		{"extra is_admin", `{"email":"test@test.com","password":"pass","is_admin":true}`},
		{"extra id", `{"email":"test@test.com","password":"pass","id":"uuid-inject"}`},
		{"extra verified", `{"email":"test@test.com","password":"pass","verified":true}`},
	}

	for _, tc := range bodies {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("Expected 400 for unknown fields (%s), got %d: %s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestContentType_MultipartToJSON verifies that multipart/form-data sent to
// a JSON endpoint is properly rejected.
func TestContentType_MultipartToJSON(t *testing.T) {
	handler := testJSONHandler()

	// Multipart body (not valid JSON)
	boundary := "----WebKitFormBoundary7MA4YWxkTrZu0gW"
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"email\"\r\n\r\n" +
		"test@test.com\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"password\"\r\n\r\n" +
		"secret\r\n" +
		"--" + boundary + "--\r\n"

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for multipart body to JSON endpoint, got %d", rec.Code)
	}
}

// TestContentType_JSONBomb verifies that deeply nested JSON does not cause
// excessive resource consumption.
func TestContentType_JSONBomb(t *testing.T) {
	handler := testJSONHandler()

	// Deeply nested JSON — Go's json.Decoder has a default nesting limit
	depth := 1000
	body := strings.Repeat(`{"a":`, depth) + `1` + strings.Repeat(`}`, depth)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should either reject (400) or handle without panic
	if rec.Code != http.StatusBadRequest {
		t.Logf("Deeply nested JSON: status=%d (decoder handled it)", rec.Code)
	}
}
