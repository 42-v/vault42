package service

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockTransport implements http.RoundTripper for testing.
type mockTransport struct {
	handler func(*http.Request) (*http.Response, error)
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.handler(req)
}

// newTestHIBPClient creates an HIBPClient with the given RoundTripper injected.
func newTestHIBPClient(transport http.RoundTripper) *HIBPClient {
	h := NewHIBPClient()
	h.client.Transport = transport
	return h
}

// hibpRange builds a range response body containing the given suffixes.
func hibpRange(suffixes ...string) string {
	var b strings.Builder
	for _, s := range suffixes {
		fmt.Fprintf(&b, "%s:42\r\n", s)
	}
	return b.String()
}

// suffixOf returns the part of the password's SHA-1 that the range response
// carries: everything after the 5-character prefix sent to the API.
func suffixOf(password string) string {
	return fmt.Sprintf("%X", sha1.Sum([]byte(password)))[5:]
}

// A password whose suffix is in the range response is breached, however the
// response is shaped and whichever case the suffix arrives in.
func TestHIBPBreachedPassword(t *testing.T) {
	const password = "breached-password-test"
	suffix := suffixOf(password)

	for _, tc := range []struct{ name, body string }{
		{"the only line", hibpRange(suffix)},
		{"among other suffixes", hibpRange("AABBCCDDEE112233445566778899AABB", suffix, "DDEEFF00112233445566778899AABB00")},
		{"lower-cased by the API", hibpRange(strings.ToLower(suffix))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHIBPClient(&mockTransport{
				handler: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(tc.body)),
					}, nil
				},
			})

			if !h.IsBreached(password) {
				t.Errorf("a range response with the password's suffix (%s) was not read as a breach", tc.name)
			}
		})
	}
}

// A 200 whose body does not carry the password's suffix means not breached,
// including when the body is empty or is not a range list at all: garbage must
// not be parsed into a match.
func TestHIBPCleanPassword(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty body", ""},
		{"other suffixes only", hibpRange("AABBCCDDEE112233445566778899AABB", "DDEEFF00112233445566778899AABB00")},
		{"several other suffixes", hibpRange("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA11", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB22", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC33")},
		{"not a range list", "this-is-not-valid-data\nALSO_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHIBPClient(&mockTransport{
				handler: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(tc.body)),
					}, nil
				},
			})

			if h.IsBreached("some-unique-password-not-in-list") {
				t.Errorf("a range response with no matching suffix (%s) was read as a breach", tc.name)
			}
		})
	}
}

// The breach check is advisory, so every way the API can fail to answer means
// "not breached": HIBP being down, rate-limiting or rejecting the client must
// never become a registration blocker.
func TestHIBPFailsOpen(t *testing.T) {
	transportError := func(msg string) *mockTransport {
		return &mockTransport{handler: func(_ *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("%s", msg)
		}}
	}
	status := func(code int, body string) *mockTransport {
		return &mockTransport{handler: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
		}}
	}

	for _, tc := range []struct {
		name      string
		transport *mockTransport
	}{
		{"network timeout", transportError("i/o timeout")},
		{"connection refused", transportError("dial tcp: connection refused")},
		{"server unreachable", transportError("connection refused")},
		{"500 from the API", status(http.StatusInternalServerError, "Internal Server Error")},
		{"429 rate limited", status(http.StatusTooManyRequests, "Rate limit exceeded")},
		{"403 forbidden", status(http.StatusForbidden, "Forbidden")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if newTestHIBPClient(tc.transport).IsBreached("any-password-here") {
				t.Errorf("%s reported the password as breached; an unanswered check must fail open", tc.name)
			}
		})
	}
}

func TestHIBPKAnonymity(t *testing.T) {
	password := "k-anonymity-test-password"
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password)))
	expectedPrefix := hash[:5]

	var capturedURL string
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			capturedURL = req.URL.String()
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		},
	})

	h.IsBreached(password)

	if capturedURL == "" {
		t.Fatal("request URL was not captured")
	}

	// Verify only the 5-char prefix is sent, not the full hash
	if !strings.HasSuffix(capturedURL, "/"+expectedPrefix) {
		t.Errorf("URL should end with /%s, got %q", expectedPrefix, capturedURL)
	}

	// Ensure the full hash is NOT in the URL
	if strings.Contains(capturedURL, hash) {
		t.Error("full hash should NOT be sent in the URL (k-anonymity violation)")
	}
}
