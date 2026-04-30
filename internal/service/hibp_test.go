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

func TestHIBPBreachedPassword(t *testing.T) {
	password := "breached-password-test"
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password)))
	suffix := hash[5:]

	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			body := fmt.Sprintf("AABBCCDDEE112233445566778899AABB:3\r\n%s:42\r\nDDEEFF00112233445566778899AABB00:1\r\n", suffix)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	})

	if !h.IsBreached(password) {
		t.Error("should detect breached password when suffix is in response")
	}
}

func TestHIBPCleanPassword(t *testing.T) {
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			body := "AABBCCDDEE112233445566778899AABB:3\r\nDDEEFF00112233445566778899AABB00:1\r\n"
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	})

	if h.IsBreached("some-unique-password-not-in-list") {
		t.Error("should not detect clean password as breached")
	}
}

func TestHIBPServerDown(t *testing.T) {
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("connection refused")
		},
	})

	if h.IsBreached("any-password-here") {
		t.Error("should fail open (return false) when HIBP is unreachable")
	}
}

func TestHIBPNon200(t *testing.T) {
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader("Internal Server Error")),
			}, nil
		},
	})

	if h.IsBreached("any-password-here") {
		t.Error("should fail open (return false) on non-200 response")
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
