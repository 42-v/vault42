package service

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Additional HIBP tests (~10)
// ---------------------------------------------------------------------------

func TestHIBPEmptyResponse(t *testing.T) {
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		},
	})

	if h.IsBreached("some-password-for-empty-test") {
		t.Error("empty response should return not breached")
	}
}

func TestHIBPNetworkTimeout(t *testing.T) {
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("i/o timeout")
		},
	})

	if h.IsBreached("password-during-timeout") {
		t.Error("network timeout should fail open (return false)")
	}
}

func TestHIBPConnectionRefused(t *testing.T) {
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("dial tcp: connection refused")
		},
	})

	if h.IsBreached("password-conn-refused") {
		t.Error("connection refused should fail open")
	}
}

func TestHIBPMalformedResponse(t *testing.T) {
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			// Malformed: no colon delimiter, random garbage
			body := "this-is-not-valid-data\nALSO_INVALID"
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	})

	if h.IsBreached("password-for-malformed-test") {
		t.Error("malformed response should return not breached")
	}
}

func TestHIBPSuffixCaseInsensitive(t *testing.T) {
	password := "case-insensitive-test-pw"
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password)))
	suffix := hash[5:]

	// Return suffix in lowercase
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			body := fmt.Sprintf("%s:10\r\n", strings.ToLower(suffix))
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	})

	if !h.IsBreached(password) {
		t.Error("suffix comparison should be case-insensitive")
	}
}

func TestHIBPMultipleSuffixesNoMatch(t *testing.T) {
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			body := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA11:5\r\n" +
				"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB22:3\r\n" +
				"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC33:1\r\n"
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	})

	if h.IsBreached("unique-password-not-breached") {
		t.Error("should not match when suffix is not in response")
	}
}

func TestHIBPHTTP429RateLimit(t *testing.T) {
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       io.NopCloser(strings.NewReader("Rate limit exceeded")),
			}, nil
		},
	})

	if h.IsBreached("rate-limited-password") {
		t.Error("429 response should fail open")
	}
}

func TestHIBPHTTP403Forbidden(t *testing.T) {
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(strings.NewReader("Forbidden")),
			}, nil
		},
	})

	if h.IsBreached("forbidden-password") {
		t.Error("403 response should fail open")
	}
}

func TestHIBPCorrectPrefixSent(t *testing.T) {
	password := "prefix-check-password-here"
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password)))
	expectedPrefix := hash[:5]

	var capturedPath string
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			capturedPath = req.URL.Path
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		},
	})

	h.IsBreached(password)

	if !strings.HasSuffix(capturedPath, "/"+expectedPrefix) {
		t.Errorf("request path should end with /%s, got %q", expectedPrefix, capturedPath)
	}
}

func TestHIBPSingleLineMatch(t *testing.T) {
	password := "single-line-match-test"
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password)))
	suffix := hash[5:]

	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			// Only one line, the matching one
			body := fmt.Sprintf("%s:1\r\n", suffix)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	})

	if !h.IsBreached(password) {
		t.Error("should detect breach with single-line response")
	}
}
