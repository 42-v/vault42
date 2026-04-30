package attack

import (
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/sanitize"
)

// TestXSSSanitization verifies that HTML special characters are properly escaped
// by the project's sanitize.String function.
func TestXSSSanitization(t *testing.T) {
	payloads := []struct {
		input    string
		contains string
	}{
		{`<script>alert('xss')</script>`, "<script>"},
		{`<img src=x onerror=alert(1)>`, "<img"},
		{`"><svg onload=alert(1)>`, "<svg"},
		{`<iframe src="evil.com">`, "<iframe"},
	}

	for _, tc := range payloads {
		t.Run(tc.input[:min(len(tc.input), 20)], func(t *testing.T) {
			result := sanitize.String(tc.input, 1000)
			if strings.Contains(result, tc.contains) {
				t.Fatalf("Sanitized output still contains %q: %s", tc.contains, result)
			}
		})
	}
}
