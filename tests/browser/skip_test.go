//go:build !browser

package browser_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// VAULT_BROWSER_REQUIRED makes a skipped run a failure. The default is a skip
// so `go test` in this module without -tags browser is not red.
const browserRequiredEnv = "VAULT_BROWSER_REQUIRED"

func browserSkipNotice() string {
	return fmt.Sprintf(
		"SKIP browser: compiled without -tags browser.\n"+
			"This is a separate Go module (tests/browser/go.mod) that needs chromedp, a\n"+
			"Chrome/Chromium binary, a reachable vault, kubectl (to verify emails) and Mailpit.\n"+
			"A default GitHub Actions runner has none of those, and the parent module does not\n"+
			"even see this directory.\n"+
			"Nothing in this suite ran. Set %s=1 to make this a failure.\n",
		browserRequiredEnv)
}

// TestMain is the loud skip. Without it, `go test` in this module with no
// build tag reports "[no test files]" and exits 0.
func TestMain(m *testing.M) {
	fmt.Fprint(os.Stderr, browserSkipNotice())
	if os.Getenv(browserRequiredEnv) == "1" {
		fmt.Fprintf(os.Stderr,
			"FAIL browser: %s=1 but this binary was built without -tags browser.\n"+
				"This suite cannot run on a default GitHub Actions runner. Unset %s only where a\n"+
				"skipped run is genuinely acceptable, which is not a release gate.\n",
			browserRequiredEnv, browserRequiredEnv)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestBrowserSkipNoticeNamesRequiredEnv(t *testing.T) {
	// Exists so `go test` in this module without the tag is not
	// "no test files". If the notice stops naming the env var, a CI step
	// cannot turn the skip into a failure.
	msg := browserSkipNotice()
	if !strings.Contains(msg, browserRequiredEnv) {
		t.Fatalf("skip notice must name %s so a gate can make the skip fatal", browserRequiredEnv)
	}
	if !strings.Contains(msg, "Nothing in this suite ran") {
		t.Fatal("skip notice must say that nothing ran, otherwise a green result looks like a real run")
	}
	if !strings.Contains(msg, "chromedp") {
		t.Fatal("skip notice must name chromedp, the reason this is a separate module")
	}
}
