//go:build !honeypot_e2e

package honeypot_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// VAULT_HONEYPOT_E2E_REQUIRED makes a skipped run a failure. The default is a
// skip so `go test ./...` on a laptop is not red.
const honeypotRequiredEnv = "VAULT_HONEYPOT_E2E_REQUIRED"

func honeypotSkipNotice() string {
	return fmt.Sprintf(
		"SKIP honeypot: compiled without -tags honeypot_e2e.\n"+
			"The container suite needs locally-tagged vault:dev and vault-bridge:dev images,\n"+
			"a Docker daemon, and five containers (2x Postgres, 2x Vault, bridge). Sibling\n"+
			"containers are given host-mapped DB ports, which do not reach each other on a\n"+
			"default GitHub Actions runner.\n"+
			"Nothing in this suite ran. Set %s=1 to make this a failure.\n",
		honeypotRequiredEnv)
}

// TestMain is the loud skip. Without it, `go test ./tests/honeypot` with no
// build tag reports "[no test files]" and exits 0, which is the failure mode
// this package used to have: a green result for doing nothing.
func TestMain(m *testing.M) {
	fmt.Fprint(os.Stderr, honeypotSkipNotice())
	if os.Getenv(honeypotRequiredEnv) == "1" {
		fmt.Fprintf(os.Stderr,
			"FAIL honeypot: %s=1 but this binary was built without -tags honeypot_e2e.\n"+
				"Build the images, run with -tags honeypot_e2e, or unset %s only where a\n"+
				"skipped run is genuinely acceptable, which is not a release gate.\n",
			honeypotRequiredEnv, honeypotRequiredEnv)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestHoneypotSkipNoticeNamesRequiredEnv(t *testing.T) {
	// Exists so `go test ./tests/honeypot` without the tag is not
	// "no test files". If the notice stops naming the env var, a CI step
	// cannot turn the skip into a failure.
	msg := honeypotSkipNotice()
	if !strings.Contains(msg, honeypotRequiredEnv) {
		t.Fatalf("skip notice must name %s so a gate can make the skip fatal", honeypotRequiredEnv)
	}
	if !strings.Contains(msg, "Nothing in this suite ran") {
		t.Fatal("skip notice must say that nothing ran, otherwise a green result looks like a real run")
	}
	if !strings.Contains(msg, "honeypot_e2e") {
		t.Fatal("skip notice must name the build tag the container suite needs")
	}
}
