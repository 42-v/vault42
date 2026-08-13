//go:build !stress

package stress

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// VAULT_STRESS_REQUIRED makes a skipped run a failure. The default is a skip
// so `go test ./...` on a laptop is not red.
const stressRequiredEnv = "VAULT_STRESS_REQUIRED"

func stressSkipNotice() string {
	return fmt.Sprintf(
		"SKIP stress: compiled without -tags stress.\n"+
			"This suite load-generates against a live vault (default https://vault.localhost),\n"+
			"uses kubectl to flip email_verified, and talks to Mailpit. A GitHub Actions\n"+
			"ubuntu-latest job has none of those.\n"+
			"Nothing in this suite ran. Set %s=1 to make this a failure.\n",
		stressRequiredEnv)
}

// TestMain is the loud skip. Without it, `go test ./tests/stress` with no
// build tag reports "[no test files]" and exits 0, which occupied the slot
// where a real run would be missed.
func TestMain(m *testing.M) {
	fmt.Fprint(os.Stderr, stressSkipNotice())
	if os.Getenv(stressRequiredEnv) == "1" {
		fmt.Fprintf(os.Stderr,
			"FAIL stress: %s=1 but this binary was built without -tags stress.\n"+
				"Point VAULT_STRESS_URL at a deployed vault and run with -tags stress, or unset\n"+
				"%s only where a skipped run is genuinely acceptable, which is not a release gate.\n",
			stressRequiredEnv, stressRequiredEnv)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestStressSkipNoticeNamesRequiredEnv(t *testing.T) {
	// Exists so `go test ./tests/stress` without the tag is not
	// "no test files". The notice must keep naming the env var a gate sets.
	msg := stressSkipNotice()
	if !strings.Contains(msg, stressRequiredEnv) {
		t.Fatalf("skip notice must name %s so a gate can make the skip fatal", stressRequiredEnv)
	}
	if !strings.Contains(msg, "Nothing in this suite ran") {
		t.Fatal("skip notice must say that nothing ran, otherwise a green result looks like a real run")
	}
	if !strings.Contains(msg, "-tags stress") {
		t.Fatal("skip notice must name the build tag the load suite needs")
	}
}
