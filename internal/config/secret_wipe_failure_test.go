package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliconfigCaptureLog redirects the standard logger for the duration of fn and
// returns everything written to it.
func cliconfigCaptureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	oldOut := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
	})
	fn()
	return buf.String()
}

// cliconfigRequireUnprivileged skips when the test runs as root, where the
// permission bits the wipe-failure cases rely on are not enforced.
func cliconfigRequireUnprivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: file permissions do not deny the wipe")
	}
}

// The consume wipe is defense in depth, not the load itself. When the zeroing
// or the removal fails the operator must still get the secret back (otherwise a
// read-only mount would take the service down), and the failure must be visible
// in the log without the secret value in it.
func TestLoadSecret_ConsumeWipeFailuresAreLoggedAndNonFatal(t *testing.T) {
	const secret = "super-secret-master-key"

	t.Run("zeroing the file fails", func(t *testing.T) {
		cliconfigRequireUnprivileged(t)
		dir := t.TempDir()
		f := filepath.Join(dir, "secret")
		if err := os.WriteFile(f, []byte(secret+"\n"), 0o400); err != nil {
			t.Fatal(err)
		}
		t.Setenv("WIPEFAIL_KEY_FILE", f)
		t.Setenv("VAULT_SECRET_FILE_CONSUME", "true")

		var val string
		var err error
		logged := cliconfigCaptureLog(t, func() {
			val, err = LoadSecret("WIPEFAIL_KEY")
		})

		if err != nil {
			t.Fatalf("LoadSecret must succeed despite a failed wipe: %v", err)
		}
		if val != secret {
			t.Fatalf("LoadSecret = %q, want %q", val, secret)
		}
		if !strings.Contains(logged, "failed to zero secret file") {
			t.Errorf("wipe failure was swallowed, log was %q", logged)
		}
		if strings.Contains(logged, secret) {
			t.Error("log leaked the secret value")
		}
		if _, statErr := os.Stat(f); statErr == nil {
			t.Error("removal should still have consumed the file")
		}
	})

	t.Run("removing the file fails", func(t *testing.T) {
		cliconfigRequireUnprivileged(t)
		dir := t.TempDir()
		f := filepath.Join(dir, "secret")
		if err := os.WriteFile(f, []byte(secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		t.Setenv("REMOVEFAIL_KEY_FILE", f)
		t.Setenv("VAULT_SECRET_FILE_CONSUME", "true")

		var val string
		var err error
		logged := cliconfigCaptureLog(t, func() {
			val, err = LoadSecret("REMOVEFAIL_KEY")
		})

		if err != nil {
			t.Fatalf("LoadSecret must succeed despite a failed removal: %v", err)
		}
		if val != secret {
			t.Fatalf("LoadSecret = %q, want %q", val, secret)
		}
		if !strings.Contains(logged, "failed to remove secret file") {
			t.Errorf("removal failure was swallowed, log was %q", logged)
		}
		if strings.Contains(logged, secret) {
			t.Error("log leaked the secret value")
		}
		onDisk, readErr := os.ReadFile(f)
		if readErr != nil {
			t.Fatalf("file should still exist: %v", readErr)
		}
		if bytes.Contains(onDisk, []byte(secret)) {
			t.Error("zeroing did not run before the failed removal")
		}
	})
}

// A path carrying CR/LF must not be able to forge extra log records (CWE-117).
func TestLoadSecret_ConsumeWipeFailureQuotesPath(t *testing.T) {
	cliconfigRequireUnprivileged(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "secret\ninjected FATAL line")
	if err := os.WriteFile(f, []byte("value"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INJECT_KEY_FILE", f)
	t.Setenv("VAULT_SECRET_FILE_CONSUME", "true")

	logged := cliconfigCaptureLog(t, func() {
		if _, err := LoadSecret("INJECT_KEY"); err != nil {
			t.Fatalf("LoadSecret: %v", err)
		}
	})

	if !strings.Contains(logged, `\ninjected FATAL line`) {
		t.Errorf("path was not quoted in the warning, log was %q", logged)
	}
	for _, line := range strings.Split(strings.TrimSuffix(logged, "\n"), "\n") {
		if !strings.Contains(line, "WARNING: failed to") {
			t.Errorf("newline in the path forged a log record: %q", line)
		}
	}
}
