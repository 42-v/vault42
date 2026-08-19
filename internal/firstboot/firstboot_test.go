package firstboot

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// nonTerminal pins stdout as "not a terminal" for the duration of a test, which
// is what a container's stdout is and what makes the file sink the only sink.
func nonTerminal(t *testing.T) {
	t.Helper()
	old := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdoutIsTerminal = old })
}

func TestDeliver_WritesToTheFileSinkAtMode0600(t *testing.T) {
	nonTerminal(t)
	path := filepath.Join(t.TempDir(), "first-boot.env")
	t.Setenv(CredentialFileEnv, path)

	dest, err := Deliver("VAULT_ADMIN_TOKEN", "s3cret")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if dest != path {
		t.Errorf("dest = %q, want %q", dest, path)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("credential file is mode %#o, want 0600", perm)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "VAULT_ADMIN_TOKEN=s3cret\n" {
		t.Errorf("file holds %q", got)
	}
}

// One boot can mint several credentials — a seed file with three clients
// delivers three secrets — so the second delivery must extend the file rather
// than replace or refuse it.
func TestDeliver_AppendsSubsequentCredentials(t *testing.T) {
	nonTerminal(t)
	path := filepath.Join(t.TempDir(), "first-boot.env")
	t.Setenv(CredentialFileEnv, path)

	for _, c := range []struct{ label, value string }{{"A", "one"}, {"B", "two"}} {
		if _, err := Deliver(c.label, c.value); err != nil {
			t.Fatalf("Deliver(%s): %v", c.label, err)
		}
	}

	got, err := os.ReadFile(path) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "A=one\nB=two\n" {
		t.Errorf("file holds %q", got)
	}
}

// A symlink at the sink path is an attempt to have the process write the
// credential somewhere the attacker already reads. Lstat reports the link and
// not its target, which is what makes the regular-file test refuse it.
func TestDeliver_RefusesASymlinkedSink(t *testing.T) {
	nonTerminal(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "attacker-readable")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "first-boot.env")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv(CredentialFileEnv, link)

	if _, err := Deliver("VAULT_ADMIN_TOKEN", "s3cret"); err == nil {
		t.Fatal("Deliver followed a symlink at the sink path")
	}
	got, err := os.ReadFile(target) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("the symlink target was written to: %q", got)
	}
}

func TestDeliver_RefusesADirectorySink(t *testing.T) {
	nonTerminal(t)
	t.Setenv(CredentialFileEnv, t.TempDir())

	if _, err := Deliver("VAULT_ADMIN_TOKEN", "s3cret"); err == nil {
		t.Fatal("Deliver accepted a directory as the credential file")
	}
}

// A file the operator created with a stock umask is world-readable, and a
// credential written into it is disclosed to every uid on the host — which is
// the same failure as logging it, one directory along.
func TestDeliver_RefusesASinkOthersCanRead(t *testing.T) {
	nonTerminal(t)
	path := filepath.Join(t.TempDir(), "first-boot.env")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(CredentialFileEnv, path)

	_, err := Deliver("VAULT_ADMIN_TOKEN", "s3cret")
	if err == nil {
		t.Fatal("Deliver wrote a credential into a file others can read")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("error does not tell the operator how to fix it: %v", err)
	}
}

func TestDeliver_ReportsAnUncreatableSink(t *testing.T) {
	nonTerminal(t)
	t.Setenv(CredentialFileEnv, filepath.Join(t.TempDir(), "no-such-dir", "first-boot.env"))

	if _, err := Deliver("VAULT_ADMIN_TOKEN", "s3cret"); err == nil {
		t.Fatal("Deliver reported success for a path it could not create")
	}
}

// A newline in a label would forge an extra credential line, and a client name
// comes straight out of an operator-supplied seed file.
func TestDeliver_LabelCannotForgeAnExtraLine(t *testing.T) {
	nonTerminal(t)
	path := filepath.Join(t.TempDir(), "first-boot.env")
	t.Setenv(CredentialFileEnv, path)

	if _, err := Deliver("VAULT_CLIENT_SECRET_web\nVAULT_ADMIN_TOKEN=forged", "real"); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(got), "\n") != 1 {
		t.Errorf("a label forged an extra credential line: %q", got)
	}
	if strings.Contains(string(got), "\nVAULT_ADMIN_TOKEN=forged") {
		t.Errorf("forged line survived: %q", got)
	}
	if !strings.Contains(string(got), "VAULT_CLIENT_SECRET_web_VAULT_ADMIN_TOKEN_forged=real") {
		t.Errorf("unexpected sanitized label: %q", got)
	}
}

// With no file configured and a human at the keyboard, showing the credential
// once is the right answer — it is what a TTY is for, and no aggregator is
// reading it.
func TestDeliver_FallsBackToTheTerminal(t *testing.T) {
	t.Setenv(CredentialFileEnv, "")

	oldCheck := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = oldCheck })

	var sb strings.Builder
	oldOut := terminalOut
	terminalOut = func() io.Writer { return &sb }
	t.Cleanup(func() { terminalOut = oldOut })

	dest, err := Deliver("VAULT_ADMIN_TOKEN", "s3cret")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if dest != "this terminal" {
		t.Errorf("dest = %q", dest)
	}
	if sb.String() != "VAULT_ADMIN_TOKEN=s3cret\n" {
		t.Errorf("terminal got %q", sb.String())
	}
}

func TestDeliver_ReportsAFailedTerminalWrite(t *testing.T) {
	t.Setenv(CredentialFileEnv, "")

	oldCheck := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = oldCheck })

	oldOut := terminalOut
	terminalOut = func() io.Writer { return failingWriter{} }
	t.Cleanup(func() { terminalOut = oldOut })

	if _, err := Deliver("VAULT_ADMIN_TOKEN", "s3cret"); err == nil {
		t.Fatal("Deliver reported success though the terminal write failed")
	}
}

// The case the whole package exists for: an unattended process with no sink
// configured must refuse rather than fall back to the log.
func TestDeliver_RefusesWhenThereIsNoSink(t *testing.T) {
	nonTerminal(t)
	t.Setenv(CredentialFileEnv, "")

	_, err := Deliver("VAULT_ADMIN_TOKEN", "s3cret")
	if !errors.Is(err, ErrNoSink) {
		t.Fatalf("err = %v, want ErrNoSink", err)
	}
	if !strings.Contains(err.Error(), CredentialFileEnv) {
		t.Errorf("ErrNoSink does not name the remedy: %v", err)
	}
}

// The default terminal check has to answer for the real os.Stdout, which under
// `go test` is a pipe or a file and never a character device.
func TestStdoutIsTerminal_IsFalseUnderTest(t *testing.T) {
	if stdoutIsTerminal() {
		t.Error("stdout reported as a terminal under go test")
	}
	if terminalOut() != os.Stdout {
		t.Error("terminalOut does not resolve os.Stdout")
	}
}

// A stdout that cannot even be stat'ed is not a terminal. Answering "yes" on an
// unreadable descriptor would send the credential to whatever stdout had become.
func TestStdoutIsTerminal_IsFalseWhenStdoutCannotBeStatted(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	os.Stdout = f
	t.Cleanup(func() { os.Stdout = old })

	if stdoutIsTerminal() {
		t.Error("a closed stdout was reported as a terminal")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no") }

// A boot path that gets its credential to the operator is a boot path that
// carries on, so MustDeliver must not exit on the way through.
func TestMustDeliver_ReturnsTheSinkAndDoesNotExit(t *testing.T) {
	nonTerminal(t)
	path := filepath.Join(t.TempDir(), "first-boot.env")
	t.Setenv(CredentialFileEnv, path)

	var exits []int
	defer SetExitForTest(func(code int) { exits = append(exits, code) })()

	dest, err := MustDeliver("VAULT_ADMIN_TOKEN", "s3cr3t")
	if err != nil {
		t.Fatalf("MustDeliver: %v", err)
	}
	if dest != path {
		t.Errorf("dest = %q, want %q", dest, path)
	}
	if len(exits) != 0 {
		t.Errorf("MustDeliver exited %v on a delivery that succeeded", exits)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}
	if !strings.Contains(string(body), "s3cr3t") {
		t.Errorf("the credential is not in the sink: %q", body)
	}
}

// The refusal itself. Without it the boot path logs the error and serves, which
// on the admin-token path meant a pod that reported Ready with no admin token in
// force, and no trace of it but one line.
func TestMustDeliver_ExitsWhenThereIsNowhereToPutTheCredential(t *testing.T) {
	nonTerminal(t)
	t.Setenv(CredentialFileEnv, "")

	var exits []int
	defer SetExitForTest(func(code int) { exits = append(exits, code) })()

	dest, err := MustDeliver("VAULT_ADMIN_TOKEN", "s3cr3t")
	if !errors.Is(err, ErrNoSink) {
		t.Fatalf("err = %v, want ErrNoSink", err)
	}
	if dest != "" {
		t.Errorf("dest = %q, want empty: nothing was delivered", dest)
	}
	if len(exits) != 1 || exits[0] != 1 {
		t.Errorf("exits = %v, want exactly one exit(1)", exits)
	}
}

// The seam has to go back, or the first test to use it disarms the refusal for
// every test that runs after it in the same binary.
func TestSetExitForTest_RestoresThePreviousExit(t *testing.T) {
	sentinel := func(int) {}
	restoreOuter := SetExitForTest(sentinel)
	defer restoreOuter()

	restoreInner := SetExitForTest(func(int) {})
	restoreInner()

	if reflect.ValueOf(exitProcess).Pointer() != reflect.ValueOf(sentinel).Pointer() {
		t.Error("the inner restore did not put the outer exit back, so a later test would run " +
			"against whichever exit an earlier one happened to leave behind")
	}
}
