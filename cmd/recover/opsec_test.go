// What the tool exposes to the machine it runs on.
//
// The other files in this package treat the escrow log as the hostile input. This
// one treats the workstation as the hazard: the operator runs this during an
// incident, on a host that is not necessarily theirs alone, holding the one
// private key the product keeps out of production and a DSN that opens the
// production database.
//
// Three channels leak without anyone doing anything wrong. /proc/<pid>/cmdline is
// world-readable on a default Linux, so every argument is visible to every local
// process for the life of the run. Terminal scrollback and shell history outlive
// the run entirely. And a diagnostic an operator pastes into a ticket takes
// whatever it carried with it.
package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// prodDSN is a DSN shaped like the one an operator would really use, with a
// password distinctive enough that a leak test can search for it.
const (
	prodDSN      = "postgres://vault_app:Tr0ub4dor-prod@db.internal:5432/vault?sslmode=require"
	prodPassword = "Tr0ub4dor-prod"
)

// `recover -h` is the first thing an operator runs, and DATABASE_URL is the way
// docs/config.md tells them to pass the DSN so its password stays out of argv.
// Wiring the environment variable in as the flag's DEFAULT value made the usage
// text print it: flag.PrintDefaults appends `(default "<value>")` for any
// non-empty string default, so -h dumped the production database password into
// the terminal, into scrollback, and into every session transcript.
func TestRun_UsageDoesNotPrintTheDSNFromTheEnvironment(t *testing.T) {
	t.Setenv("DATABASE_URL", prodDSN)

	o := &opened{rows: &fakeRows{}}
	var stdout, stderr strings.Builder
	if code := run([]string{"-h"}, &stdout, &stderr, o.open); code != 0 {
		t.Fatalf("exit code = %d, want 0 for -h\n%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-dsn string") {
		t.Fatalf("usage does not document -dsn, so this test would pass vacuously:\n%s", stderr.String())
	}
	mustNotLeak(t, "usage text", stderr.String(), prodPassword, prodDSN)
}

// The environment variable has to keep working after the default is emptied,
// because it is the only way to supply the DSN without putting it in argv.
func TestRun_DSNFromTheEnvironmentIsStillUsedWhenTheFlagIsAbsent(t *testing.T) {
	t.Setenv("DATABASE_URL", prodDSN)

	o := &opened{rows: &fakeRows{}}
	var stdout, stderr strings.Builder
	if code := run([]string{"--key", writeKey(t, escrowKey)}, &stdout, &stderr, o.open); code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", code, stderr.String())
	}
	if o.dsn != prodDSN {
		t.Errorf("opener got DSN %q, want the DATABASE_URL value", o.dsn)
	}
}

// A password in --dsn is readable by every process on the box for as long as the
// run lasts, and stays in shell history afterwards. The tool cannot rewrite its
// own argv, so the only thing it can do is tell the operator that the credential
// they just used is now exposed and needs rotating. Saying nothing leaves them
// believing an offline recovery run was contained.
func TestRun_SaysSoWhenTheDSNPasswordWasPassedInArgv(t *testing.T) {
	o := &opened{rows: &fakeRows{}}
	got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", prodDSN}, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0: the warning must not fail the run\n%s", got.code, got.stderr)
	}
	if !strings.Contains(got.stderr, "DATABASE_URL") {
		t.Errorf("stderr does not point at the safer channel:\n%s", got.stderr)
	}
	if !strings.Contains(got.stderr, "/proc") {
		t.Errorf("stderr does not say where the password is now readable:\n%s", got.stderr)
	}
	// The warning itself must not repeat the credential it is warning about, or
	// it moves the password from argv into the scrollback as well.
	mustNotLeak(t, "argv warning", got.stderr, prodPassword)
}

// pgx reads a keyword/value DSN as readily as a URL, and both spellings land the
// password in argv. A warning that fires only on the form net/url understands
// leaves the other one silently exposed on /proc and in shell history, which is
// the case an operator is least likely to notice on their own.
func TestRun_SaysSoWhenAKeywordValueDSNCarriesAPassword(t *testing.T) {
	dsns := map[string]string{
		"keyword/value pairs":       "host=db.internal port=5432 user=vault_app password=" + prodPassword + " dbname=vault sslmode=require",
		"password in the URL query": "postgres://vault_app@db.internal:5432/vault?sslmode=require&password=" + prodPassword,
	}

	for name, dsn := range dsns {
		t.Run(name, func(t *testing.T) {
			o := &opened{rows: &fakeRows{}}
			got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", dsn}, o)

			if got.code != 0 {
				t.Fatalf("exit code = %d, want 0: the warning must not fail the run\n%s", got.code, got.stderr)
			}
			if !strings.Contains(got.stderr, "readable to every process") {
				t.Errorf("a password in argv produced no warning:\n%s", got.stderr)
			}
			if !strings.Contains(got.stderr, "DATABASE_URL") {
				t.Errorf("stderr does not point at the safer channel:\n%s", got.stderr)
			}
			mustNotLeak(t, "argv warning", got.stderr, prodPassword)
		})
	}
}

// The keyword/value form has spellings that name the key without carrying a
// value: a template whose password variable was unset, or the key at the end of
// the string. Warning about those is the same failure as warning about a DSN
// with no password at all, and one false warning is enough to teach an operator
// that the line is noise.
func TestRun_NoArgvWarningWhenAKeywordValueDSNHasNoPassword(t *testing.T) {
	dsns := map[string]string{
		"empty value, more pairs follow":          "host=db.internal password= dbname=vault",
		"empty value at the end of the DSN":       "host=db.internal dbname=vault password=",
		"empty value, more URL parameters follow": "postgres://vault_app@db.internal:5432/vault?password=&sslmode=require",
	}

	for name, dsn := range dsns {
		t.Run(name, func(t *testing.T) {
			o := &opened{rows: &fakeRows{}}
			got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", dsn}, o)

			if got.code != 0 {
				t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
			}
			if strings.Contains(got.stderr, "readable to every process") {
				t.Errorf("the argv warning fired for a DSN that carries no password:\n%s", got.stderr)
			}
		})
	}
}

// Clearing the dumpable flag is defense in depth and the run continues without
// it, which makes this line the only thing standing between the operator and a
// false sense of containment: a recovery they believe was sealed would have held
// the private key in a process any program running as them could ptrace, and any
// crash could have written that key to the disk in a core file.
func TestWarnIfUnhardened_SaysWhatTheFailedStepWouldHavePrevented(t *testing.T) {
	var stderr strings.Builder
	warnIfUnhardened(&stderr, errors.New("operation not permitted"))

	for _, want := range []string{"core dumps", "debugger attach", "operation not permitted"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the hardening warning does not mention %q:\n%s", want, stderr.String())
		}
	}

	// The quiet case matters as much: every other test in this package drives
	// run(), which hardens for real, and a line printed on a hardened process
	// would be a permanent false alarm in every operator's scrollback.
	stderr.Reset()
	warnIfUnhardened(&stderr, nil)
	if stderr.String() != "" {
		t.Errorf("a hardening step that succeeded still wrote to stderr: %q", stderr.String())
	}
}

// The warning has to be specific to the case it describes. A DSN with no
// password in it, and a DSN that arrived through the environment rather than
// through argv, are both the recommended usage: warning about either would train
// an operator to ignore the line that matters.
func TestRun_NoArgvWarningWhenThereIsNoPasswordInArgv(t *testing.T) {
	tests := []struct {
		name string
		args func(t *testing.T) []string
		env  string
	}{
		{
			name: "no password in the flag",
			args: func(t *testing.T) []string {
				return []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://db.internal:5432/vault?sslmode=require"}
			},
		},
		{
			name: "password came from the environment",
			args: func(t *testing.T) []string { return []string{"--key", writeKey(t, escrowKey)} },
			env:  prodDSN,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := &opened{rows: &fakeRows{}}
			t.Setenv("DATABASE_URL", tc.env)
			var stdout, stderr strings.Builder
			if code := run(tc.args(t), &stdout, &stderr, o.open); code != 0 {
				t.Fatalf("exit code = %d, want 0\n%s", code, stderr.String())
			}
			if strings.Contains(stderr.String(), "readable to every process") {
				t.Errorf("the argv warning fired for a run that did not put a password in argv:\n%s", stderr.String())
			}
		})
	}
}

// The recovery private key is the one secret whose exposure cannot be undone: it
// opens every escrow record ever written, including the ones already swept out of
// the database but still sitting in a backup. A key file that any local account
// can read has already lost that property, and this run is the moment an operator
// can be told.
//
// It is a warning rather than a refusal on purpose. The tool is run mid-incident,
// sometimes from a read-only mount where chmod is not available, and refusing to
// answer a legal request because of a permission bit is the worse failure.
func TestRun_SaysSoWhenTheRecoveryKeyFileIsReadableByOtherAccounts(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666} {
		t.Run(mode.String(), func(t *testing.T) {
			keyPath := writeKey(t, escrowKey)
			if err := os.Chmod(keyPath, mode); err != nil {
				t.Fatalf("chmod key: %v", err)
			}

			o := &opened{rows: &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail)}}}
			got := exercise(t, []string{"--key", keyPath, "--dsn", "postgres://offline/vault"}, o)

			if got.code != 0 {
				t.Fatalf("exit code = %d, want 0: a permission warning must not abandon the recovery\n%s", got.code, got.stderr)
			}
			if !strings.Contains(got.stderr, "readable by accounts other than yours") {
				t.Errorf("a key file at mode %v produced no warning:\n%s", mode, got.stderr)
			}
			if !strings.Contains(got.stderr, keyPath) {
				t.Errorf("the warning does not name the file the operator has to fix:\n%s", got.stderr)
			}
			mustNotLeak(t, "permission warning", got.stderr, keyMaterial(t, escrowKey)...)
		})
	}
}

// A correctly held key must produce no warning at all, or the warning stops
// meaning anything.
func TestRun_NoPermissionWarningForAKeyOnlyItsOwnerCanRead(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		t.Run(mode.String(), func(t *testing.T) {
			keyPath := writeKey(t, escrowKey)
			if err := os.Chmod(keyPath, mode); err != nil {
				t.Fatalf("chmod key: %v", err)
			}

			o := &opened{rows: &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail)}}}
			got := exercise(t, []string{"--key", keyPath, "--dsn", "postgres://offline/vault"}, o)

			if got.code != 0 {
				t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
			}
			if strings.Contains(got.stderr, "readable by accounts other than yours") {
				t.Errorf("mode %v warned anyway, which trains an operator to ignore the warning:\n%s", mode, got.stderr)
			}
		})
	}
}
