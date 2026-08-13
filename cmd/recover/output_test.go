// Where the recovered data lands.
//
// The output of this tool is the single most sensitive artifact the product
// produces: it is exactly the personal data an erasure removed, reassembled for
// an operator who has a legal reason to see it. Before --out existed the only way
// to keep it was a shell redirect, which creates the file with the operator's
// umask - 0644 on a stock Fedora or Debian login - so answering a subject-access
// request left every erased user's address world-readable on the workstation, and
// nothing in the run said so.
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The file the tool creates itself is created private, and the recovered records
// go there instead of to stdout. An operator who redirects stdout gets whatever
// their umask gives them; the file this flag opens is not subject to that.
func TestRun_OutFileIsCreatedPrivateAndKeepsTheRecordsOffStdout(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "recovered.jsonl")

	o := &opened{rows: &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail), goodRow(t, "second@example.invalid")}}}
	got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault", "--out", outPath}, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty: --out means the records went to the file", got.stdout)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("output file is mode %#o, want 0600: an erasure record must not be readable by other accounts", perm)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	recs := records(t, string(data))
	if len(recs) != 2 {
		t.Fatalf("file holds %d records, want 2: %q", len(recs), data)
	}
	if recs[0].Email != sampleEmail || recs[1].Email != "second@example.invalid" {
		t.Errorf("file holds %+v, want both recovered accounts", recs)
	}
	// stderr keeps its job: diagnostics only, never the recovered identities.
	mustNotLeak(t, "stderr", got.stderr, sampleEmail, "second@example.invalid", sampleDisplayName)
}

// An existing file must stop the run, not be overwritten. Two recovery runs an
// hour apart into the same filename is an ordinary mistake, and silently
// truncating the first result destroys an artifact that may already have been
// referenced in a legal response.
func TestRun_OutRefusesToOverwriteAnExistingFile(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "recovered.jsonl")
	const existing = "the first run's output, already handed to legal\n"
	if err := os.WriteFile(outPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("seed output: %v", err)
	}

	o := &opened{rows: &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail)}}}
	got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault", "--out", outPath}, o)

	if got.code != 1 {
		t.Errorf("exit code = %d, want 1: an occupied output path is a fatal error", got.code)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(data) != existing {
		t.Errorf("the existing file was rewritten: %q", data)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty: a refused output path must not fall back to stdout", got.stdout)
	}
}

// A symlink at the output path must not be followed. Anyone who can create a file
// in the directory the operator runs from can plant one, and following it would
// write every recovered identity wherever it points, under the operator's
// privileges and with no sign in the run that anything unusual happened.
func TestRun_OutDoesNotFollowASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "attacker-readable.jsonl")
	outPath := filepath.Join(dir, "recovered.jsonl")

	tests := map[string]func(t *testing.T){
		"dangling symlink": func(t *testing.T) {},
		"symlink onto an existing file": func(t *testing.T) {
			if err := os.WriteFile(target, []byte("planted\n"), 0o666); err != nil {
				t.Fatalf("seed target: %v", err)
			}
		},
	}

	for name, seed := range tests {
		t.Run(name, func(t *testing.T) {
			_ = os.Remove(target)
			_ = os.Remove(outPath)
			seed(t)
			if err := os.Symlink(target, outPath); err != nil {
				t.Fatalf("symlink: %v", err)
			}

			o := &opened{rows: &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail)}}}
			got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault", "--out", outPath}, o)

			if got.code != 1 {
				t.Errorf("exit code = %d, want 1: a symlink at the output path is refused", got.code)
			}
			data, err := os.ReadFile(target)
			if err != nil && !os.IsNotExist(err) {
				t.Fatalf("read symlink target: %v", err)
			}
			if strings.Contains(string(data), sampleEmail) {
				t.Errorf("a recovered identity was written through a symlink to %s: %q", target, data)
			}
		})
	}
}

// A run that dies part way through must not leave a file that looks like a
// finished recovery. The failure modes that reach here are a dropped connection
// or a row the driver could not decode, both of which stop the read at an
// arbitrary point; a restore driven from the surviving prefix would silently
// recreate a subset of the accounts and report itself complete.
func TestRun_OutFileIsRemovedWhenTheRunDiesPartWayThrough(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "recovered.jsonl")

	o := &opened{rows: &fakeRows{
		rows:    []escrowRow{goodRow(t, sampleEmail), goodRow(t, "second@example.invalid")},
		iterErr: errors.New("unexpected EOF"),
	}}
	got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault", "--out", outPath}, o)

	if got.code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", got.code, got.stderr)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		data, _ := os.ReadFile(outPath)
		t.Errorf("a truncated recovery survived a fatal error: %q (stat err %v)", data, err)
	}
}

// A run that completes with unrecoverable records is not a fatal error: it came
// back short, which the exit status reports, but what it did recover is real and
// has to survive.
func TestRun_OutFileSurvivesAnIncompleteRun(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "recovered.jsonl")

	bad := goodRow(t, "corrupt@example.invalid")
	bad.payload = sealTo(t, &wrongKey.PublicKey,
		escrowJSON(t, "corrupt@example.invalid", "Wrong Key", nil), bindingFor("corrupt@example.invalid"))

	o := &opened{rows: &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail), bad}}}
	got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault", "--out", outPath}, o)

	if got.code != exitIncomplete {
		t.Fatalf("exit code = %d, want %d\n%s", got.code, exitIncomplete, got.stderr)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	recs := records(t, string(data))
	if len(recs) != 1 || recs[0].Email != sampleEmail {
		t.Errorf("file holds %+v, want the one recoverable account", recs)
	}
}

// An output path that cannot be opened at all stops the run before the escrow log
// is read. Discovering the problem after decrypting everything would mean holding
// the whole recovered set in a process with nowhere to put it.
func TestRun_UnusableOutPathIsFatalBeforeConnecting(t *testing.T) {
	o := &opened{rows: &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail)}}}
	outPath := filepath.Join(t.TempDir(), "no-such-directory", "recovered.jsonl")
	got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault", "--out", outPath}, o)

	if got.code != 1 {
		t.Errorf("exit code = %d, want 1", got.code)
	}
	if o.calls != 0 {
		t.Errorf("opener called %d times, want 0: an unusable output path must not open the escrow log", o.calls)
	}
	if !strings.Contains(got.stderr, "recover: open output:") {
		t.Errorf("stderr does not name the output file as the problem:\n%s", got.stderr)
	}
}
