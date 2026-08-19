// The only instructions an operator has for a credential shown once.
//
// NOTES.txt published this:
//
//	kubectl debug -n <ns> -it deploy/<fullname> --image=busybox --target=vault-auth \
//	  -- cat /proc/1/root/run/first-boot/credentials
//
// Two defects in one command, both reproduced on a live cluster against a
// shell-less pod shaped like this chart's.
//
// It does not work. `kubectl debug --target` attaches an ephemeral container,
// which only a Pod can hold, so the Deployment form answers
// `error: "apps/v1, Kind=Deployment" not supported by debug`.
//
// And the form that does work leaks. An ephemeral container's command writes to
// that container's stdout, and that stdout is a container log: after the
// corrected `-- cat ...` ran, `kubectl logs credpod -c logs-it` returned
// `VAULT_ADMIN_TOKEN=s3cr3t-first-boot`. internal/firstboot exists precisely
// because that log is scraped into an aggregator with a wider readership than
// the database the credential protects, so the documented retrieval put the
// credential back exactly where the feature had just taken it out of.
//
// What works and does not leak, also verified live: an ephemeral container whose
// command is `sleep`, read with `kubectl exec`. Its stdout stays empty and the
// value goes to the operator's terminal over the exec stream.
//
// This gate holds both properties. It reads the commands NOTES.txt actually
// publishes rather than checking for prose about them.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNotesDebugCommandsTargetAPod fails on the shape that cannot run.
func TestNotesDebugCommandsTargetAPod(t *testing.T) {
	for _, cmd := range notesCommands(t, "kubectl debug") {
		if regexp.MustCompile(`\b(deploy|deployment|deployments)/`).MatchString(cmd) {
			t.Errorf("NOTES.txt tells the operator to run:\n  %s\n"+
				"kubectl debug attaches an ephemeral container and only a Pod can hold one, so "+
				"this answers `error: \"apps/v1, Kind=Deployment\" not supported by debug`. It is "+
				"the only instruction there is for a credential that is shown once.", cmd)
		}
	}
}

// TestNotesDebugCommandsDoNotPrintTheCredential fails on the shape that works
// and leaks.
func TestNotesDebugCommandsDoNotPrintTheCredential(t *testing.T) {
	notes := readNotes(t)
	path := credentialPathToken(t, notes)

	debugCommands := notesCommands(t, "kubectl debug")
	if len(debugCommands) == 0 {
		t.Fatal("NOTES.txt publishes no kubectl debug command at all, so this gate has nothing " +
			"to check and the operator has nothing to run")
	}

	for _, cmd := range debugCommands {
		if strings.Contains(cmd, path) {
			t.Errorf("NOTES.txt tells the operator to run:\n  %s\n"+
				"An ephemeral container's command writes to that container's stdout, which is a "+
				"container log, so this puts the credential into `kubectl logs` and from there "+
				"into whatever scrapes the cluster. Start the container idle and read the file "+
				"with kubectl exec, whose stream is not logged.", cmd)
		}
		if strings.Contains(cmd, " -it") || strings.Contains(cmd, " -i ") || strings.Contains(cmd, " -t ") {
			t.Errorf("NOTES.txt tells the operator to run:\n  %s\n"+
				"kubectl debug warns about this itself: everything in an interactive session is "+
				"recorded in the container's log, credentials included.", cmd)
		}
	}

	var readCommands int
	for _, cmd := range notesCommands(t, "kubectl exec") {
		if strings.Contains(cmd, path) {
			readCommands++
		}
	}
	if readCommands == 0 {
		t.Errorf("no `kubectl exec` in NOTES.txt reads %s. The debug container is then either "+
			"printing the credential into its own log or the operator has no way to read the "+
			"file at all.", path)
	}
}

// TestNotesSaysWhatToDoAfterALeakingRetrieval keeps the recovery instruction
// present. An operator who already ran the old command needs to be told that the
// credential is in the log store and what to do about it, because deleting the
// pod does not take the log record with it.
func TestNotesSaysWhatToDoAfterALeakingRetrieval(t *testing.T) {
	notes := readNotes(t)
	if !strings.Contains(notes, "rotate-admin-token") {
		t.Error("NOTES.txt does not name the rotation command for a credential that has already " +
			"been printed into a container log. The disclosure is durable; the instructions have " +
			"to be too.")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func readNotes(t *testing.T) string {
	t.Helper()
	return readFileString(t, filepath.Join(repoRoot(t), chartDir, "templates", "NOTES.txt"))
}

// credentialPathToken is the template expression NOTES.txt renders the
// credential path from. Taken out of the file rather than written here, so
// renaming the value moves this gate with it instead of past it.
func credentialPathToken(t *testing.T, notes string) string {
	t.Helper()
	const token = "{{ .Values.firstBootCredential.path }}" // #nosec G101 -- a Helm template expression, not a credential
	if !strings.Contains(notes, token) {
		t.Fatalf("NOTES.txt no longer renders the credential path from %s, so this gate cannot "+
			"tell which commands touch the credential", token)
	}
	return token
}

// notesCommands returns every shell command in NOTES.txt that starts with the
// given prefix, with backslash continuations folded into one line so a command
// split across three lines is still read as one.
func notesCommands(t *testing.T, prefix string) []string {
	t.Helper()

	folded := regexp.MustCompile(`\\\s*\n\s*`).ReplaceAllString(readNotes(t), " ")
	var out []string
	for _, line := range strings.Split(folded, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) || strings.Contains(line, "$("+prefix) {
			out = append(out, strings.Join(strings.Fields(line), " "))
		}
	}
	return out
}
