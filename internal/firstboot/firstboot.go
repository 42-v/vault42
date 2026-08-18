// Package firstboot hands a freshly generated credential to the operator
// without putting it in the process log.
//
// Three code paths mint a credential exactly once and have no second chance to
// show it: the first-boot super_admin password, the admin CLI token, and each
// seeded client secret. All three ran through log.Printf or fmt.Printf, and all
// three are reached from a server boot path rather than only from an
// interactive command. That stream is stderr/stdout on a long-running process,
// and in every deployment this repo targets it is scraped into a durable
// aggregator whose readers are a far wider set than the database the credential
// protects — so the credential ends up permanently at rest there, and it
// outlives its own rotation.
//
// The rule this package enforces is that the log records that a credential was
// minted and where it went, never what it was. The value itself goes to one of
// two places:
//
//   - the file named by VAULT_FIRST_BOOT_CREDENTIAL_FILE, created 0600, refusing
//     a path that is not already a regular file no wider than 0600 (which is
//     what rejects a symlink planted at the path); or
//   - stdout, but only when stdout is a terminal, which is the one case where
//     the reader is a human at a keyboard and not a log shipper.
//
// With neither available, Deliver refuses. Refusing is the point: the caller is
// then obliged to abandon whatever it was creating rather than store the hash of
// a credential nobody holds, which is the failure that cannot be recovered from.
//
// The env var is read here rather than carried on config.Config, following the
// same reasoning as cli.loadProvisionedAdminToken and cmd/vault's SIGNING_KEY
// read: this package is the setting's only consumer, and three binaries would
// otherwise each have to thread it through.
package firstboot

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// CredentialFileEnv names the env var holding the path first-boot credentials
// are written to.
const CredentialFileEnv = "VAULT_FIRST_BOOT_CREDENTIAL_FILE"

// ErrNoSink reports that there is nowhere to put a credential that is not the
// log. It names the remedy because the caller that surfaces it is usually a pod
// that has just refused to finish booting.
var ErrNoSink = errors.New("no first-boot credential sink: set " + CredentialFileEnv +
	" to a path the process can create, or run this command on a terminal; a first-boot credential is never written to the log")

// terminalOut and stdoutIsTerminal are the seams the tests use, on the model of
// cli.exitProcess: the terminal branch cannot otherwise be exercised, and a
// failed write on the way to the operator has to be provable rather than
// assumed. terminalOut resolves os.Stdout at call time so a test that swaps it
// for a pipe is observed.
var (
	terminalOut = func() io.Writer { return os.Stdout }

	stdoutIsTerminal = func() bool {
		fi, err := os.Stdout.Stat()
		if err != nil {
			return false
		}
		return fi.Mode()&os.ModeCharDevice != 0
	}
)

// Deliver hands one credential to the operator and reports where it went, in a
// form suitable for logging. The value is never part of that description.
//
// label identifies the credential in the file (KEY=VALUE, one per line, so the
// file can be sourced or read by a secret loader). It is sanitized, because a
// client name comes out of an operator-supplied seed file and a newline in it
// would forge an extra credential line in exactly the way CWE-117 forges a log
// record.
func Deliver(label, value string) (string, error) {
	w, dest, err := openSink()
	if err != nil {
		return "", err
	}
	_, werr := io.WriteString(w, sanitizeLabel(label)+"="+value+"\n")
	if c, ok := w.(io.Closer); ok {
		werr = errors.Join(werr, c.Close())
	}
	if werr != nil {
		return "", fmt.Errorf("deliver a first-boot credential to %s: %w", dest, werr)
	}
	return dest, nil
}

// exitProcess ends the process when a boot path has minted a credential it
// cannot hand over. It is a variable so a test can observe the refusal without
// killing the test binary; production never reassigns it, and a replacement must
// not return.
var exitProcess = os.Exit

// SetExitForTest replaces the exit MustDeliver uses and returns a function that
// puts the previous one back.
//
// Exported deliberately, and only for that. The boot paths that call MustDeliver
// live in internal/cli and internal/adminapi, so the tests that have to prove
// the refusal cannot reach an unexported seam in this package, and a test that
// left the real os.Exit in place would take the whole test binary with it.
// Nothing in cmd/ calls this.
func SetExitForTest(fn func(int)) func() {
	previous := exitProcess
	exitProcess = fn
	return func() { exitProcess = previous }
}

// MustDeliver is Deliver for the paths that mint a credential while a server is
// starting up. In production it either returns where the credential went, or it
// does not return: there is no third outcome in which the process carries on
// having minted a credential nobody received.
//
// The distinction from Deliver is not stylistic. An error is the right shape for
// an interactive command, whose operator reads it on the terminal and runs the
// command again. A boot path has no such reader, and the error was handled the
// way an error with no reader always is:
//
//	Admin token init error: deliver admin token: VAULT_FIRST_BOOT_CREDENTIAL_FILE:
//	  open /nonexistent-dir/credentials: no such file or directory
//	metrics listening on 127.0.0.1:19091
//	The Vault listening on :18081 (profile=production)
//
// One log line, and then a pod that passes /healthz, reports Ready and has no
// admin token in force. A broken install is indistinguishable from a healthy one
// unless somebody reads that line, and NOTES.txt sends the operator to read a
// file that was never written. That is why the refusal lives here and not at the
// call site: a caller can log an error and carry on, and this one did.
//
// Refusing is safe because delivery precedes persistence everywhere this is
// used. The admin token's hash, the first admin's row and a seeded client's row
// are all written after the credential is in the operator's hands, so nothing is
// stored and the next boot with a working sink mints again. The state with no
// way back is the other one: an Argon2id hash of a credential nobody holds, in a
// table whose presence makes the mint path skip itself forever.
//
// The error return is reached only when a test has replaced the exit. Callers
// keep handling it as they did, so the shape a test observes is the shape the
// process would have had at that point.
func MustDeliver(label, value string) (string, error) {
	dest, err := Deliver(label, value)
	if err == nil {
		return dest, nil
	}
	return "", Refuse(err)
}

// Refuse is MustDeliver's second half on its own, for a caller that has
// something to undo first.
//
// InitAdminToken is the one: it has to claim admin_token_hash before it knows
// whether it is the replica that mints, so by the time delivery can fail the
// hash is already in the database. Exiting from inside MustDeliver would skip
// every deferred cleanup -- os.Exit does not run them -- and leave exactly the
// state that has no way back: a stored hash of a token nobody holds, in a row
// whose presence makes the next boot skip minting forever.
//
// So the caller releases the claim, then calls this. Like MustDeliver, it does
// not return in production; the error it returns is for a test that has replaced
// the exit, and returning it keeps the caller's own error shape intact.
func Refuse(err error) error {
	log.Printf("REFUSING TO START: a first-boot credential was generated and could not be "+
		"delivered: %v. Nothing was stored, so fixing the sink and starting again mints a "+
		"fresh one; starting anyway would serve with no credential in force.", err)
	exitProcess(1)
	return err
}

// openSink resolves where this process is allowed to put a credential. The
// returned writer is closed by Deliver when it owns one.
func openSink() (io.Writer, string, error) {
	if path := os.Getenv(CredentialFileEnv); path != "" {
		clean := filepath.Clean(path)
		f, err := openCredentialFile(clean)
		if err != nil {
			return nil, "", err
		}
		return f, clean, nil
	}
	if stdoutIsTerminal() {
		return terminalOut(), "this terminal", nil
	}
	return nil, "", ErrNoSink
}

// openCredentialFile opens the sink file for appending.
//
// It is O_APPEND rather than O_EXCL because one boot can mint several
// credentials (a seed file with three clients delivers three secrets), so the
// symlink and permission protections O_EXCL would have given for free are made
// explicit instead: an existing path must be a regular file whose mode grants
// nothing to group or other, and a symlink fails that test because Lstat reports
// the link rather than its target.
func openCredentialFile(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: %s is not a regular file", CredentialFileEnv, path)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s: %s is mode %#o, so the credential would be readable by others; chmod 600 it",
				CredentialFileEnv, path, fi.Mode().Perm())
		}
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- the operator names their own credential file
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CredentialFileEnv, err)
	}
	return f, nil
}

// sanitizeLabel reduces a label to characters that cannot end a line or open a
// terminal control sequence. Anything outside the set becomes '_'.
func sanitizeLabel(label string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '_', r == '-', r == '.':
			return r
		}
		return '_'
	}, label)
}
