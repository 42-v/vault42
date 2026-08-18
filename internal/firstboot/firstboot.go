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
//   - the file named by VAULT_FIRST_BOOT_CREDENTIAL_FILE, created 0600 and
//     opened O_NOFOLLOW, refusing anything the open descriptor does not report
//     as a private regular file this process owns outright; or
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
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
// explicit instead.
//
// Every check runs against the open descriptor rather than against the path.
// Checking the path first and opening it second is two lookups of a name that
// anyone with write access to the containing directory controls, and the sink's
// directory is exactly that kind of place: a memory-backed emptyDir, or /tmp
// when an operator points the variable there. Be a regular 0600 file for the
// first lookup, be a symlink by the second, and the credential lands wherever
// the link's author chose. O_NOFOLLOW settles that in the kernel — the open
// itself fails on a symlink, with no window between the decision and the write —
// and Fstat then describes the one inode this descriptor is pinned to, which no
// later rename can swap.
//
// Ownership and link count are checked for the same reason the mode is. A
// hardlink to an inode the attacker already holds is a regular file at 0600 and
// passes every mode test, while the credential is still readable through their
// name for it.
func openCredentialFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- the operator names their own credential file
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s: %s is a symlink, so the credential would be written to a path its author chose rather than the one configured",
				CredentialFileEnv, path)
		}
		return nil, fmt.Errorf("%s: %w", CredentialFileEnv, err)
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w", CredentialFileEnv, err)
	}
	if err := checkCredentialSink(path, fi); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// checkCredentialSink refuses a descriptor that is anything other than a private
// regular file belonging to this process.
func checkCredentialSink(path string, fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: %s is not a regular file", CredentialFileEnv, path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: %s is mode %#o, so the credential would be readable by others; chmod 600 it",
			CredentialFileEnv, path, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := os.Getuid(); uid >= 0 && uint64(st.Uid) != uint64(uid) {
		return fmt.Errorf("%s: %s is owned by uid %d and this process runs as %d, so the credential would be readable by another account; chown it",
			CredentialFileEnv, path, st.Uid, uid)
	}
	if st.Nlink > 1 {
		return fmt.Errorf("%s: %s has %d hard links, so the credential would be readable through a name that is not the configured one; rm it and let the boot recreate it",
			CredentialFileEnv, path, st.Nlink)
	}
	return nil
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
