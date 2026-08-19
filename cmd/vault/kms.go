package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/kms"
)

// runKMS dispatches the `vault kms <subcommand>` group. It is intercepted early
// in main() — before any database or server wiring — because wrapping only needs
// the KMS root keyfile, not a running vault. Returns an error for the caller to
// print and exit non-zero on.
func runKMS(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: vault kms wrap --kid <kid> [--in <file|->] [--out <file|->]")
	}
	switch args[0] {
	case "wrap":
		return runKMSWrap(args[1:], stdin, stdout)
	default:
		return fmt.Errorf("unknown kms subcommand %q (want: wrap)", args[0])
	}
}

// runKMSWrap implements `vault kms wrap`: it reads a plaintext key, loads the KMS
// root the SAME way the server does (config.LoadSecret → KMS_ROOT_KEY_FILE),
// seals it under the per-kid KEK via internal/kms Service.Wrap, and emits the
// base64 envelope in the exact wire form POST /kms/unwrap consumes
// (base64.StdEncoding of nonce || AES-256-GCM ciphertext, AAD = kid).
//
// This is what life42 deploy tooling calls to produce the wrapped-root artifact.
// All key material (root + plaintext, and the KEK inside Wrap) is zeroized before
// return.
func runKMSWrap(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("kms wrap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	kid := fs.String("kid", "", "KEK key id the envelope is bound to as AAD (required; letters, digits, dot, underscore, at-sign, dash)")
	in := fs.String("in", "-", "plaintext input file, or - for stdin")
	out := fs.String("out", "-", "base64 envelope output file, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kid == "" {
		return errors.New("--kid is required")
	}
	if err := validateKID(*kid); err != nil {
		return err
	}

	// Load the KMS root byte-for-byte as the server does so the derived KEK — and
	// therefore the envelope — matches what /kms/unwrap expects. The trailing
	// string copy returned by LoadSecret can't be zeroed (Go strings are
	// immutable), same accepted limitation as the server; the []byte copy is.
	rootStr, err := config.LoadSecret("KMS_ROOT_KEY")
	if err != nil {
		return fmt.Errorf("load KMS root: %w", err)
	}
	root := []byte(rootStr)
	defer config.ZeroBytes(root)

	plaintext, err := readInput(*in, stdin)
	if err != nil {
		return fmt.Errorf("read plaintext: %w", err)
	}
	defer config.ZeroBytes(plaintext)

	// Nothing is not a key. AES-GCM seals zero bytes into a well-formed envelope,
	// so without this the command exits zero having emitted an artifact that
	// unwraps to nothing; the deploy pipeline stores it and the mistake surfaces
	// much later as an empty secret in a running service, with nothing pointing
	// back at the wrap step. Whitespace-only is refused on the same grounds: a
	// lone newline is a truncated file or a here-doc that lost its body.
	//
	// The trim only judges the input. Wrap still receives the bytes that were
	// read, because a key legitimately carries its own trailing newline and
	// sealing it a byte short would hand the consumer material that no longer
	// matches what was provided.
	if len(bytes.TrimSpace(plaintext)) == 0 {
		source, check := plaintextSource(*in)
		if len(plaintext) == 0 {
			return fmt.Errorf("refusing to wrap an empty plaintext: %s produced zero bytes, which seal into a valid envelope that unwraps to nothing; %s", source, check)
		}
		unit := "bytes"
		if len(plaintext) == 1 {
			unit = "byte"
		}
		return fmt.Errorf("refusing to wrap a whitespace-only plaintext: %s holds %d %s of whitespace and no key material; %s", source, len(plaintext), unit, check)
	}

	svc, err := kms.New(root)
	if err != nil {
		return err
	}
	defer svc.Close()

	envelope, err := svc.Wrap(*kid, plaintext)
	if err != nil {
		return fmt.Errorf("wrap: %w", err)
	}

	// The envelope is ciphertext, not a secret; emit it exactly (no trailing
	// newline) so the artifact decodes cleanly with base64.StdEncoding.
	return writeOutput(*out, base64.StdEncoding.EncodeToString(envelope), stdout)
}

// kidRe and kidMaxLen are the identifier rule POST /mint applies to its
// caller-supplied subject (internal/service.mintSubjectRe, mintSubjectMaxLen),
// reused rather than reinvented so vault42 has one answer for what an operator
// may name a thing.
//
// Nothing dereferences a kid: it is HKDF info and GCM AAD, so an odd one is not
// a traversal or injection risk. It is an identity risk. The envelope opens only
// under the exact bytes it was sealed with, and a kid holding a space, a
// trailing newline from an unquoted shell variable, or a Cyrillic lookalike is
// invisible in the deploy log, in the audit row, and in the runbook where the
// operator writes it down. The artifact would be unopenable with no way to see
// why, so the wrap is refused at the one point a human is still watching.
var kidRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)

const kidMaxLen = 128

// validateKID rejects a kid that is not a plain identifier. The kid is quoted in
// the message so whitespace and control bytes are visible in a terminal.
func validateKID(kid string) error {
	if len(kid) > kidMaxLen || !kidRe.MatchString(kid) {
		return fmt.Errorf("--kid %q is not a valid key id: 1-%d characters of letters, digits, dot, underscore, at-sign or dash, starting with a letter or digit", kid, kidMaxLen)
	}
	return nil
}

// plaintextSource names where the plaintext came from and what the operator
// should go and look at. A refusal that says only "empty" leaves the owner of an
// unattended pipeline guessing which file or which pipe came up short, which is
// the part that costs time at 3am.
func plaintextSource(path string) (source, check string) {
	if path == "" || path == "-" {
		return "stdin", "check that the step piping into `vault kms wrap` produced the key and exited zero"
	}
	return path, "check that this is the path the generating step wrote to, and that the step succeeded"
}

// readInput returns the plaintext from path, or from stdin when path is "" or "-".
func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(filepath.Clean(path)) // #nosec G304 -- path is an operator-supplied CLI flag
}

// writeOutput writes data to path, or to stdout when path is "" or "-".
func writeOutput(path, data string, stdout io.Writer) error {
	if path == "" || path == "-" {
		_, err := io.WriteString(stdout, data)
		return err
	}
	return os.WriteFile(filepath.Clean(path), []byte(data), 0o600) // #nosec G306 -- envelope is ciphertext, not a secret
}
