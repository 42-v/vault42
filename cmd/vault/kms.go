package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	kid := fs.String("kid", "", "KEK key id the envelope is bound to as AAD (required)")
	in := fs.String("in", "-", "plaintext input file, or - for stdin")
	out := fs.String("out", "-", "base64 envelope output file, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kid == "" {
		return errors.New("--kid is required")
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
