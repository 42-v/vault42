package main

// `vault kms wrap`.
//
// This is the command life42 deploy tooling calls to produce the wrapped-root
// artifact that POST /kms/unwrap consumes, which makes its output a wire format
// with a consumer on the other side of a deployment boundary. The tests below
// therefore assert the artifact byte for byte (exact base64, no trailing
// newline, 0600 on disk) rather than only that a wrap "worked", and they assert
// the failure shapes an unattended pipeline branches on.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/kms"
)

// TestKMSWrap_RoundTripWithUnwrap drives the real `vault kms wrap` code path
// (flag parse → config.LoadSecret(KMS_ROOT_KEY_FILE) → Service.Wrap → base64) and
// asserts the emitted envelope round-trips through Service.Unwrap back to the
// byte-identical plaintext. Root and kid are ephemeral, never a real KMS root.
func TestKMSWrap_RoundTripWithUnwrap(t *testing.T) {
	root := ephemeralRoot(t)
	const kid = "life42-root-kek-test"
	plaintext := []byte("this-is-a-32-byte-life42-datroot") // exactly 32 bytes

	// Point the wrap command at the ephemeral root via the same _FILE convention
	// the server uses to load KMS_ROOT_KEY.
	rootFile := filepath.Join(t.TempDir(), "kms_root.key")
	if err := os.WriteFile(rootFile, root, 0o600); err != nil {
		t.Fatalf("write root: %v", err)
	}
	t.Setenv("KMS_ROOT_KEY_FILE", rootFile)

	var out bytes.Buffer
	if err := runKMSWrap([]string{"--kid", kid, "--in", "-", "--out", "-"}, bytes.NewReader(plaintext), &out); err != nil {
		t.Fatalf("runKMSWrap: %v", err)
	}

	envelope, err := base64.StdEncoding.DecodeString(out.String())
	if err != nil {
		t.Fatalf("emitted envelope is not valid base64: %v", err)
	}

	svc, err := kms.New(root)
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	defer svc.Close()

	got, err := svc.Unwrap(kid, envelope)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, plaintext)
	}
	if bytes.Contains(envelope, plaintext) {
		t.Fatal("envelope leaks plaintext")
	}
}

// TestKMSWrapEnvelopeIsBoundToItsKID is the property the whole envelope format
// exists for. The kid is the AAD, so an envelope produced for one kid must not
// open under another even though both KEKs come from the same root. Without this
// the per-kid separation would be decorative.
func TestKMSWrapEnvelopeIsBoundToItsKID(t *testing.T) {
	root := ephemeralRoot(t)
	t.Setenv("KMS_ROOT_KEY_FILE", writeBytes(t, "kms_root.key", root))

	var out bytes.Buffer
	if err := runKMSWrap([]string{"--kid", "kid-a"}, strings.NewReader("payload"), &out); err != nil {
		t.Fatalf("runKMSWrap: %v", err)
	}
	envelope, err := base64.StdEncoding.DecodeString(out.String())
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	svc, err := kms.New(root)
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	defer svc.Close()

	if _, err := svc.Unwrap("kid-b", envelope); err == nil {
		t.Fatal("an envelope wrapped for kid-a opened under kid-b")
	}
	if _, err := svc.Unwrap("kid-a", envelope); err != nil {
		t.Fatalf("the envelope does not open under its own kid: %v", err)
	}
}

// TestRunKMSDispatch covers the subcommand table. `vault kms` with nothing after
// it must answer with the usage line rather than defaulting to wrap, and an
// unknown subcommand must name what it did not understand: this group is driven
// by deploy scripts, and a silent default would wrap the wrong thing.
func TestRunKMSDispatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "no subcommand",
			args: nil,
			want: "usage: vault kms wrap --kid <kid> [--in <file|->] [--out <file|->]",
		},
		{
			name: "empty subcommand",
			args: []string{""},
			want: `unknown kms subcommand "" (want: wrap)`,
		},
		{
			name: "unknown subcommand",
			args: []string{"unwrap"},
			want: `unknown kms subcommand "unwrap" (want: wrap)`,
		},
		{
			name: "subcommand is matched exactly",
			args: []string{"Wrap"},
			want: `unknown kms subcommand "Wrap" (want: wrap)`,
		},
		{
			name: "wrap is delegated with its own arguments",
			args: []string{"wrap", "--in", "-"},
			want: "--kid is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runKMS(tc.args, strings.NewReader(""), &out)

			if err == nil {
				t.Fatalf("runKMS(%q) returned no error", tc.args)
			}
			if err.Error() != tc.want {
				t.Fatalf("runKMS(%q) = %q, want %q", tc.args, err, tc.want)
			}
			if out.Len() != 0 {
				t.Fatalf("a rejected invocation still wrote output: %q", out.String())
			}
		})
	}
}

// TestRunKMSWrapArgumentHandling covers the flag set. The rows that matter are
// the last two: flag.Parse stops at the first non-flag argument, so a trailing
// positional is not an error by itself, and the command must still refuse to run
// without a kid rather than wrap under an empty AAD.
func TestRunKMSWrapArgumentHandling(t *testing.T) {
	root := ephemeralRoot(t)

	for _, tc := range []struct {
		name    string
		args    []string
		wantErr string
		isHelp  bool
	}{
		{
			name:    "no arguments",
			args:    nil,
			wantErr: "--kid is required",
		},
		{
			name:    "empty kid",
			args:    []string{"--kid", ""},
			wantErr: "--kid is required",
		},
		{
			name:    "unknown flag",
			args:    []string{"--kid", "k", "--algorithm", "aes"},
			wantErr: "flag provided but not defined: -algorithm",
		},
		{
			name:    "kid flag with no value",
			args:    []string{"--kid"},
			wantErr: "flag needs an argument: -kid",
		},
		{
			// -h is reported as an error and main() turns it into exit 1. Pinned
			// because a pipeline that runs `vault kms wrap -h` to probe the
			// command reads that status.
			name:   "help",
			args:   []string{"-h"},
			isHelp: true,
		},
		{
			name:    "flags after a positional argument are not parsed",
			args:    []string{"extra", "--kid", "k"},
			wantErr: "--kid is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KMS_ROOT_KEY_FILE", writeBytes(t, "kms_root.key", root))

			var out bytes.Buffer
			err := runKMSWrap(tc.args, strings.NewReader("payload"), &out)

			if err == nil {
				t.Fatalf("runKMSWrap(%q) returned no error", tc.args)
			}
			if tc.isHelp {
				if !errors.Is(err, flag.ErrHelp) {
					t.Fatalf("runKMSWrap(-h) = %v, want flag.ErrHelp", err)
				}
			} else if err.Error() != tc.wantErr {
				t.Fatalf("runKMSWrap(%q) = %q, want %q", tc.args, err, tc.wantErr)
			}
			if out.Len() != 0 {
				t.Fatalf("a rejected invocation still wrote an envelope: %q", out.String())
			}
		})
	}
}

// TestKMSWrapFileIO covers the --in and --out plumbing, including the artifact's
// on-disk shape. The mode matters because the envelope lands wherever a deploy
// script points it, and the absence of a trailing newline matters because the
// consumer decodes with base64.StdEncoding, which rejects one.
func TestKMSWrapFileIO(t *testing.T) {
	root := ephemeralRoot(t)
	t.Setenv("KMS_ROOT_KEY_FILE", writeBytes(t, "kms_root.key", root))

	dir := t.TempDir()
	inPath := filepath.Join(dir, "datakey.bin")
	plaintext := []byte("data-key-material-from-a-file")
	if err := os.WriteFile(inPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	outPath := filepath.Join(dir, "sub", "..", "wrapped.b64")

	var stdout bytes.Buffer
	if err := runKMSWrap([]string{"--kid", "k1", "--in", inPath, "--out", outPath}, strings.NewReader("ignored"), &stdout); err != nil {
		t.Fatalf("runKMSWrap: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("--out to a file still wrote to stdout: %q", stdout.String())
	}

	written, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if bytes.HasSuffix(written, []byte("\n")) {
		t.Fatalf("artifact ends with a newline, which base64.StdEncoding rejects: %q", written)
	}
	info, err := os.Stat(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("stat artifact: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("artifact mode = %v, want 0600", perm)
	}

	envelope, err := base64.StdEncoding.DecodeString(string(written))
	if err != nil {
		t.Fatalf("artifact is not valid base64: %v", err)
	}
	svc, err := kms.New(root)
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	defer svc.Close()
	got, err := svc.Unwrap("k1", envelope)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("file round-trip mismatch: got %q want %q", got, plaintext)
	}
}

// TestKMSWrapIOFailures covers the error paths around the plaintext and the
// artifact. Each one must be reported, not swallowed: a wrap that quietly
// produced nothing would leave the deploy pipeline writing an empty secret.
func TestKMSWrapIOFailures(t *testing.T) {
	root := ephemeralRoot(t)
	dir := t.TempDir()

	t.Run("unreadable input file", func(t *testing.T) {
		t.Setenv("KMS_ROOT_KEY_FILE", writeBytes(t, "kms_root.key", root))
		var out bytes.Buffer
		err := runKMSWrap([]string{"--kid", "k", "--in", filepath.Join(dir, "absent.bin")}, strings.NewReader(""), &out)
		if err == nil || !strings.HasPrefix(err.Error(), "read plaintext: ") {
			t.Fatalf("error = %v, want a read plaintext failure", err)
		}
		if out.Len() != 0 {
			t.Fatalf("an unreadable input still produced output: %q", out.String())
		}
	})

	t.Run("unwritable output path", func(t *testing.T) {
		t.Setenv("KMS_ROOT_KEY_FILE", writeBytes(t, "kms_root.key", root))
		var out bytes.Buffer
		err := runKMSWrap([]string{"--kid", "k", "--out", filepath.Join(dir, "no-such-dir", "wrapped.b64")}, strings.NewReader("x"), &out)
		if err == nil {
			t.Fatal("writing into a missing directory reported success")
		}
	})

	t.Run("stdout that cannot be written", func(t *testing.T) {
		t.Setenv("KMS_ROOT_KEY_FILE", writeBytes(t, "kms_root.key", root))
		err := runKMSWrap([]string{"--kid", "k"}, strings.NewReader("x"), failingWriter{})
		if !errors.Is(err, errWriteFailed) {
			t.Fatalf("error = %v, want the underlying write failure", err)
		}
	})

	t.Run("missing root key file", func(t *testing.T) {
		t.Setenv("KMS_ROOT_KEY_FILE", filepath.Join(dir, "absent.key"))
		var out bytes.Buffer
		err := runKMSWrap([]string{"--kid", "k"}, strings.NewReader("x"), &out)
		if err == nil || !strings.HasPrefix(err.Error(), "load KMS root: ") {
			t.Fatalf("error = %v, want a load KMS root failure", err)
		}
	})

	t.Run("root key too short", func(t *testing.T) {
		t.Setenv("KMS_ROOT_KEY_FILE", writeBytes(t, "short.key", []byte("not-32-bytes")))
		var out bytes.Buffer
		err := runKMSWrap([]string{"--kid", "k"}, strings.NewReader("x"), &out)
		if err == nil || !strings.Contains(err.Error(), "root key must be at least 32 bytes") {
			t.Fatalf("error = %v, want a short-root rejection", err)
		}
		if out.Len() != 0 {
			t.Fatalf("a rejected root still produced an envelope: %q", out.String())
		}
	})
}

// TestKMSWrapSealFailureIsReported covers the last failure Wrap can still report
// once the kid and the root have passed their own checks: the AEAD seal draws a
// nonce from crypto/rand.Reader, and this starves it.
//
// The second assertion is the one that matters. base64 of a nil envelope is the
// empty string, so a swallowed seal error would exit zero having written a
// zero-length artifact, and the deploy pipeline would ship a file that decodes
// cleanly and carries no key.
func TestKMSWrapSealFailureIsReported(t *testing.T) {
	// Every fixture that needs real entropy is built first: once the reader is
	// starved, crypto/rand.Read does not fail, it takes the process down.
	t.Setenv("KMS_ROOT_KEY_FILE", writeBytes(t, "kms_root.key", ephemeralRoot(t)))
	kmsStarveEntropy(t)

	var out bytes.Buffer
	err := runKMSWrap([]string{"--kid", "life42-root-kek"}, strings.NewReader("payload"), &out)
	if err == nil || !strings.HasPrefix(err.Error(), "wrap: ") {
		t.Fatalf("error = %v, want the failure attributed to the wrap step", err)
	}
	if out.Len() != 0 {
		t.Fatalf("a failed wrap still produced an artifact: %q", out.String())
	}
}

// kmsStarveEntropy swaps the process CSPRNG for the duration of one test.
func kmsStarveEntropy(t *testing.T) {
	t.Helper()
	orig := rand.Reader
	rand.Reader = starvedReader{}
	t.Cleanup(func() { rand.Reader = orig })
}

// TestKMSRootKeyIsWhitespaceTrimmed pins a sharp edge of the _FILE convention.
// config.LoadSecret trims whitespace so that a key written with `echo` is not
// rejected for its trailing newline, but it trims raw binary key files too: a
// root generated with `head -c 32 /dev/urandom` whose first or last byte happens
// to be one of the six ASCII whitespace values loses it, and the command then
// refuses a file that is 32 bytes on disk.
//
// The wrap command and the server both read the root through LoadSecret, so they
// agree with each other and the envelope still opens; the failure mode is a
// confusing rejection at provisioning time, not a mismatch at runtime. Both
// halves are asserted here because a change to either one is a change to the
// deployment contract.
func TestKMSRootKeyIsWhitespaceTrimmed(t *testing.T) {
	t.Run("a trimmed root is rejected as too short", func(t *testing.T) {
		root := append([]byte("\n"), bytes.Repeat([]byte("k"), 31)...) // 32 bytes on disk
		t.Setenv("KMS_ROOT_KEY_FILE", writeBytes(t, "kms_root.key", root))

		var out bytes.Buffer
		err := runKMSWrap([]string{"--kid", "k"}, strings.NewReader("x"), &out)
		if err == nil || !strings.Contains(err.Error(), "root key must be at least 32 bytes") {
			t.Fatalf("error = %v, want the short-root rejection a trimmed 32-byte file produces", err)
		}
	})

	t.Run("the wrap command trims exactly as the server does", func(t *testing.T) {
		root := append([]byte(" "), bytes.Repeat([]byte("k"), 40)...)
		t.Setenv("KMS_ROOT_KEY_FILE", writeBytes(t, "kms_root.key", root))

		var out bytes.Buffer
		if err := runKMSWrap([]string{"--kid", "k"}, strings.NewReader("payload"), &out); err != nil {
			t.Fatalf("runKMSWrap: %v", err)
		}
		envelope, err := base64.StdEncoding.DecodeString(out.String())
		if err != nil {
			t.Fatalf("decode envelope: %v", err)
		}

		// The server derives its KEK from whatever LoadSecret returns, so that
		// is what the envelope must be openable with.
		loaded, err := config.LoadSecret("KMS_ROOT_KEY")
		if err != nil {
			t.Fatalf("LoadSecret: %v", err)
		}
		svc, err := kms.New([]byte(loaded))
		if err != nil {
			t.Fatalf("kms.New: %v", err)
		}
		defer svc.Close()
		if _, err := svc.Unwrap("k", envelope); err != nil {
			t.Fatalf("the server's view of the root does not open the artifact: %v", err)
		}

		if _, err := kms.New(root); err != nil {
			t.Fatalf("fixture is unusable: %v", err)
		}
		untrimmed, err := kms.New(root)
		if err != nil {
			t.Fatalf("kms.New with the untrimmed bytes: %v", err)
		}
		defer untrimmed.Close()
		if _, err := untrimmed.Unwrap("k", envelope); err == nil {
			t.Fatal("the untrimmed file bytes also open the envelope, so nothing was trimmed")
		}
	})
}

// TestKMSWrapAcceptsEmptyInput records the current contract rather than
// endorsing it. An empty plaintext produces a well-formed envelope that unwraps
// to zero bytes, so a pipeline that pipes an empty file into `vault kms wrap`
// gets a valid-looking artifact instead of an error and only discovers the
// mistake when whatever consumes the unwrapped key fails.
func TestKMSWrapAcceptsEmptyInput(t *testing.T) {
	root := ephemeralRoot(t)
	t.Setenv("KMS_ROOT_KEY_FILE", writeBytes(t, "kms_root.key", root))

	var out bytes.Buffer
	if err := runKMSWrap([]string{"--kid", "k"}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("runKMSWrap: %v", err)
	}
	envelope, err := base64.StdEncoding.DecodeString(out.String())
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	svc, err := kms.New(root)
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	defer svc.Close()
	got, err := svc.Unwrap("k", envelope)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("unwrapped %d bytes from an empty input, want 0", len(got))
	}
}

// TestReadInputAndWriteOutputTreatDashAsAStream pins the "-" and "" conventions
// both helpers share. They are the reason a wrap can be piped, and the empty
// string is the case a caller hits by passing an unset variable rather than by
// typing a dash.
func TestReadInputAndWriteOutputTreatDashAsAStream(t *testing.T) {
	dir := t.TempDir()
	onDisk := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(onDisk, []byte("from-a-file"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{name: "dash reads stdin", path: "-", want: "from-stdin"},
		{name: "empty path reads stdin", path: "", want: "from-stdin"},
		{name: "a path reads the file", path: onDisk, want: "from-a-file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readInput(tc.path, strings.NewReader("from-stdin"))
			if err != nil {
				t.Fatalf("readInput(%q): %v", tc.path, err)
			}
			if string(got) != tc.want {
				t.Fatalf("readInput(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name    string
		path    string
		toFile  bool
		wantOut string
	}{
		{name: "dash writes stdout", path: "-", wantOut: "envelope"},
		{name: "empty path writes stdout", path: "", wantOut: "envelope"},
		{name: "a path writes the file", path: filepath.Join(dir, "out.b64"), toFile: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeOutput(tc.path, "envelope", &out); err != nil {
				t.Fatalf("writeOutput(%q): %v", tc.path, err)
			}
			if out.String() != tc.wantOut {
				t.Fatalf("writeOutput(%q) wrote %q to stdout, want %q", tc.path, out.String(), tc.wantOut)
			}
			if tc.toFile {
				data, err := os.ReadFile(filepath.Clean(tc.path))
				if err != nil {
					t.Fatalf("read output file: %v", err)
				}
				if string(data) != "envelope" {
					t.Fatalf("output file = %q, want %q", data, "envelope")
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// ephemeralRoot returns 32 random bytes with no whitespace at either end.
//
// The trimming in config.LoadSecret is why the resampling is here: a plain
// 32-byte random root has roughly a one in twenty-two chance of starting or
// ending with an ASCII whitespace byte, and such a root is trimmed below the
// 32-byte minimum and rejected. A test that generated one without noticing would
// fail a few times in a hundred runs for reasons that have nothing to do with
// what it asserts.
func ephemeralRoot(t *testing.T) []byte {
	t.Helper()
	for attempt := 0; attempt < 32; attempt++ {
		root := make([]byte, 32)
		if _, err := rand.Read(root); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if len(strings.TrimSpace(string(root))) == 32 {
			return root
		}
	}
	t.Fatal("could not draw a root that survives whitespace trimming")
	return nil
}

// writeBytes writes content into a fresh temporary directory and returns the path.
func writeBytes(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// errWriteFailed is what failingWriter returns, so a test can assert the wrap
// surfaced the underlying error rather than inventing its own.
var errWriteFailed = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteFailed }
