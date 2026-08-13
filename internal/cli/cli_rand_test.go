package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// cliScriptedReader stands in for crypto/rand.Reader: it serves whole reads
// until the budget is spent, then fails. While it is installed, only code
// paths that return BEFORE any HashPassword call may run: HashPassword uses
// crypto/rand.Read, which is process-fatal on a failing Reader.
type cliScriptedReader struct {
	reads int
}

func (r *cliScriptedReader) Read(p []byte) (int, error) {
	if r.reads <= 0 {
		return 0, errors.New("entropy exhausted")
	}
	r.reads--
	for i := range p {
		p[i] = 0x42
	}
	return len(p), nil
}

// swapRandReader installs r as crypto/rand.Reader and restores the original
// when the test ends. Package tests already serialize on globals
// (os.Stdout/os.Stderr), so this is safe without t.Parallel.
func swapRandReader(t *testing.T, r io.Reader) {
	t.Helper()
	old := rand.Reader
	rand.Reader = r
	t.Cleanup(func() { rand.Reader = old })
}

func TestAddClient_EntropyFailureAborts(t *testing.T) {
	ctx := context.Background()
	args := []string{"--name", "frontend", "--role", "web", "--scopes", "user:read"}

	t.Run("client ID generation fails", func(t *testing.T) {
		c, clients, _, _, _ := newTestCLI()
		created := false
		clients.CreateFn = func(context.Context, *model.Client) error { created = true; return nil }
		swapRandReader(t, &cliScriptedReader{reads: 0})

		stderr := captureStderr(t, func() {
			if !c.addClient(ctx, args) {
				t.Error("expected handled=true")
			}
		})
		if !strings.Contains(stderr, "ERROR:") || !strings.Contains(stderr, "entropy exhausted") {
			t.Errorf("expected entropy error on stderr, got %q", stderr)
		}
		if created {
			t.Error("client was created despite an entropy failure")
		}
	})

	t.Run("client secret generation fails", func(t *testing.T) {
		c, clients, _, _, _ := newTestCLI()
		created := false
		clients.CreateFn = func(context.Context, *model.Client) error { created = true; return nil }
		swapRandReader(t, &cliScriptedReader{reads: 1})

		stderr := captureStderr(t, func() {
			if !c.addClient(ctx, args) {
				t.Error("expected handled=true")
			}
		})
		if !strings.Contains(stderr, "ERROR:") || !strings.Contains(stderr, "entropy exhausted") {
			t.Errorf("expected entropy error on stderr, got %q", stderr)
		}
		if created {
			t.Error("client was created despite an entropy failure")
		}
	})
}


func TestRotateJWKS_KidEntropyFailureAborts(t *testing.T) {
	c, _, _, _, _ := newTestCLI()
	// rsa.GenerateKey does not read from a replaced rand.Reader (key
	// generation draws from the internal DRBG), so a zero-budget reader
	// lets the key pair generate and fails only the kid read.
	swapRandReader(t, &cliScriptedReader{reads: 0})

	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if !c.rotateJWKS(nil) {
				t.Error("expected handled=true")
			}
		})
	})
	if !strings.Contains(stderr, "ERROR: generate key ID: crypto/rand: entropy exhausted") {
		t.Errorf("expected kid entropy error on stderr, got %q", stderr)
	}
	if stdout != "" {
		t.Errorf("expected no stdout output, got %q", stdout)
	}
}

func TestInitAdminToken_EntropyFailureAborts(t *testing.T) {
	c, _, _, _, admin := newTestCLI()
	stored := false
	admin.SetFn = func(context.Context, string, string) error { stored = true; return nil }
	swapRandReader(t, &cliScriptedReader{reads: 0})

	stdout := captureStdout(t, func() {
		err := c.InitAdminToken(context.Background())
		if err == nil {
			t.Fatal("expected error from InitAdminToken")
		}
		if err.Error() != "generate admin token: crypto/rand: entropy exhausted" {
			t.Errorf("unexpected error: %v", err)
		}
	})
	if stdout != "" {
		t.Errorf("expected no output, got %q", stdout)
	}
	if stored {
		t.Error("a hash was stored despite an entropy failure")
	}
}

func TestRotateAdminToken_EntropyFailureAborts(t *testing.T) {
	c, _, _, _, admin := newTestCLI()
	stored := false
	admin.SetFn = func(context.Context, string, string) error { stored = true; return nil }
	swapRandReader(t, &cliScriptedReader{reads: 0})

	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if !c.rotateAdminToken(context.Background()) {
				t.Error("expected handled=true")
			}
		})
	})
	if !strings.Contains(stderr, "ERROR:") || !strings.Contains(stderr, "entropy exhausted") {
		t.Errorf("expected entropy error on stderr, got %q", stderr)
	}
	if strings.Contains(stdout, "New admin token:") {
		t.Error("a token was printed despite an entropy failure")
	}
	if stored {
		t.Error("a hash was stored despite an entropy failure")
	}
}
