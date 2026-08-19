package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// cliconfigStubHasher replaces the Argon2id hasher for the duration of a test
// and reports how many times it was reached.
func cliconfigStubHasher(t *testing.T, err error) *int {
	t.Helper()
	calls := 0
	old := hashPassword
	hashPassword = func(string, ...string) (string, error) {
		calls++
		return "", err
	}
	t.Cleanup(func() { hashPassword = old })
	return &calls
}

// cliconfigExitCalled is the panic value the stub exit uses to model os.Exit's
// "never returns" contract inside a test process.
type cliconfigExitCalled struct{ code int }

// cliconfigStubExit swaps the process-exit seam for one that unwinds the stack
// like the real os.Exit would, and returns the recorded codes.
func cliconfigStubExit(t *testing.T) *[]int {
	t.Helper()
	var codes []int
	old := exitProcess
	exitProcess = func(code int) {
		codes = append(codes, code)
		panic(cliconfigExitCalled{code})
	}
	t.Cleanup(func() { exitProcess = old })
	return &codes
}

// cliconfigRunCatchingExit runs the CLI and reports whether the admin-token
// gate terminated the process before dispatch.
func cliconfigRunCatchingExit(c *CLI, args []string) (exited bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(cliconfigExitCalled); !ok {
				panic(r)
			}
			exited = true
		}
	}()
	c.Run(context.Background(), args)
	return false
}

// Every admin command is gated on --admin-token. A missing, empty, wrong or
// unreadable token must terminate with a non-zero status BEFORE the switch
// dispatches, otherwise an unauthenticated caller reaches revoke-all-sessions.
func TestRun_AdminTokenGateDeniesBeforeDispatch(t *testing.T) {
	goodToken := "the-real-admin-token"
	goodHash := hashToken(t, goodToken)

	tests := []struct {
		name  string
		args  []string
		getFn func(context.Context, string) (string, error)
	}{
		{
			name:  "no token flag",
			args:  []string{"vault", "revoke-all-sessions"},
			getFn: func(context.Context, string) (string, error) { return goodHash, nil },
		},
		{
			name:  "flag present but value missing",
			args:  []string{"vault", "revoke-all-sessions", "--admin-token"},
			getFn: func(context.Context, string) (string, error) { return goodHash, nil },
		},
		{
			name:  "wrong token",
			args:  []string{"vault", "revoke-all-sessions", "--admin-token", "not-the-token"},
			getFn: func(context.Context, string) (string, error) { return goodHash, nil },
		},
		{
			name:  "config store unavailable",
			args:  []string{"vault", "revoke-all-sessions", "--admin-token", goodToken},
			getFn: func(context.Context, string) (string, error) { return "", errors.New("db down") },
		},
		{
			name:  "no token provisioned yet",
			args:  []string{"vault", "revoke-all-sessions", "--admin-token", goodToken},
			getFn: func(context.Context, string) (string, error) { return "", nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, _, tokens, admin := newTestCLI()
			admin.GetFn = tt.getFn
			revoked := false
			tokens.RevokeAllFn = func(context.Context) error { revoked = true; return nil }
			codes := cliconfigStubExit(t)

			var exited bool
			stderr := captureStderr(t, func() {
				exited = cliconfigRunCatchingExit(c, tt.args)
			})

			if !exited {
				t.Fatal("unauthenticated invocation was not terminated")
			}
			if len(*codes) != 1 || (*codes)[0] != 1 {
				t.Errorf("exit codes = %v, want [1]", *codes)
			}
			if revoked {
				t.Error("command ran despite failed admin authentication")
			}
			if !strings.Contains(stderr, "Admin authentication required") {
				t.Errorf("stderr = %q, want an authentication error", stderr)
			}
			if strings.Contains(stderr, goodHash) || strings.Contains(stderr, goodToken) {
				t.Error("the admin token or its hash leaked to stderr")
			}
		})
	}
}

// A valid token must get through the gate without exiting, or the gate would
// be a denial of service rather than an authorization check.
func TestRun_AdminTokenGateAdmitsValidToken(t *testing.T) {
	const token = "the-real-admin-token"
	c, _, _, tokens, admin := newTestCLI()
	hash := hashToken(t, token)
	admin.GetFn = func(context.Context, string) (string, error) { return hash, nil }
	revoked := false
	tokens.RevokeAllFn = func(context.Context) error { revoked = true; return nil }
	codes := cliconfigStubExit(t)

	captureStderr(t, func() {
		captureStdout(t, func() {
			if cliconfigRunCatchingExit(c, []string{"vault", "revoke-all-sessions", "--admin-token", token}) {
				t.Error("a valid admin token was rejected")
			}
		})
	})

	if len(*codes) != 0 {
		t.Errorf("exit codes = %v, want none", *codes)
	}
	if !revoked {
		t.Error("authenticated command did not run")
	}
}

// The argon2id semaphore rejects hashing when four operations are already in
// flight. Every credential-minting command must abort on that rejection: a
// client, an admin token or a rotated secret persisted with an empty hash is a
// credential that verifies against nothing and locks the operator out.
func TestCommands_HashFailureMintsNoCredential(t *testing.T) {
	ctx := context.Background()

	t.Run("add-client", func(t *testing.T) {
		c, clients, _, _, _ := newTestCLI()
		created := 0
		clients.CreateFn = func(context.Context, *model.Client) error { created++; return nil }
		calls := cliconfigStubHasher(t, vaultcrypto.ErrArgon2Overloaded)

		var stdout string
		stderr := captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				if !c.addClient(ctx, []string{"--name", "frontend", "--role", "web", "--scopes", "user:read"}) {
					t.Error("expected handled=true")
				}
			})
		})

		if *calls != 1 {
			t.Errorf("hasher called %d times, want 1", *calls)
		}
		if created != 0 {
			t.Error("client was written with no secret hash")
		}
		if !strings.Contains(stderr, vaultcrypto.ErrArgon2Overloaded.Error()) {
			t.Errorf("stderr = %q, want the overload error", stderr)
		}
		if strings.Contains(stdout, "Client created") {
			t.Errorf("success was reported to stdout: %q", stdout)
		}
	})

	t.Run("rotate-admin-token", func(t *testing.T) {
		c, _, _, _, admin := newTestCLI()
		var stored []string
		admin.SetFn = func(_ context.Context, _, value string) error {
			stored = append(stored, value)
			return nil
		}
		calls := cliconfigStubHasher(t, vaultcrypto.ErrArgon2Overloaded)

		var stdout string
		stderr := captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				if !c.rotateAdminToken(ctx) {
					t.Error("expected handled=true")
				}
			})
		})

		if *calls != 1 {
			t.Errorf("hasher called %d times, want 1", *calls)
		}
		if len(stored) != 0 {
			t.Errorf("admin_token_hash was overwritten with %q, locking the operator out", stored[0])
		}
		if !strings.Contains(stderr, vaultcrypto.ErrArgon2Overloaded.Error()) {
			t.Errorf("stderr = %q, want the overload error", stderr)
		}
		if strings.Contains(stdout, "New admin token:") {
			t.Errorf("a token was printed that was never stored: %q", stdout)
		}
	})

	t.Run("first-boot init", func(t *testing.T) {
		c, _, _, _, admin := newTestCLI()
		admin.GetFn = func(context.Context, string) (string, error) { return "", nil }
		stored := 0
		admin.SetFn = func(context.Context, string, string) error { stored++; return nil }
		calls := cliconfigStubHasher(t, vaultcrypto.ErrArgon2Overloaded)

		var err error
		stdout := captureStdout(t, func() {
			err = c.InitAdminToken(ctx)
		})

		if err == nil {
			t.Fatal("first boot reported success without storing a token hash")
		}
		if !errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			t.Errorf("error %v does not wrap ErrArgon2Overloaded", err)
		}
		if !strings.Contains(err.Error(), "hash admin token") {
			t.Errorf("error %q does not say which step failed", err)
		}
		if *calls != 1 {
			t.Errorf("hasher called %d times, want 1", *calls)
		}
		if stored != 0 {
			t.Error("a token hash was stored despite the hashing failure")
		}
		if strings.Contains(stdout, "FIRST BOOT") {
			t.Errorf("a first-boot token was printed that was never stored: %q", stdout)
		}
	})
}

// cliconfigFailingReader always fails, standing in for an exhausted entropy
// source.
type cliconfigFailingReader struct{}

func (cliconfigFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy exhausted")
}

// rotate-jwks mints a signing key. If RSA generation fails the command must
// print nothing that looks like a key and must not write the output file:
// a truncated or empty key file would be loaded at the next boot and every
// token the service issued would verify against nothing.
func TestRotateJWKS_KeyGenerationFailureWritesNothing(t *testing.T) {
	c, _, _, _, _ := newTestCLI()
	out := t.TempDir() + "/signing-key.pem"

	// crypto/rsa only honors a replaced crypto/rand.Reader when this GODEBUG
	// knob is set; without it key generation draws from the internal DRBG and
	// the failure cannot be injected at all.
	t.Setenv("GODEBUG", "cryptocustomrand=1")
	old := rand.Reader
	rand.Reader = cliconfigFailingReader{}
	t.Cleanup(func() { rand.Reader = old })

	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if !c.rotateJWKS([]string{"--output", out}) {
				t.Error("expected handled=true")
			}
		})
	})

	rand.Reader = old

	if !strings.Contains(stderr, "ERROR: generate RSA key pair") {
		t.Fatalf("stderr = %q, want an RSA generation error (is the cryptocustomrand GODEBUG knob still supported?)", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	if strings.Contains(stderr, "RSA PRIVATE KEY") {
		t.Error("a private key block was emitted despite the failure")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("an output key file was written despite the failure")
	}
}
