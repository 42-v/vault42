package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// `vault add-client` is run from Jobs and init containers as often as from a
// keyboard, and its stdout is the pod log there. The secret it mints is a bearer
// credential for the client's whole role, so it belongs in the same sink as
// every other first-boot credential rather than in the process output.
func TestAddClient_SecretNeverReachesTheProcessOutput(t *testing.T) {
	sink := firstBootSink(t)
	c, clients, _, _, _ := newTestCLI()
	var created *model.Client
	clients.CreateFn = func(_ context.Context, cl *model.Client) error {
		created = cl
		return nil
	}

	out := captureStdout(t, func() {
		c.addClient(context.Background(), []string{"vault", "add-client", "--name", "web", "--role", "frontend", "--scopes", "user:read"})
	})

	if created == nil {
		t.Fatal("add-client created no client")
	}

	raw, err := os.ReadFile(sink) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	_, secret, ok := strings.Cut(strings.TrimSpace(string(raw)), "=")
	if !ok || secret == "" {
		t.Fatalf("credential file holds no key=value line: %q", raw)
	}
	if valid, _ := vaultcrypto.VerifyPassword(secret, created.SecretHash); !valid {
		t.Fatal("the credential file does not hold the secret of the client that was created")
	}
	if strings.Contains(out, secret) {
		t.Errorf("the client secret was written to the process output:\n%s", out)
	}
}

// A client whose secret went nowhere cannot authenticate and cannot be repaired:
// only the Argon2id hash is kept. Refuse the row rather than create it.
func TestAddClient_UndeliverableSecretCreatesNoClient(t *testing.T) {
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", "")
	c, clients, _, _, _ := newTestCLI()
	createCalled := false
	clients.CreateFn = func(context.Context, *model.Client) error {
		createCalled = true
		return nil
	}

	captureStdout(t, func() {
		captureStderr(t, func() {
			c.addClient(context.Background(), []string{"vault", "add-client", "--name", "web", "--role", "frontend", "--scopes", "user:read"})
		})
	})

	if createCalled {
		t.Error("a client was created whose secret went nowhere")
	}
}

// rotate-admin-token replaces the credential every administrative subcommand
// authenticates with. Printing the replacement puts the live credential in the
// log the moment the rotation is done, which defeats the rotation.
func TestRotateAdminToken_TokenNeverReachesTheProcessOutput(t *testing.T) {
	sink := firstBootSink(t)
	store := newStoringAdminConfig()
	c := New(nil, nil, nil, store, nil, "")

	out := captureStdout(t, func() { c.rotateAdminToken(context.Background()) })

	stored := store.values["admin_token_hash"]
	if stored == "" {
		t.Fatal("rotate-admin-token stored no hash")
	}
	raw, err := os.ReadFile(sink) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	_, token, ok := strings.Cut(strings.TrimSpace(string(raw)), "=")
	if !ok || token == "" {
		t.Fatalf("credential file holds no key=value line: %q", raw)
	}
	if valid, _ := vaultcrypto.VerifyPassword(token, stored); !valid {
		t.Fatal("the credential file does not hold the token that was installed")
	}
	if strings.Contains(out, token) {
		t.Errorf("the rotated admin token was written to the process output:\n%s", out)
	}
}

// Rotating to a token the operator was never handed locks the CLI out, so an
// undeliverable token must not be installed.
func TestRotateAdminToken_UndeliverableTokenIsNotInstalled(t *testing.T) {
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", "")
	store := newStoringAdminConfig()
	c := New(nil, nil, nil, store, nil, "")

	captureStdout(t, func() {
		captureStderr(t, func() { c.rotateAdminToken(context.Background()) })
	})

	if store.values["admin_token_hash"] != "" {
		t.Error("a token hash was installed for a token the operator never received")
	}
}

// rotate-jwks without --output printed a PKCS#1 RSA private key to stdout. That
// key signs every access token the deployment issues, and stdout is the one
// place it must never go.
func TestRotateJWKS_NeverPrintsThePrivateKey(t *testing.T) {
	c, _, _, _, _ := newTestCLI()

	var out, errOut string
	out = captureStdout(t, func() {
		errOut = captureStderr(t, func() {
			c.rotateJWKS([]string{"vault", "rotate-jwks"})
		})
	})

	if strings.Contains(out, "PRIVATE KEY") {
		t.Errorf("rotate-jwks printed a private key to stdout:\n%s", out)
	}
	if strings.Contains(errOut, "PRIVATE KEY") {
		t.Errorf("rotate-jwks printed a private key to stderr:\n%s", errOut)
	}
	if !strings.Contains(errOut, "--output") {
		t.Errorf("rotate-jwks did not tell the operator to name a key file: %s", errOut)
	}
}

// --output is now the only way the signing key leaves the process, which makes
// how it opens that path part of the same finding. os.WriteFile follows a
// symlink and keeps a pre-existing file's mode, so a path an attacker had
// prepared received the private key at whatever permissions they chose — the
// same disclosure as printing it, one directory along. cmd/recover's openOutput
// already solves this with O_EXCL, which fails with EEXIST on a symlink whether
// or not its target exists.
func TestRotateJWKS_OutputDoesNotFollowASymlinkOrClobber(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "attacker-readable")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "signing-key.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	c, _, _, _, _ := newTestCLI()
	var stderr string
	captureStdout(t, func() {
		stderr = captureStderr(t, func() { c.rotateJWKS([]string{"--output", link}) })
	})

	if !strings.Contains(stderr, "ERROR:") {
		t.Errorf("rotate-jwks did not refuse a symlinked --output: %q", stderr)
	}
	got, err := os.ReadFile(target) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("the private key was written through the symlink: %d bytes", len(got))
	}
}
