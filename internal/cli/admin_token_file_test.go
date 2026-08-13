package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// These tests guard the regression where ADMIN_TOKEN_FILE was parsed into the
// config and then read by nothing. An operator mounted a secret, the server
// started clean, and the credential the CLI actually accepted was a different
// one generated on first boot and printed to stdout. scripts/generate-secrets.sh
// writes that file and charts/vault/templates/NOTES.txt tells the operator to
// authenticate with `--admin-token "$(cat /run/secrets/admin-token)"`, so the
// documented quickstart could not work.

// newCLIWithAdminTokenFile builds a CLI the way cmd/vault does, with
// ADMIN_TOKEN_FILE pointing at a file holding contents.
//
// The returned string is the admin_config store. The stock mockAdminConfigRepo
// returns "" from Get no matter what Set wrote, which cannot answer the only
// question that matters here: is the credential handed to the operator the one
// the CLI later accepts.
func newCLIWithAdminTokenFile(t *testing.T, contents string) (*CLI, *string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "admin-token")
	if err := os.WriteFile(path, []byte(contents+"\n"), 0o600); err != nil {
		t.Fatalf("write admin token file: %v", err)
	}
	t.Setenv("ADMIN_TOKEN_FILE", path)

	stored := new(string)
	admin := &mockAdminConfigRepo{
		GetFn: func(_ context.Context, key string) (string, error) {
			if key != "admin_token_hash" {
				return "", nil
			}
			return *stored, nil
		},
		SetFn: func(_ context.Context, key, value string) error {
			if key == "admin_token_hash" {
				*stored = value
			}
			return nil
		},
	}

	c := New(&mockClientRepo{}, &mockUserRepo{}, &mockRefreshTokenRepo{}, admin, &mockAuditRepo{}, "")
	return c, stored
}

func TestInitAdminTokenUsesProvisionedHash(t *testing.T) {
	ctx := context.Background()
	const token = "b1946ac92492d2347c6235b4d2611184c0d1f3a9e8b7c6d5a4f3e2d1c0b9a8f7"

	hash, err := vaultcrypto.HashPassword(token)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	c, stored := newCLIWithAdminTokenFile(t, hash)
	out := captureStdout(t, func() {
		if initErr := c.InitAdminToken(ctx); initErr != nil {
			t.Fatalf("InitAdminToken: %v", initErr)
		}
	})

	if *stored != hash {
		t.Errorf("admin_token_hash = %q, want the hash from ADMIN_TOKEN_FILE %q", *stored, hash)
	}
	if !c.verifyAdminToken(ctx, token) {
		t.Error("the admin token provisioned through ADMIN_TOKEN_FILE is rejected by the CLI")
	}
	if strings.Contains(out, "FIRST BOOT") {
		t.Errorf("a generated admin token was printed to stdout despite ADMIN_TOKEN_FILE being provisioned: %q", out)
	}
}

func TestInitAdminTokenUsesProvisionedPlaintext(t *testing.T) {
	ctx := context.Background()
	// What scripts/generate-secrets.sh writes: `openssl rand -hex 32`.
	const token = "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1"

	c, stored := newCLIWithAdminTokenFile(t, token)
	out := captureStdout(t, func() {
		if initErr := c.InitAdminToken(ctx); initErr != nil {
			t.Fatalf("InitAdminToken: %v", initErr)
		}
	})

	if *stored == "" {
		t.Fatal("nothing was written to admin_token_hash")
	}
	if !c.verifyAdminToken(ctx, token) {
		t.Error("the admin token provisioned through ADMIN_TOKEN_FILE is rejected by the CLI")
	}
	if strings.Contains(out, token) {
		t.Error("the provisioned admin token was echoed to stdout, which under systemd is the journal")
	}
	if strings.Contains(out, "FIRST BOOT") {
		t.Errorf("a generated admin token was printed to stdout despite ADMIN_TOKEN_FILE being provisioned: %q", out)
	}
}

// TestInitAdminTokenReportsIgnoredFile covers the second shape of the same
// trap: once the database holds a hash (a restart, or a rotate-admin-token),
// the mounted file is no longer the credential. That is correct, but it must
// not be silent, or the operator keeps trusting a file that is not in force.
func TestInitAdminTokenReportsIgnoredFile(t *testing.T) {
	ctx := context.Background()

	fileHash, err := vaultcrypto.HashPassword("2b8f1c3d4e5a6b7c8d9e0f1a2b3c4d5e")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	rotatedHash, err := vaultcrypto.HashPassword("ffeeddccbbaa99887766554433221100")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	c, stored := newCLIWithAdminTokenFile(t, fileHash)
	*stored = rotatedHash

	msg := captureStderr(t, func() {
		if initErr := c.InitAdminToken(ctx); initErr != nil {
			t.Fatalf("InitAdminToken: %v", initErr)
		}
	})

	if *stored != rotatedHash {
		t.Error("the mounted file overwrote a rotated admin token")
	}
	if !strings.Contains(msg, "ADMIN_TOKEN_FILE") {
		t.Errorf("no warning that ADMIN_TOKEN_FILE is not in force, got %q", msg)
	}
}

// TestInitAdminTokenUnreadableFileIsAnError keeps a mount that disappeared
// between config validation and first boot from degrading back into the silent
// generate-and-print path.
func TestInitAdminTokenUnreadableFileIsAnError(t *testing.T) {
	t.Setenv("ADMIN_TOKEN_FILE", filepath.Join(t.TempDir(), "absent"))

	c := New(&mockClientRepo{}, &mockUserRepo{}, &mockRefreshTokenRepo{}, &mockAdminConfigRepo{}, &mockAuditRepo{}, "")
	out := captureStdout(t, func() {
		if err := c.InitAdminToken(context.Background()); err == nil {
			t.Error("an unreadable ADMIN_TOKEN_FILE was accepted")
		}
	})
	if strings.Contains(out, "FIRST BOOT") {
		t.Errorf("an admin token was generated despite an unreadable ADMIN_TOKEN_FILE: %q", out)
	}
}
