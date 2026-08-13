package cli

import (
	"context"
	"errors"
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

// TestInitAdminTokenReportsAFailureToHashTheProvisionedPlaintext covers the
// other half of the plaintext branch. Argon2id refuses work when its semaphore
// is full, and first boot is a plausible moment to meet that: a fleet coming up
// together bootstraps and serves logins at once. If the refusal were swallowed,
// InitAdminToken would fall through to Set with an empty hash, and an empty hash
// verifies against no token at all, so the mounted credential would be dead and
// the operator would be told nothing.
func TestInitAdminTokenReportsAFailureToHashTheProvisionedPlaintext(t *testing.T) {
	// The plaintext form scripts/generate-secrets.sh writes, so the hasher is
	// reached at all; a pre-hashed file would be stored verbatim.
	c, stored := newCLIWithAdminTokenFile(t, "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1")
	calls := cliconfigStubHasher(t, vaultcrypto.ErrArgon2Overloaded)

	var err error
	out := captureStdout(t, func() { err = c.InitAdminToken(context.Background()) })

	if err == nil {
		t.Fatal("InitAdminToken reported success while the provisioned token could not be hashed")
	}
	if !errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
		t.Errorf("err = %v, want it to wrap ErrArgon2Overloaded so the operator can retry", err)
	}
	if !strings.Contains(err.Error(), "ADMIN_TOKEN_FILE") {
		t.Errorf("err = %q, does not name the mounted file as the credential that failed", err)
	}
	if *calls != 1 {
		t.Errorf("hasher called %d times, want 1", *calls)
	}
	if *stored != "" {
		t.Errorf("admin_token_hash was written as %q; an empty or unhashed value verifies against nothing", *stored)
	}
	if out != "" {
		t.Errorf("stdout = %q, want nothing said about a token that was never stored", out)
	}
}

// TestInitAdminTokenReportsAFailureToStoreTheProvisionedToken keeps the write to
// admin_config from being fire-and-forget. Reporting success while the store
// rejected the write leaves the database with no admin_token_hash, so every
// later `vault ... --admin-token` fails with "Admin authentication required."
// while the boot log says the mounted file was taken.
func TestInitAdminTokenReportsAFailureToStoreTheProvisionedToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-token")
	hash, err := vaultcrypto.HashPassword("d0b1e2f3a4958677a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if writeErr := os.WriteFile(path, []byte(hash+"\n"), 0o600); writeErr != nil {
		t.Fatalf("write admin token file: %v", writeErr)
	}
	t.Setenv("ADMIN_TOKEN_FILE", path)

	storeErr := errors.New("admin_config write rejected")
	admin := &mockAdminConfigRepo{
		GetFn: func(context.Context, string) (string, error) { return "", nil },
		SetFn: func(context.Context, string, string) error { return storeErr },
	}
	c := New(&mockClientRepo{}, &mockUserRepo{}, &mockRefreshTokenRepo{}, admin, &mockAuditRepo{}, "")

	var initErr error
	out := captureStdout(t, func() { initErr = c.InitAdminToken(context.Background()) })

	if !errors.Is(initErr, storeErr) {
		t.Fatalf("err = %v, want the store failure so the caller can report it", initErr)
	}
	if strings.Contains(out, "ADMIN_TOKEN_FILE") {
		t.Errorf("stdout claimed the mounted token was taken while the store rejected it: %q", out)
	}
	if strings.Contains(out, "FIRST BOOT") {
		t.Errorf("a token was minted and printed after the store failure: %q", out)
	}
}

// TestInitAdminTokenChecksAPlaintextFileAgainstTheStoredHash covers the
// verification half of the "your mount is not in force" warning. The stored
// value is always an Argon2id hash, so a file holding the plaintext token can be
// compared only by verifying it; a string comparison would never match and would
// warn on every boot, training operators to ignore the one message that tells
// them their mounted credential has been rotated away.
func TestInitAdminTokenChecksAPlaintextFileAgainstTheStoredHash(t *testing.T) {
	const mounted = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"

	t.Run("the mounted plaintext is still the credential in force", func(t *testing.T) {
		c, stored := newCLIWithAdminTokenFile(t, mounted)
		*stored = hashToken(t, mounted)
		inForce := *stored

		msg := captureStderr(t, func() {
			if err := c.InitAdminToken(context.Background()); err != nil {
				t.Fatalf("InitAdminToken: %v", err)
			}
		})

		if strings.Contains(msg, "WARNING") {
			t.Errorf("the operator was warned about a mount that does verify against the stored hash: %q", msg)
		}
		if *stored != inForce {
			t.Error("the stored hash was rewritten on a boot that had nothing to change")
		}
		if !c.verifyAdminToken(context.Background(), mounted) {
			t.Error("the mounted token is rejected by the CLI, so the warning would have been correct")
		}
	})

	t.Run("the mounted plaintext was rotated away", func(t *testing.T) {
		c, stored := newCLIWithAdminTokenFile(t, mounted)
		rotated := hashToken(t, "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9")
		*stored = rotated

		msg := captureStderr(t, func() {
			if err := c.InitAdminToken(context.Background()); err != nil {
				t.Fatalf("InitAdminToken: %v", err)
			}
		})

		if !strings.Contains(msg, "ADMIN_TOKEN_FILE") {
			t.Errorf("no warning that the mounted plaintext is not in force, got %q", msg)
		}
		if *stored != rotated {
			t.Error("the mounted file overwrote a rotated admin token")
		}
		if strings.Contains(msg, mounted) {
			t.Error("the admin token itself was written to stderr, which under systemd is the journal")
		}
	})
}
