package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// --admin-token was the only way to authenticate a `vault` subcommand, and a
// flag is the one delivery mechanism that cannot be made safe: every argument of
// a running process is readable through /proc/<pid>/cmdline by anything running
// as the same uid, it shows in `ps` and in container process listings, and the
// shell keeps it in history afterwards. cmd/recover already says exactly this
// about --dsn.
//
// The repo's convention for a secret is a _FILE env var (ADMIN_TOKEN_FILE,
// BRIDGE_ADMIN_TOKEN_FILE, VAULT_PEPPER_FILE), and the CLI already reads
// ADMIN_TOKEN_FILE to seed admin_token_hash on first boot. This makes that same
// file the authentication path, so the secure route is the default one.
func TestRun_AuthenticatesFromAdminTokenFileWithNoFlag(t *testing.T) {
	token := fakeAdminToken(t)
	c := cliWithProvisionedToken(t, token, token)

	cliconfigStubExit(t)
	var exited bool
	stderr := captureStderr(t, func() {
		captureStdout(t, func() {
			exited = cliconfigRunCatchingExit(c, []string{"vault", "list-clients"})
		})
	})
	if exited {
		t.Errorf("ADMIN_TOKEN_FILE did not authenticate the command: %q", stderr)
	}
}

// The file may hold the Argon2id hash rather than the plaintext — that is the
// other form InitAdminToken accepts — and it has to authenticate too, otherwise
// the safe path only works for half the deployments that already use it.
func TestRun_AuthenticatesFromAnAdminTokenFileHoldingTheHash(t *testing.T) {
	token := fakeAdminToken(t)
	hash, err := vaultcrypto.HashPassword(token, "")
	if err != nil {
		t.Fatal(err)
	}
	// InitAdminToken stores the hash from the file verbatim, so the file and
	// admin_token_hash hold the same string in a deployment provisioned this way.
	path := filepath.Join(t.TempDir(), "admin-token")
	if err := os.WriteFile(path, []byte(hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADMIN_TOKEN_FILE", path)
	store := newStoringAdminConfig()
	store.values["admin_token_hash"] = hash
	c := New(&mockClientRepo{}, nil, nil, store, nil, "")
	_ = token

	cliconfigStubExit(t)
	var exited bool
	stderr := captureStderr(t, func() {
		captureStdout(t, func() {
			exited = cliconfigRunCatchingExit(c, []string{"vault", "list-clients"})
		})
	})
	if exited {
		t.Errorf("a hash in ADMIN_TOKEN_FILE did not authenticate the command: %q", stderr)
	}
}

// The flag still works, because scripts depend on it, but it says out loud that
// the credential it carried is already disclosed. The process cannot rewrite its
// own argv, so saying so is the only move left.
func TestRun_AdminTokenFlagWarnsThatItIsDisclosed(t *testing.T) {
	token := fakeAdminToken(t)
	hash, err := vaultcrypto.HashPassword(token, "")
	if err != nil {
		t.Fatal(err)
	}
	store := newStoringAdminConfig()
	store.values["admin_token_hash"] = hash
	c := New(&mockClientRepo{}, nil, nil, store, nil, "")

	cliconfigStubExit(t)
	var exited bool
	stderr := captureStderr(t, func() {
		captureStdout(t, func() {
			exited = cliconfigRunCatchingExit(c, []string{"vault", "list-clients", "--admin-token", token})
		})
	})
	if exited {
		t.Fatalf("the flag no longer authenticates: %q", stderr)
	}
	if !strings.Contains(stderr, "/proc/") {
		t.Errorf("no warning that the token is readable from argv: %q", stderr)
	}
	if !strings.Contains(stderr, "ADMIN_TOKEN_FILE") {
		t.Errorf("the warning does not name the safe alternative: %q", stderr)
	}
}

// A stale mount must not lock an operator out of a command they authenticated
// correctly: the file is tried first, the flag is the fallback.
func TestRun_FlagStillWorksWhenTheMountedFileIsStale(t *testing.T) {
	token := fakeAdminToken(t)
	hash, err := vaultcrypto.HashPassword(token, "")
	if err != nil {
		t.Fatal(err)
	}
	c := cliWithProvisionedToken(t, "a-token-that-is-no-longer-in-force", token)
	c.adminConfig.(*storingAdminConfig).values["admin_token_hash"] = hash

	cliconfigStubExit(t)
	var exited bool
	stderr := captureStderr(t, func() {
		captureStdout(t, func() {
			exited = cliconfigRunCatchingExit(c, []string{"vault", "list-clients", "--admin-token", token})
		})
	})
	if exited {
		t.Errorf("a stale ADMIN_TOKEN_FILE blocked a correct --admin-token: %q", stderr)
	}
}

func TestRun_NoCredentialAtAllIsRefused(t *testing.T) {
	codes := cliconfigStubExit(t)
	store := newStoringAdminConfig()
	store.values["admin_token_hash"] = "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aaaa"
	c := New(&mockClientRepo{}, nil, nil, store, nil, "")

	var exited bool
	captureStderr(t, func() {
		exited = cliconfigRunCatchingExit(c, []string{"vault", "list-clients"})
	})
	if !exited {
		t.Fatal("a command with no credential at all was not refused")
	}
	if len(*codes) == 0 || (*codes)[0] != 1 {
		t.Errorf("exit codes = %v, want [1]", *codes)
	}
}

// cliWithProvisionedToken builds a CLI whose ADMIN_TOKEN_FILE holds fileContents
// and whose admin_token_hash is the hash of inForce.
// fakeAdminToken derives a 64-hex-character token from the name of the test
// asking for one.
//
// It is the shape InitAdminToken accepts, it differs per test, and it is
// obviously not a credential. Deriving it also keeps a high-entropy literal
// under the name "token" out of the source, which is the pattern gosec G101
// looks for, without spending a suppression on a value invented on the spot.
func fakeAdminToken(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte("vault42 cli test admin token: " + t.Name()))
	return hex.EncodeToString(sum[:])
}

func cliWithProvisionedToken(t *testing.T, fileContents, inForce string) *CLI {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin-token")
	if err := os.WriteFile(path, []byte(fileContents+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADMIN_TOKEN_FILE", path)

	hash, err := vaultcrypto.HashPassword(inForce, "")
	if err != nil {
		t.Fatal(err)
	}
	store := newStoringAdminConfig()
	store.values["admin_token_hash"] = hash
	return New(&mockClientRepo{}, nil, nil, store, nil, "")
}
