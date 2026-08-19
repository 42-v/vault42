package main

// The admin CLI seam.
//
// main() hands os.Args to the CLI handler between provisioning the admin token
// and starting the retention sweepers, and branches on a single bool: handled
// means return, unhandled means become a server. Everything an operator sees
// from `vault <subcommand>` is decided by that seam, and the two failure shapes
// it can produce are indistinguishable from the outside without checking the
// exit status, so that is what these tests check.
//
// The admin commands themselves are covered by internal/cli. What is covered
// here is what only this package decides: which invocations get authenticated,
// which ones end the process, and which ones fall through and bring up a server.

import (
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// adminToken is the plaintext the CLI tests authenticate with. It is hashed once
// per test binary because Argon2id at the configured parameters costs 46 MiB and
// a couple of hundred milliseconds a call.
const adminToken = "test-admin-token-not-a-real-credential"

var adminTokenHash = sync.OnceValue(func() string {
	hash, err := vaultcrypto.HashPassword(adminToken)
	if err != nil {
		panic("hash the fixture admin token: " + err.Error())
	}
	return hash
})

// authenticatedStub is a database that recognizes adminToken.
func authenticatedStub(t *testing.T) *pgStub {
	t.Helper()
	return startPGStub(t, adminTokenRule(adminTokenHash()))
}

// TestAdminCommandsRequireAuthentication pins the gate in front of every admin
// subcommand. The CLI verifies the token before it looks at which command was
// asked for, so a wrong or absent token must fail identically for a read-only
// command and for a destructive one. Anything less than a non-zero exit here
// would let a deployment script treat a rejected `vault revoke-client` as done.
func TestAdminCommandsRequireAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "no token at all", args: []string{"list-clients"}},
		{name: "empty token", args: []string{"list-clients", "--admin-token", ""}},
		{name: "wrong token", args: []string{"list-clients", "--admin-token", "not-the-token"}},
		{name: "destructive command with no token", args: []string{"revoke-all-sessions"}},
		{name: "flag with no value", args: []string{"list-clients", "--admin-token"}},
		{name: "unrecognized subcommand", args: []string{"definitely-not-a-command"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := authenticatedStub(t)
			addr := freeAddr(t)

			res := runVault(t, vaultRun{args: tc.args, env: bootEnv(t, stub, addr)})

			requireExit(t, res, 1, "ERROR: Admin authentication required.")
			if dialable(addr) {
				t.Fatal("an unauthenticated CLI invocation started the server")
			}
			requireNoSecretLeak(t, res, adminToken, adminTokenHash())
		})
	}
}

// TestAuthenticatedCommandReturnsBeforeTheServerStarts pins the handled branch.
// A recognized subcommand must end the process with a zero status and must not
// bring up an HTTP listener on the way out: `vault list-clients` run on a host
// that already has a vault42 replica would otherwise fight it for the port.
func TestAuthenticatedCommandReturnsBeforeTheServerStarts(t *testing.T) {
	stub := authenticatedStub(t)
	addr := freeAddr(t)

	res := runVault(t, vaultRun{
		args: []string{"list-clients", "--admin-token", adminToken},
		env:  bootEnv(t, stub, addr),
	})

	if res.code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	if strings.Contains(res.stderr, "The Vault listening on") {
		t.Fatalf("a handled CLI command started the server anyway\nstderr:\n%s", res.stderr)
	}
	if dialable(addr) {
		t.Fatal("a handled CLI command left an HTTP listener behind")
	}
	if !stub.sawQuery("FROM auth.clients") {
		t.Fatalf("list-clients never queried the client table; queries seen: %v", stub.queries())
	}
	requireNoSecretLeak(t, res, adminToken, adminTokenHash())
}

// TestCLIDoesNotApplySeedFile pins where VAULT_SEED_FILE is applied.
//
// Seeding used to run before the CLI check, so `vault list-clients` created
// the declared clients and users as a side effect, and a broken seed file
// killed an unrelated admin command with log.Fatalf. The retention sweepers
// were already started after the CLI check for the same reason; seeding has
// to sit with them.
func TestCLIDoesNotApplySeedFile(t *testing.T) {
	t.Run("broken seed file does not kill list-clients", func(t *testing.T) {
		stub := authenticatedStub(t)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		env["VAULT_SEED_FILE"] = filepath.Join(t.TempDir(), "absent.json")

		res := runVault(t, vaultRun{
			args: []string{"list-clients", "--admin-token", adminToken},
			env:  env,
		})

		if res.code != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
		}
		if strings.Contains(res.stderr, "Failed to load seed file") {
			t.Fatalf("a broken seed file killed an unrelated admin command\nstderr:\n%s", res.stderr)
		}
		if strings.Contains(res.stderr, "The Vault listening on") {
			t.Fatalf("list-clients started the server\nstderr:\n%s", res.stderr)
		}
		if !stub.sawQuery("FROM auth.clients") {
			t.Fatalf("list-clients never queried the client table; queries seen: %v", stub.queries())
		}
	})

	t.Run("malformed seed file does not kill list-clients", func(t *testing.T) {
		stub := authenticatedStub(t)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		env["VAULT_SEED_FILE"] = secretFile(t, t.TempDir(), "seed.json", `{`)

		res := runVault(t, vaultRun{
			args: []string{"list-clients", "--admin-token", adminToken},
			env:  env,
		})

		if res.code != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
		}
		if strings.Contains(res.stderr, "Failed to load seed file") {
			t.Fatalf("a malformed seed file killed an unrelated admin command\nstderr:\n%s", res.stderr)
		}
	})

	t.Run("list-clients does not create declared clients", func(t *testing.T) {
		stub := authenticatedStub(t)
		addr := freeAddr(t)
		env := bootEnv(t, stub, addr)
		env["VAULT_SEED_FILE"] = secretFile(t, t.TempDir(), "seed.json",
			`{"clients":[{"name":"seeded-side-effect","role":"service","scopes":["read"]}]}`)

		res := runVault(t, vaultRun{
			args: []string{"list-clients", "--admin-token", adminToken},
			env:  env,
		})

		if res.code != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
		}
		if stub.sawQuery("WHERE name") {
			t.Fatalf("list-clients applied VAULT_SEED_FILE as a side effect; queries seen: %v", stub.queries())
		}
		if stub.sawQuery("INSERT INTO auth.clients") {
			t.Fatalf("list-clients inserted a seeded client; queries seen: %v", stub.queries())
		}
		if !stub.sawQuery("ORDER BY name") {
			t.Fatalf("list-clients never listed clients; queries seen: %v", stub.queries())
		}
	})
}

// TestAuthenticatedCommandWithMissingArgumentsPrintsUsage covers the argument
// handling one level down. A subcommand missing a required flag is still
// "handled": it prints its usage and the process returns zero. That is the
// deliberate shape, and it is worth pinning because the alternative reading of
// the same code, treating an incomplete command as unhandled, would silently
// start a server instead of telling the operator what they typed wrong.
func TestAuthenticatedCommandWithMissingArgumentsPrintsUsage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		usage string
	}{
		{
			name:  "add-client without a name",
			args:  []string{"add-client", "--role", "service"},
			usage: "Usage: vault add-client --admin-token <token> --name <name> --role <role> --scopes <scopes>",
		},
		{
			name:  "seed without a file",
			args:  []string{"seed"},
			usage: "Usage: vault seed --admin-token <token> --file <path>",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := authenticatedStub(t)
			addr := freeAddr(t)

			res := runVault(t, vaultRun{
				args: append(tc.args, "--admin-token", adminToken),
				env:  bootEnv(t, stub, addr),
			})

			if res.code != 0 {
				t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, tc.usage) {
				t.Fatalf("stderr does not show the usage line\nwant: %s\nstderr:\n%s", tc.usage, res.stderr)
			}
			if dialable(addr) {
				t.Fatal("an incomplete CLI command started the server")
			}
		})
	}
}

// TestUnknownAuthenticatedSubcommandFallsThroughToTheServer pins the other side
// of the seam. With a valid token, a subcommand the CLI does not recognize is
// reported as unhandled and main() carries on into server startup. That is how
// the binary can be launched with arguments it does not own, and it is the only
// path in main() where the CLI check returns false with a non-empty argv.
func TestUnknownAuthenticatedSubcommandFallsThroughToTheServer(t *testing.T) {
	stub := authenticatedStub(t)
	addr := freeAddr(t)

	res := bootAndShutdown(t, vaultRun{
		args: []string{"not-a-vault-subcommand", "--admin-token", adminToken},
		env:  bootEnv(t, stub, addr),
	}, addr, syscall.SIGTERM, nil)

	requireExit(t, res, 0, "The Vault listening on "+addr)
	requireNoSecretLeak(t, res, adminToken, adminTokenHash())
}
