package main

// Argument dispatch and error redaction at the top of main().
//
// Everything in this file is about the part of the binary that runs before any
// database, configuration, or server exists. Two of those paths are load-bearing
// for deployment: `vault --version` is what an image healthcheck and a release
// pipeline call, and `vault kms wrap` is what life42 deploy tooling calls to
// produce the wrapped-root artifact. Both must work on a host with no database,
// no secrets, and no configuration at all, and a regression that made either one
// require a Config would only show up in production.

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestVersionFlagNeedsNothingButTheBinary pins the --version contract: the exact
// output shape, a zero exit status, and above all that it is answered before
// config.Load runs. The child here is given an environment with no VAULT_*
// variables and a database it could not reach if it tried, which is the state a
// container healthcheck or a `docker run image --version` smoke test runs in.
func TestVersionFlagNeedsNothingButTheBinary(t *testing.T) {
	stub := startPGStub(t)

	res := runVault(t, vaultRun{args: []string{"--version"}})

	if res.code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	want := fmt.Sprintf("vault %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
	if res.stdout != want {
		t.Fatalf("stdout = %q, want %q", res.stdout, want)
	}
	if res.stderr != "" {
		t.Fatalf("--version wrote to stderr: %q", res.stderr)
	}
	if got := stub.queries(); len(got) != 0 {
		t.Fatalf("--version talked to the database: %v", got)
	}
}

// TestVersionFlagOnlyMatchesTheFirstArgument keeps --version from swallowing an
// invocation that merely mentions it. The check reads os.Args[1] and nothing
// else, and the CLI below it treats an unrecognized argument as an
// authentication-required subcommand, so `vault list-clients --version` must be
// rejected as an unauthenticated admin command rather than answered as a version
// query.
func TestVersionFlagOnlyMatchesTheFirstArgument(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)

	res := runVault(t, vaultRun{args: []string{"list-clients", "--version"}, env: env})

	if strings.Contains(res.stdout, "vault "+Version) {
		t.Fatalf("--version was honored in a non-leading position\nstdout:\n%s", res.stdout)
	}
	requireExit(t, res, 1, "ERROR: Admin authentication required.")
}

// TestKMSSubcommandIsHandledBeforeAnyWiring pins the other early-exit path.
// `vault kms wrap` derives its KEK from the KMS root keyfile alone, and it is
// intercepted before the database and server are wired precisely so that deploy
// tooling can produce an envelope on a machine that has the root key and nothing
// else.
func TestKMSSubcommandIsHandledBeforeAnyWiring(t *testing.T) {
	stub := startPGStub(t)
	root := strings.Repeat("k", 32)

	res := runVault(t, vaultRun{
		args:  []string{"kms", "wrap", "--kid", "life42-root"},
		env:   map[string]string{"KMS_ROOT_KEY_FILE": secretFile(t, t.TempDir(), "kms.key", root)},
		stdin: "a-data-key-to-be-wrapped",
	})

	if res.code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	if res.stdout == "" {
		t.Fatal("kms wrap produced no envelope")
	}
	if got := stub.queries(); len(got) != 0 {
		t.Fatalf("kms wrap talked to the database: %v", got)
	}
	requireNoSecretLeak(t, res, root, "a-data-key-to-be-wrapped")
}

// TestKMSSubcommandFailureExitsNonZero pins the error contract of the kms group
// as main() presents it: the message is prefixed so an operator can tell a wrap
// failure from a startup failure, and the exit status is non-zero so a deploy
// script that pipes the envelope into a secret store does not store an empty
// file and carry on.
func TestKMSSubcommandFailureExitsNonZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{
			name: "no subcommand",
			args: []string{"kms"},
			want: "vault kms: usage: vault kms wrap --kid <kid> [--in <file|->] [--out <file|->]",
		},
		{
			name: "unknown subcommand",
			args: []string{"kms", "unwrap"},
			want: `vault kms: unknown kms subcommand "unwrap" (want: wrap)`,
		},
		{
			name: "missing kid",
			args: []string{"kms", "wrap"},
			env:  map[string]string{"KMS_ROOT_KEY_FILE": "fixture"},
			want: "vault kms: --kid is required",
		},
		{
			name: "no root key configured",
			args: []string{"kms", "wrap", "--kid", "life42-root"},
			want: "vault kms: load KMS root: KMS_ROOT_KEY_FILE not set",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			for k, v := range tc.env {
				if v == "fixture" {
					v = secretFile(t, t.TempDir(), "kms.key", strings.Repeat("k", 32))
				}
				env[k] = v
			}

			res := runVault(t, vaultRun{args: tc.args, env: env})
			requireExit(t, res, 1, tc.want)
			if res.stdout != "" {
				t.Fatalf("a failed wrap still wrote to stdout: %q", res.stdout)
			}
		})
	}
}

// TestSanitizeDBError is the unit half of the redaction contract that
// TestDatabaseConnectFailureIsFatalAndRedacted asserts end to end. pgx puts the
// connection string into its dial errors and the connection string carries the
// vault_app password, so this runs on the path to every fatal database log line
// in main().
func TestSanitizeDBError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      error
		want    string
		unwant  string
		wantNil bool
	}{
		{
			name:    "nil stays nil",
			in:      nil,
			wantNil: true,
		},
		{
			name:   "credentials in a connection url are replaced",
			in:     errors.New(`failed to connect to postgres://vault_app:hunter2@db.internal:5432/vault: timeout`),
			want:   "failed to connect to postgres://***:***@db.internal:5432/vault: timeout",
			unwant: "hunter2",
		},
		{
			name:   "every url in the message is redacted",
			in:     fmt.Errorf("primary postgres://a:p1@h1/db failed, replica postgres://b:p2@h2/db failed"),
			want:   "primary postgres://***:***@h1/db failed, replica postgres://***:***@h2/db failed",
			unwant: "p2",
		},
		{
			name: "a message with no url is passed through unchanged",
			in:   errors.New("dial tcp 127.0.0.1:5432: connect: connection refused"),
			want: "dial tcp 127.0.0.1:5432: connect: connection refused",
		},
		{
			name:   "percent encoded credentials are redacted too",
			in:     errors.New(`cannot parse postgres://vault_app:p%40ss%20word@db:5432/vault`),
			want:   "cannot parse postgres://***:***@db:5432/vault",
			unwant: "p%40ss%20word",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeDBError(tc.in)

			if tc.wantNil {
				if got != nil {
					t.Fatalf("sanitizeDBError(nil) = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("sanitizeDBError returned nil for a non-nil error")
			}
			if got.Error() != tc.want {
				t.Fatalf("sanitizeDBError = %q, want %q", got.Error(), tc.want)
			}
			if tc.unwant != "" && strings.Contains(got.Error(), tc.unwant) {
				t.Fatalf("sanitized error still contains %q: %s", tc.unwant, got.Error())
			}
		})
	}
}

// TestSanitizeDBErrorDoesNotDependOnTheErrorChain records a limitation rather
// than a feature. sanitizeDBError rebuilds the message with fmt.Errorf("%s"),
// which deliberately drops the wrapped error: keeping it would keep a
// %w-formatted copy of the original, unredacted text reachable through
// errors.Unwrap and defeat the redaction for any caller that logged the cause.
func TestSanitizeDBErrorDoesNotDependOnTheErrorChain(t *testing.T) {
	cause := errors.New("postgres://vault_app:hunter2@db:5432/vault is unreachable")
	got := sanitizeDBError(fmt.Errorf("connect: %w", cause))

	if errors.Is(got, cause) {
		t.Fatal("the unredacted cause is still reachable through the error chain")
	}
	if strings.Contains(got.Error(), "hunter2") {
		t.Fatalf("password survived sanitization: %s", got.Error())
	}
}
