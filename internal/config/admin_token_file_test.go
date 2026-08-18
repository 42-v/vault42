package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ADMIN_TOKEN_FILE names the credential the admin CLI will accept. It used to be
// read into a config field that nothing consulted, so every way of getting it
// wrong (absent mount, empty file, a truncated hash) started a server that
// looked healthy and then rejected the operator's token. These tests keep every
// one of those a startup failure.

func writeAdminTokenFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin-token")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write admin token file: %v", err)
	}
	return path
}

// loadAndValidate runs the startup sequence cmd/vault runs, which is the only
// place the refusal has to hold: either step returning an error stops the boot.
func loadAndValidate(t *testing.T) error {
	t.Helper()
	cfg, err := Load()
	if err != nil {
		return err
	}
	return cfg.Validate()
}

// mustRejectAdminTokenFile fails unless startup refuses and says why in terms
// of ADMIN_TOKEN_FILE. Both halves matter: a production profile fails for its
// own reasons (no HMAC key, no origin), so "returned some error" would pass
// against a build that never looks at the file at all, and an operator reading
// "HMAC_SECRET_FILE required" learns nothing about the mount they got wrong.
func mustRejectAdminTokenFile(t *testing.T, what string) {
	t.Helper()
	err := loadAndValidate(t)
	if err == nil {
		t.Fatalf("startup accepted %s", what)
	}
	if !strings.Contains(err.Error(), "ADMIN_TOKEN_FILE") {
		t.Fatalf("startup refused %s but not because of the admin token: %v", what, err)
	}
}

func TestLoadRejectsUnreadableAdminTokenFile(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "production")
	t.Setenv("ADMIN_TOKEN_FILE", filepath.Join(t.TempDir(), "absent"))

	mustRejectAdminTokenFile(t, "an ADMIN_TOKEN_FILE that cannot be read")
}

func TestLoadRejectsEmptyAdminTokenFile(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "production")
	t.Setenv("ADMIN_TOKEN_FILE", writeAdminTokenFile(t, "\n"))

	mustRejectAdminTokenFile(t, "an empty ADMIN_TOKEN_FILE")
}

func TestLoadRejectsMalformedAdminTokenHash(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "production")
	// A truncated PHC string: it announces itself as an Argon2id hash and can
	// never verify anything, so the CLI would be locked out with no clue why.
	t.Setenv("ADMIN_TOKEN_FILE", writeAdminTokenFile(t, "$argon2id$v=19$m=47104,t=1,p=1"))

	mustRejectAdminTokenFile(t, "a truncated Argon2id hash in ADMIN_TOKEN_FILE")
}

func TestLoadRejectsShortAdminTokenOutsideDev(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "production")
	t.Setenv("ADMIN_TOKEN_FILE", writeAdminTokenFile(t, "hunter2\n"))

	mustRejectAdminTokenFile(t, "a guessable admin token in a production profile")
}

func TestLoadAcceptsProvisionedAdminToken(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "production")
	t.Setenv("ADMIN_TOKEN_FILE", writeAdminTokenFile(t,
		"$argon2id$v=19$m=47104,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"))

	// Matched on the message rather than on err being nil: a production profile
	// with no HMAC key and no origin fails for its own reasons, and those are
	// not what this test is about.
	if err := loadAndValidate(t); err != nil && strings.Contains(err.Error(), "ADMIN_TOKEN") {
		t.Fatalf("startup rejected a well-formed Argon2id hash: %v", err)
	}

	t.Setenv("ADMIN_TOKEN_FILE", writeAdminTokenFile(t,
		"3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1\n"))

	if err := loadAndValidate(t); err != nil && strings.Contains(err.Error(), "ADMIN_TOKEN") {
		t.Fatalf("startup rejected the plaintext token scripts/generate-secrets.sh writes: %v", err)
	}
}

// TestLoadLeavesAdminTokenFileForTheCLI pins the division of labor. Config only
// inspects the file; internal/cli performs the real (and, under
// VAULT_SECRET_FILE_CONSUME, destructive) read. A consuming read here would
// delete the file before its only consumer ever saw it.
func TestLoadLeavesAdminTokenFileForTheCLI(t *testing.T) {
	path := writeAdminTokenFile(t, "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1\n")
	t.Setenv("VAULT_PROFILE", "production")
	t.Setenv("ADMIN_TOKEN_FILE", path)
	t.Setenv("VAULT_SECRET_FILE_CONSUME", "true")

	if err := loadAndValidate(t); err != nil && strings.Contains(err.Error(), "ADMIN_TOKEN") {
		t.Fatalf("startup rejected a well-formed admin token: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config consumed ADMIN_TOKEN_FILE before internal/cli could read it: %v", err)
	}
}

// TestDevProfileWarnsAboutAShortAdminTokenInsteadOfRefusing pins the one profile
// where a guessable admin token is not a boot failure. Dev has to stay usable
// with a token someone typed, but the admin CLI can add clients and revoke every
// session and nothing rate limits it, so the leniency must be loud: a silent
// accept is how a short token reaches a deployment that is only nominally dev.
func TestDevProfileWarnsAboutAShortAdminTokenInsteadOfRefusing(t *testing.T) {
	const token = "hunter2"
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("ADMIN_TOKEN_FILE", writeAdminTokenFile(t, token+"\n"))

	var err error
	logged := cliconfigCaptureLog(t, func() { err = loadAndValidate(t) })

	if err != nil {
		t.Fatalf("the dev profile refused to start on a short admin token: %v", err)
	}
	if !strings.Contains(logged, "SECURITY WARNING") {
		t.Errorf("a short admin token was accepted without a warning; log was:\n%s", logged)
	}
	if !strings.Contains(logged, "ADMIN_TOKEN_FILE") {
		t.Errorf("the warning does not name the setting it is about; log was:\n%s", logged)
	}
	if strings.Contains(logged, token) {
		t.Error("the admin token itself was written to the log, which under systemd is the journal")
	}
}

// TestLoadRejectsAnArgon2idHashWithAnEmptySegment covers the truncation that a
// segment count alone cannot catch. A PHC string cut at a "$" boundary, or
// written by a shell pipeline that dropped a field, still has six segments and
// still announces itself as Argon2id, but it carries no salt or no digest and
// therefore verifies against nothing. Accepting it would start a server whose
// admin CLI can never be authenticated, with the mounted file looking correct.
func TestLoadRejectsAnArgon2idHashWithAnEmptySegment(t *testing.T) {
	const prefix = "$argon2id$v=19$m=47104,t=1,p=1"
	const salt = "c2FsdHNhbHRzYWx0c2FsdA"
	const digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	cases := []struct {
		name     string
		contents string
	}{
		{"digest cut off after the final separator", prefix + "$" + salt + "$"},
		{"salt field empty", prefix + "$$" + digest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VAULT_PROFILE", "production")
			t.Setenv("ADMIN_TOKEN_FILE", writeAdminTokenFile(t, tc.contents+"\n"))

			mustRejectAdminTokenFile(t, "an Argon2id hash with an empty segment in ADMIN_TOKEN_FILE")
		})
	}
}

// The second boot of a deployment that consumes its secret files.
//
// internal/cli reads ADMIN_TOKEN_FILE for real, and under
// VAULT_SECRET_FILE_CONSUME that read zeroes and removes the file. This check
// re-reads the same path on every boot and treated its absence as a broken
// mount, so boot 1 destroyed the file and boot 2 refused to start:
//
//	boot 1 removed .../admin-token
//	boot 2: read ADMIN_TOKEN_FILE "...": no such file or directory
//
// The chart is not affected -- its secrets volume is readOnly and it never sets
// the flag -- so this is compose, systemd and bare metal with a writable
// keyfile. The token itself is not lost: its hash went into auth.admin_config on
// boot 1 and is what authenticates from then on.
//
// An absent file is only forgivable under the flag. Without it, nothing in this
// process removes the file, so absence still means the mount is broken and that
// is still a startup failure.
func TestConsumedAdminTokenFileDoesNotBlockTheNextBoot(t *testing.T) {
	path := writeAdminTokenFile(t, "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1\n")
	t.Setenv("VAULT_PROFILE", "production")
	t.Setenv("ADMIN_TOKEN_FILE", path)
	t.Setenv("VAULT_SECRET_FILE_CONSUME", "true")

	// What internal/cli does to it on the first boot.
	if _, err := LoadSecret("ADMIN_TOKEN"); err != nil {
		t.Fatalf("first boot could not read the admin token: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the consuming read did not remove the file, so this test is not describing "+
			"the second boot at all (stat err = %v)", err)
	}

	if err := loadAndValidate(t); err != nil && strings.Contains(err.Error(), "ADMIN_TOKEN") {
		t.Fatalf("the second boot refused to start over a file the first boot was told to "+
			"destroy: %v", err)
	}
}

// The other direction, which has to keep failing: without the consume flag
// nothing in this process removes the file, so an absent one is a mount that
// never arrived, and a server that starts anyway rejects the operator's token
// with "Admin authentication required."
func TestAbsentAdminTokenFileWithoutConsumeIsStillFatal(t *testing.T) {
	path := writeAdminTokenFile(t, "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1\n")
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	t.Setenv("VAULT_PROFILE", "production")
	t.Setenv("ADMIN_TOKEN_FILE", path)

	err := loadAndValidate(t)
	if err == nil || !strings.Contains(err.Error(), "ADMIN_TOKEN_FILE") {
		t.Fatalf("an absent ADMIN_TOKEN_FILE was accepted: %v", err)
	}
}
