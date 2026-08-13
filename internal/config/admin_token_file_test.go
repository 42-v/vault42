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
