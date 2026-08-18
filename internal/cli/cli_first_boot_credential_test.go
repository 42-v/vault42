package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/firstboot"
)

// InitAdminToken runs from cmd/vault's boot path before the server starts, so
// the token it mints is printed by a long-running process whose stdout and
// stderr both end up in the cluster log store. That token is the sole
// authenticator for every `vault` administrative subcommand, so it must not be
// the thing the aggregator keeps.
func TestInitAdminToken_GeneratedTokenNeverReachesTheProcessOutput(t *testing.T) {
	credFile := filepath.Join(t.TempDir(), "first-boot.env")
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", credFile)

	store := newStoringAdminConfig()
	c := New(nil, nil, nil, store, nil, "")

	out := captureStdout(t, func() {
		if err := c.InitAdminToken(context.Background()); err != nil {
			t.Errorf("InitAdminToken: %v", err)
		}
	})

	stored := store.values["admin_token_hash"]
	if stored == "" {
		t.Fatal("InitAdminToken stored no token hash")
	}

	raw, err := os.ReadFile(credFile) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	_, token, ok := strings.Cut(strings.TrimSpace(string(raw)), "=")
	if !ok || token == "" {
		t.Fatalf("credential file holds no key=value line: %q", raw)
	}
	if valid, _ := vaultcrypto.VerifyPassword(token, stored); !valid {
		t.Fatal("the credential file does not hold the admin token that was installed")
	}
	if strings.Contains(out, token) {
		t.Errorf("the generated admin token was written to the process output:\n%s", out)
	}
}

// Storing the hash of a token the operator was never handed locks the CLI out
// permanently: InitAdminToken returns early once admin_token_hash is set, so
// there is no second chance to learn the value.
func TestInitAdminToken_UndeliverableTokenIsNotInstalled(t *testing.T) {
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", filepath.Join(t.TempDir(), "no-such-dir", "first-boot.env"))

	// The real exit would take this binary with it, which is the point: in a pod
	// the process is gone by the assertions below. Recording the code proves the
	// refusal happened; the assertions then prove what it left behind.
	var exits []int
	defer firstboot.SetExitForTest(func(code int) { exits = append(exits, code) })()

	store := newStoringAdminConfig()
	c := New(nil, nil, nil, store, nil, "")

	var err error
	captureStdout(t, func() { err = c.InitAdminToken(context.Background()) })
	if err == nil {
		t.Fatal("InitAdminToken reported success though the token could not be delivered")
	}
	if len(exits) != 1 || exits[0] != 1 {
		t.Errorf("the process exited %v, want exactly one exit(1). Without it cmd/vault logs "+
			"this error and serves: Ready, healthy, and no admin token in force.", exits)
	}
	if store.values["admin_token_hash"] != "" {
		t.Error("a token hash was installed for a token the operator never received")
	}
}

// storingAdminConfig is an AdminConfigRepository that actually keeps what it is
// given, which is what a first-boot install has to be judged against: the
// package's shared mock answers "" to every Get regardless of what was Set.
type storingAdminConfig struct{ values map[string]string }

func newStoringAdminConfig() *storingAdminConfig {
	return &storingAdminConfig{values: map[string]string{}}
}

func (s *storingAdminConfig) List(context.Context) (map[string]string, error) {
	return s.values, nil
}

func (s *storingAdminConfig) Get(_ context.Context, key string) (string, error) {
	return s.values[key], nil
}

func (s *storingAdminConfig) Set(_ context.Context, key, value string) error {
	s.values[key] = value
	return nil
}

func (s *storingAdminConfig) Delete(_ context.Context, key string) error {
	delete(s.values, key)
	return nil
}

// firstBootSink points this test's process at a private credential file, which
// is what every InitAdminToken test needs now that a token that cannot be
// delivered is not installed.
func firstBootSink(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "first-boot.env")
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", path)
	return path
}
