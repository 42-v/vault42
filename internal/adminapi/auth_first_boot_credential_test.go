package adminapi

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// EnsureFirstAdmin mints the one credential that owns the admin plane, and it
// runs unattended at gateway boot. Anything it prints through the log package
// goes to stderr, and in every deployment this repo targets stderr is scraped
// into a durable aggregator whose readers are a far wider set than the database
// the credential protects — and the record outlives the credential's own
// rotation. So the password has to reach the operator by a channel that is not
// the process log.
func TestEnsureFirstAdmin_PasswordNeverReachesTheLog(t *testing.T) {
	credFile := filepath.Join(t.TempDir(), "first-boot.env")
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", credFile)

	logged := captureLog(t)

	repo := newFakeAdminRepo()
	if err := EnsureFirstAdmin(context.Background(), repo, newStoringAdminConfig(), ""); err != nil {
		t.Fatalf("EnsureFirstAdmin: %v", err)
	}

	var created string
	for _, a := range repo.users {
		created = a.PasswordHash
	}
	if created == "" {
		t.Fatal("EnsureFirstAdmin created no admin")
	}

	raw, err := os.ReadFile(credFile) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	password := credentialValue(t, string(raw))
	if ok, _ := vaultcrypto.VerifyPassword(password, created); !ok {
		t.Fatalf("the credential file does not hold the password of the admin that was created")
	}

	if strings.Contains(logged.String(), password) {
		t.Errorf("the first-boot super_admin password was written to the process log:\n%s", logged.String())
	}
}

// The one thing worse than logging the credential is creating the account and
// then failing to hand its password over: auth.admin_users is non-empty from
// then on, so the next boot will not mint another, and the deployment owns an
// admin nobody can log in as. Delivery therefore has to happen before the row
// does.
func TestEnsureFirstAdmin_UndeliverableCredentialCreatesNoAdmin(t *testing.T) {
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", filepath.Join(t.TempDir(), "no-such-dir", "first-boot.env"))

	logged := captureLog(t)

	repo := newFakeAdminRepo()
	err := EnsureFirstAdmin(context.Background(), repo, newStoringAdminConfig(), "")
	if err == nil {
		t.Fatal("EnsureFirstAdmin reported success though the credential could not be delivered")
	}
	if len(repo.users) != 0 {
		t.Errorf("an admin was created whose password went nowhere: %d rows", len(repo.users))
	}
	_ = logged
}

// captureLog redirects the standard logger for the duration of one test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return &buf
}

// credentialValue pulls the value out of the single key=value line the
// credential file is expected to hold.
func credentialValue(t *testing.T, contents string) string {
	t.Helper()
	line := strings.TrimSpace(contents)
	_, value, ok := strings.Cut(line, "=")
	if !ok || value == "" {
		t.Fatalf("credential file holds no key=value line: %q", contents)
	}
	return value
}

// firstBootSink points this test's process at a private credential file, which
// is what every EnsureFirstAdmin test needs now that a credential that cannot be
// delivered abandons the bootstrap.
func firstBootSink(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "first-boot.env")
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", path)
	return path
}
