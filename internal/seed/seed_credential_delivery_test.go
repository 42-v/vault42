package seed

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// Seeding is reached from the server boot path (cmd/vault runs it whenever
// VAULT_SEED_FILE is set), not only from an interactive `vault seed`. A client
// secret printed there lands in the same durable log store as everything else
// the pod writes, and a client secret is a bearer credential for the whole
// client role. It has to be handed over somewhere the aggregator does not read.
func TestSeedClient_SecretNeverReachesTheProcessOutput(t *testing.T) {
	credFile := filepath.Join(t.TempDir(), "first-boot.env")
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", credFile)

	clients := newMockClientRepo()
	sf := &SeedFile{Clients: []ClientSeed{{Name: "web", Role: "frontend", Scopes: []string{"user:read"}}}}

	out := captureProcessOutput(t, func() {
		if err := Run(context.Background(), sf, Deps{Clients: clients}, ""); err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	if len(clients.created) != 1 {
		t.Fatalf("expected 1 client created, got %d", len(clients.created))
	}

	raw, err := os.ReadFile(credFile) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	_, secret, ok := strings.Cut(strings.TrimSpace(string(raw)), "=")
	if !ok || secret == "" {
		t.Fatalf("credential file holds no key=value line: %q", raw)
	}
	if valid, _ := vaultcrypto.VerifyPassword(secret, clients.created[0].SecretHash); !valid {
		t.Fatal("the credential file does not hold the secret of the client that was created")
	}
	if strings.Contains(out, secret) {
		t.Errorf("the seeded client secret was written to the process output:\n%s", out)
	}
}

// A client whose secret went nowhere is a row nobody can authenticate as: the
// plaintext exists for one instant and is stored only as an Argon2id hash. If
// the secret cannot be delivered, the client must not be created.
func TestSeedClient_UndeliverableSecretCreatesNoClient(t *testing.T) {
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", filepath.Join(t.TempDir(), "no-such-dir", "first-boot.env"))

	clients := newMockClientRepo()
	sf := &SeedFile{Clients: []ClientSeed{{Name: "web", Role: "frontend", Scopes: []string{"user:read"}}}}

	var err error
	captureProcessOutput(t, func() {
		err = Run(context.Background(), sf, Deps{Clients: clients}, "")
	})
	if err == nil {
		t.Fatal("Run reported success though the client secret could not be delivered")
	}
	if len(clients.created) != 0 {
		t.Errorf("a client was created whose secret went nowhere: %d rows", len(clients.created))
	}
}

// captureProcessOutput collects everything fn writes to stdout.
func captureProcessOutput(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	_ = w.Close()
	os.Stdout = old
	return <-done
}

// firstBootSink points this test's process at a private credential file, which
// is what every client-seeding test needs now that a secret that cannot be
// delivered abandons the client.
func firstBootSink(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "first-boot.env")
	t.Setenv("VAULT_FIRST_BOOT_CREDENTIAL_FILE", path)
	return path
}
