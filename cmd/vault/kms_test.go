package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/42-v/vault42/internal/kms"
)

// TestKMSWrap_RoundTripWithUnwrap drives the real `vault kms wrap` code path
// (flag parse → config.LoadSecret(KMS_ROOT_KEY_FILE) → Service.Wrap → base64) and
// asserts the emitted envelope round-trips through Service.Unwrap back to the
// byte-identical plaintext. Root and kid are ephemeral, never a real KMS root.
func TestKMSWrap_RoundTripWithUnwrap(t *testing.T) {
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatalf("rand: %v", err)
	}
	const kid = "life42-root-kek-test"
	plaintext := []byte("this-is-a-32-byte-life42-datroot") // exactly 32 bytes

	// Point the wrap command at the ephemeral root via the same _FILE convention
	// the server uses to load KMS_ROOT_KEY.
	rootFile := filepath.Join(t.TempDir(), "kms_root.key")
	if err := os.WriteFile(rootFile, root, 0o600); err != nil {
		t.Fatalf("write root: %v", err)
	}
	t.Setenv("KMS_ROOT_KEY_FILE", rootFile)

	var out bytes.Buffer
	if err := runKMSWrap([]string{"--kid", kid, "--in", "-", "--out", "-"}, bytes.NewReader(plaintext), &out); err != nil {
		t.Fatalf("runKMSWrap: %v", err)
	}

	envelope, err := base64.StdEncoding.DecodeString(out.String())
	if err != nil {
		t.Fatalf("emitted envelope is not valid base64: %v", err)
	}

	svc, err := kms.New(root)
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	defer svc.Close()

	got, err := svc.Unwrap(kid, envelope)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, plaintext)
	}
	if bytes.Contains(envelope, plaintext) {
		t.Fatal("envelope leaks plaintext")
	}
}
