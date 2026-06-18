package config

import (
	"os"
	"path/filepath"
	"testing"
)

// L5: by default LoadSecret must NOT destroy the secret file (read-only mount is
// the canonical deployment; destroying a writable keyfile on first read was the bug).
func TestLoadSecret_DefaultDoesNotConsumeFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret")
	if err := os.WriteFile(f, []byte("keep-me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEEP_KEY_FILE", f)
	// VAULT_SECRET_FILE_CONSUME deliberately unset.

	val, err := LoadSecret("KEEP_KEY")
	if err != nil || val != "keep-me" {
		t.Fatalf("LoadSecret = %q, %v", val, err)
	}
	if _, err := os.Stat(f); err != nil {
		t.Fatalf("secret file must survive by default, stat err: %v", err)
	}
}
