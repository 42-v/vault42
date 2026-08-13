package config

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// writeSecretFile puts content at a temp path and points NAME_FILE at it.
func writeSecretFile(t *testing.T, envKey string, content []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	t.Setenv(envKey+"_FILE", path)
}

// TestLoadSecretBinaryKeepsWhitespaceBytes is the regression that matters.
//
// scripts/generate-secrets.sh writes the master key as 32 raw bytes from
// `openssl rand 32`. Six of the 256 byte values are ASCII whitespace, so a key
// beginning or ending in one of them is a normal, correct key that occurs about
// once every twenty-two generations. LoadSecret's TrimSpace ate that byte, the
// length check then rejected the 31 bytes that remained, and the process died
// with "MASTER_KEY_FILE is required (32 bytes for AES-256)". An operator reading
// that message checks their mount, not their key, because the key is fine.
//
// Each whitespace byte is exercised at both ends rather than once in the middle,
// since only the ends are what a trim touches.
func TestLoadSecretBinaryKeepsWhitespaceBytes(t *testing.T) {
	for _, ws := range []byte{' ', '\t', '\n', '\v', '\f', '\r'} {
		for _, at := range []string{"first", "last"} {
			t.Run(string(rune(ws))+"-"+at, func(t *testing.T) {
				key := make([]byte, 32)
				if _, err := rand.Read(key); err != nil {
					t.Fatalf("generate key: %v", err)
				}
				if at == "first" {
					key[0] = ws
				} else {
					key[31] = ws
				}

				writeSecretFile(t, "MASTER_KEY", key)
				got, err := LoadSecretBinary("MASTER_KEY", 32)
				if err != nil {
					t.Fatalf("a valid 32-byte key was rejected: %v", err)
				}
				if !bytes.Equal(got, key) {
					t.Errorf("key came back altered:\n got %x\nwant %x", got, key)
				}
			})
		}
	}
}

// TestLoadSecretBinaryToleratesOneTrailingNewline covers the operator who
// writes a key by hand or with a shell redirect that appends a line ending.
// Their key is not wrong, so it is accepted, but exactly one line ending is
// stripped and only when doing so yields the expected length.
func TestLoadSecretBinaryToleratesOneTrailingNewline(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	for name, suffix := range map[string][]byte{"lf": {'\n'}, "crlf": {'\r', '\n'}} {
		t.Run(name, func(t *testing.T) {
			writeSecretFile(t, "MASTER_KEY", append(append([]byte{}, key...), suffix...))
			got, err := LoadSecretBinary("MASTER_KEY", 32)
			if err != nil {
				t.Fatalf("a 32-byte key with a trailing %s was rejected: %v", name, err)
			}
			if !bytes.Equal(got, key) {
				t.Errorf("key came back altered:\n got %x\nwant %x", got, key)
			}
		})
	}
}

// TestLoadSecretBinaryDoesNotTruncateAKeyEndingInNewline is the other half of
// the newline tolerance, and the reason it is length-conditional rather than a
// blanket TrimRight. A raw key whose 32nd byte is 0x0A is a correct key. Only a
// file of length wantLen+1 is treated as having a line ending, so this one is
// returned whole.
func TestLoadSecretBinaryDoesNotTruncateAKeyEndingInNewline(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key[31] = '\n'

	writeSecretFile(t, "MASTER_KEY", key)
	got, err := LoadSecretBinary("MASTER_KEY", 32)
	if err != nil {
		t.Fatalf("a valid key ending in 0x0A was rejected: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Errorf("key ending in 0x0A was altered:\n got %x\nwant %x", got, key)
	}
}

// TestLoadSecretBinaryRejectsWrongLength keeps the length check honest, and
// makes the message say what was actually found rather than implying the file
// is missing.
func TestLoadSecretBinaryRejectsWrongLength(t *testing.T) {
	for name, content := range map[string][]byte{
		"too short": make([]byte, 31),
		"too long":  make([]byte, 40),
		"empty":     {},
	} {
		t.Run(name, func(t *testing.T) {
			writeSecretFile(t, "MASTER_KEY", content)
			if _, err := LoadSecretBinary("MASTER_KEY", 32); err == nil {
				t.Fatal("a wrong-length key was accepted")
			}
		})
	}
}

// TestLoadSecretBinaryRequiresTheEnvVar keeps the unset case distinguishable
// from a bad key.
func TestLoadSecretBinaryRequiresTheEnvVar(t *testing.T) {
	t.Setenv("MASTER_KEY_FILE", "")
	if _, err := LoadSecretBinary("MASTER_KEY", 32); err == nil {
		t.Fatal("an unset MASTER_KEY_FILE was accepted")
	}
}

// TestLoadSecretStillTrimsTextSecrets pins the behavior the binary loader was
// split away from. Text secrets are written by `openssl rand -hex`, and a
// trailing newline there is noise rather than key material.
func TestLoadSecretStillTrimsTextSecrets(t *testing.T) {
	writeSecretFile(t, "HMAC_SECRET", []byte("  deadbeef\n"))
	got, err := LoadSecret("HMAC_SECRET")
	if err != nil {
		t.Fatalf("LoadSecret: %v", err)
	}
	if got != "deadbeef" {
		t.Errorf("got %q, want %q", got, "deadbeef")
	}
}

// TestLoadWiresTheBinaryMasterKeyLoader is the wiring half of the regression.
//
// TestLoadSecretBinaryKeepsWhitespaceBytes proves the loader is correct. It does
// not prove Load calls it, and that distinction is the whole bug: LoadSecret was
// always correct for the text secrets it was written for, and wrong only because
// the master key was routed through it. A test that exercises the loader
// directly stays green while the wiring regresses, so this one goes through
// Load.
func TestLoadWiresTheBinaryMasterKeyLoader(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// Whitespace at both ends, which is what a trim would take. This exact file
	// is a correct key that `openssl rand 32` produces about once in 700 runs,
	// and any single-ended variant about once in 22.
	key[0], key[31] = ' ', '\n'

	t.Setenv("VAULT_PROFILE", "production")
	writeSecretFile(t, "MASTER_KEY", key)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load rejected a valid 32-byte master key: %v", err)
	}
	if !bytes.Equal(cfg.MasterKey, key) {
		t.Errorf("Load altered the master key, so it is not using LoadSecretBinary:\n got %x\nwant %x",
			cfg.MasterKey, key)
	}
}
