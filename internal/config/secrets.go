package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LoadSecret reads a secret from the file path specified in the env var
// (envKey + "_FILE") and trims whitespace. When VAULT_SECRET_FILE_CONSUME=true it
// also zeroes + removes the file (defense in depth). That destruction is opt-in
// (audit L5): the canonical deployment mounts secrets read-only where it is a
// silent no-op, while on a writable real keyfile it would destroy the operator's
// secret on first read — so failures are now surfaced rather than swallowed.
func LoadSecret(envKey string) (string, error) {
	path := os.Getenv(envKey + "_FILE")
	if path == "" {
		return "", fmt.Errorf("%s_FILE not set", envKey)
	}
	path = filepath.Clean(path)
	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env var (_FILE convention), cleaned with filepath.Clean
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	consumeSecretFile(path, len(data))
	return strings.TrimSpace(string(data)), nil
}

// LoadSecretBinary reads a fixed-length binary secret without trimming it.
//
// LoadSecret trims whitespace, which is right for the text secrets written by
// `openssl rand -hex` and wrong for a key that is raw bytes. scripts/generate-secrets.sh
// writes the master key as 32 raw bytes from `openssl rand 32`. Six of the 256
// possible byte values are ASCII whitespace, so a correctly generated key whose
// first or last byte happens to be one of them lost that byte to the trim: about
// one key in twenty-two. The file on disk was exactly 32 bytes and exactly right,
// and the process refused to start with "MASTER_KEY_FILE is required (32 bytes
// for AES-256)", which reads as a missing mount rather than a mangled read.
//
// A trailing newline is still tolerated, because an operator who writes a key
// with a shell redirect or an editor gets one and their key is not wrong. Exactly
// one is stripped, and only when doing so produces the expected length, so a raw
// key that genuinely ends in 0x0A is kept rather than truncated.
//
// The consume-on-read behavior is identical to LoadSecret.
func LoadSecretBinary(envKey string, wantLen int) ([]byte, error) {
	path := os.Getenv(envKey + "_FILE")
	if path == "" {
		return nil, fmt.Errorf("%s_FILE not set", envKey)
	}
	path = filepath.Clean(path)
	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env var (_FILE convention), cleaned with filepath.Clean
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	consumeSecretFile(path, len(data))

	switch {
	case len(data) == wantLen:
		return data, nil
	case len(data) == wantLen+1 && data[len(data)-1] == '\n':
		return data[:wantLen], nil
	case len(data) == wantLen+2 && data[len(data)-2] == '\r' && data[len(data)-1] == '\n':
		return data[:wantLen], nil
	default:
		return nil, fmt.Errorf("%s_FILE holds %d bytes, want %d", envKey, len(data), wantLen)
	}
}

// consumeSecretFile applies the opt-in zero-and-remove wipe shared by LoadSecret
// and LoadSecretBinary.
func consumeSecretFile(path string, size int) {
	if os.Getenv("VAULT_SECRET_FILE_CONSUME") != "true" {
		return
	}
	// path comes from an operator-controlled env var. Quote it, and the error
	// text repeating it, so CR/LF cannot forge extra log records (CWE-117).
	safePath := strconv.Quote(path)
	if werr := os.WriteFile(path, make([]byte, size), 0o400); werr != nil { // #nosec G104,G306 -- best-effort zeroing; path from operator env var
		log.Printf("WARNING: failed to zero secret file %s (defense-in-depth wipe skipped): %s", safePath, strconv.Quote(werr.Error()))
	}
	if rerr := os.Remove(path); rerr != nil {
		log.Printf("WARNING: failed to remove secret file %s (defense-in-depth wipe skipped): %s", safePath, strconv.Quote(rerr.Error()))
	}
}

// LoadSecretOptional is like LoadSecret but returns empty string if not set.
func LoadSecretOptional(envKey string) string {
	val, _ := LoadSecret(envKey)
	return val
}

// ZeroBytes overwrites a byte slice with zeros.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroString clears a string pointer. Note: Go strings are immutable, so the
// original string data cannot be zeroed in place — it remains in memory until
// garbage collected. For true secret zeroing, use []byte throughout.
// This function only clears the pointer to reduce the window of exposure.
func ZeroString(s *string) {
	*s = ""
}
