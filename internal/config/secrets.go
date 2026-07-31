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
	if os.Getenv("VAULT_SECRET_FILE_CONSUME") == "true" {
		// path comes from an operator-controlled env var. Quote it, and the error
		// text repeating it, so CR/LF cannot forge extra log records (CWE-117).
		safePath := strconv.Quote(path)
		if werr := os.WriteFile(path, make([]byte, len(data)), 0o400); werr != nil { // #nosec G104,G306 -- best-effort zeroing; path from operator env var
			log.Printf("WARNING: failed to zero secret file %s (defense-in-depth wipe skipped): %s", safePath, strconv.Quote(werr.Error()))
		}
		if rerr := os.Remove(path); rerr != nil {
			log.Printf("WARNING: failed to remove secret file %s (defense-in-depth wipe skipped): %s", safePath, strconv.Quote(rerr.Error()))
		}
	}
	return strings.TrimSpace(string(data)), nil
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
