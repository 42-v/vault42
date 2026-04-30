package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadSecret reads a secret from the file path specified in the env var
// (envKey + "_FILE"), trims whitespace, and zeros the file after reading.
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
	// Zero the file contents and delete it (defense in depth)
	_ = os.WriteFile(path, make([]byte, len(data)), 0o400) // #nosec G104 -- secret file zeroing is best-effort; path from operator env var
	_ = os.Remove(path)                                    // #nosec G104 -- secret file deletion is best-effort
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
