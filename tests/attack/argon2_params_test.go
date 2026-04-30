package attack

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestArgon2Params_MemoryRequirement verifies that Argon2id uses at least
// 46 MiB of memory (47104 KiB).
func TestArgon2Params_MemoryRequirement(t *testing.T) {
	hash, err := vaultcrypto.HashPassword("test-argon2-memory")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("Invalid PHC format: expected 6 parts, got %d", len(parts))
	}

	params := parseArgon2Params(t, parts[3])
	// 47104 KiB = 46 MiB
	if params.memory < 47104 {
		t.Fatalf("Argon2id memory must be >= 47104 KiB (46 MiB), got %d KiB (%d MiB)",
			params.memory, params.memory/1024)
	}

	// NIST/OWASP minimum is 19 MiB = 19456 KiB
	if params.memory < 19456 {
		t.Fatalf("Argon2id memory must be >= 19456 KiB (19 MiB OWASP minimum), got %d KiB",
			params.memory)
	}
}

// TestArgon2Params_IterationRequirement verifies at least 1 iteration.
func TestArgon2Params_IterationRequirement(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("test-argon2-iterations")
	parts := strings.Split(hash, "$")
	params := parseArgon2Params(t, parts[3])

	if params.iterations < 1 {
		t.Fatalf("Argon2id iterations must be >= 1, got %d", params.iterations)
	}
}

// TestArgon2Params_ParallelismRequirement verifies parallelism >= 1.
func TestArgon2Params_ParallelismRequirement(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("test-argon2-parallelism")
	parts := strings.Split(hash, "$")
	params := parseArgon2Params(t, parts[3])

	if params.parallelism < 1 {
		t.Fatalf("Argon2id parallelism must be >= 1, got %d", params.parallelism)
	}
}

// TestArgon2Params_Variant verifies that Argon2id variant is used (not Argon2i or Argon2d).
func TestArgon2Params_Variant(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("test-variant-check")
	parts := strings.Split(hash, "$")

	if parts[1] != "argon2id" {
		t.Fatalf("Expected argon2id variant, got %q", parts[1])
	}
}

// TestArgon2Params_Version verifies Argon2 version 19.
func TestArgon2Params_Version(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("test-version-check")
	parts := strings.Split(hash, "$")

	if parts[2] != "v=19" {
		t.Fatalf("Expected Argon2 v=19, got %q", parts[2])
	}
}

// TestArgon2Params_SaltLength verifies salt is >= 16 bytes (128 bits).
func TestArgon2Params_SaltLength(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("test-salt-length")
	parts := strings.Split(hash, "$")

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}
	if len(salt) < 16 {
		t.Fatalf("Salt must be >= 16 bytes (128 bits), got %d bytes", len(salt))
	}
}

// TestArgon2Params_HashLength verifies output hash is >= 32 bytes (256 bits).
func TestArgon2Params_HashLength(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("test-hash-length")
	parts := strings.Split(hash, "$")

	output, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatalf("Failed to decode hash output: %v", err)
	}
	if len(output) < 32 {
		t.Fatalf("Hash output must be >= 32 bytes (256 bits), got %d bytes", len(output))
	}
}

// TestArgon2Params_MalformedHashRejection verifies that malformed Argon2id hashes
// are rejected during verification.
func TestArgon2Params_MalformedHashRejection(t *testing.T) {
	malformedHashes := []struct {
		name string
		hash string
	}{
		{"wrong algorithm", "$argon2d$v=19$m=47104,t=1,p=1$c2FsdA$aGFzaA"},
		{"missing parts", "$argon2id$v=19$m=47104,t=1,p=1$c2FsdA"},
		{"empty", ""},
		{"just prefix", "$argon2id$"},
		{"no params", "$argon2id$v=19$$c2FsdA$aGFzaA"},
		{"bad memory", "$argon2id$v=19$m=abc,t=1,p=1$c2FsdA$aGFzaA"},
	}

	for _, tt := range malformedHashes {
		t.Run(tt.name, func(t *testing.T) {
			match, err := vaultcrypto.VerifyPassword("any-password", tt.hash)
			if match {
				t.Fatalf("Malformed hash %q should not match any password", tt.name)
			}
			// err may or may not be nil (dummy computation may succeed),
			// but match must always be false
			_ = err
		})
	}
}

// TestArgon2Params_ExtremeParamsRejected verifies that crafted hashes with
// extreme parameters are rejected during verification.
func TestArgon2Params_ExtremeParamsRejected(t *testing.T) {
	extremeHashes := []struct {
		name string
		hash string
	}{
		{
			"extreme memory (1 TB)",
			"$argon2id$v=19$m=1073741824,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			"extreme iterations",
			"$argon2id$v=19$m=47104,t=999999,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			"extreme parallelism",
			"$argon2id$v=19$m=47104,t=1,p=255$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			"zero iterations",
			"$argon2id$v=19$m=47104,t=0,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			"zero parallelism",
			"$argon2id$v=19$m=47104,t=1,p=0$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
	}

	for _, tt := range extremeHashes {
		t.Run(tt.name, func(t *testing.T) {
			match, err := vaultcrypto.VerifyPassword("test-password", tt.hash)
			if match {
				t.Fatalf("Hash with extreme params (%s) should not match", tt.name)
			}
			// Extreme params should cause an error (rejected during parsing)
			if err == nil {
				t.Logf("Warning: extreme params %q did not return error", tt.name)
			}
		})
	}
}

type argon2TestParams struct {
	memory      int
	iterations  int
	parallelism int
}

func parseArgon2Params(t *testing.T, paramStr string) argon2TestParams {
	t.Helper()
	params := argon2TestParams{}
	parts := strings.Split(paramStr, ",")
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			t.Fatalf("Malformed param: %q", p)
		}
		val, err := strconv.Atoi(kv[1])
		if err != nil {
			t.Fatalf("Invalid param value: %q", kv[1])
		}
		switch kv[0] {
		case "m":
			params.memory = val
		case "t":
			params.iterations = val
		case "p":
			params.parallelism = val
		}
	}
	return params
}
