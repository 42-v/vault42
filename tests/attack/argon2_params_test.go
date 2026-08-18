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

// parseArgon2Params reads the PHC parameter segment of a hash the production
// hasher produced.
//
// It does not call internal/crypto's own decoder: parseArgon2Hash is unexported,
// and exporting it so a test could call it would add a production seam whose
// only consumer is this file. What closes the gap the duplicate leaves is
// TestArgon2Params_TheEncodedParametersAreTheOnesTheHashWasComputedWith below —
// the numbers read here are provably the numbers the derivation used, because
// verification re-derives from them and matches.
//
// The parse is strict where the previous version was not: it required nothing,
// silently ignored an unknown key, and left a missing one at zero, so an
// encoding change turned every floor below into a comparison against 0.
func parseArgon2Params(t *testing.T, paramStr string) argon2TestParams {
	t.Helper()
	fields := strings.Split(paramStr, ",")
	if len(fields) != 3 {
		t.Fatalf("PHC parameter segment %q has %d fields, want exactly m, t and p", paramStr, len(fields))
	}

	params := argon2TestParams{}
	seen := map[string]bool{}
	for _, f := range fields {
		key, value, ok := strings.Cut(f, "=")
		if !ok {
			t.Fatalf("PHC parameter %q is not key=value", f)
		}
		n, err := strconv.Atoi(value)
		if err != nil {
			t.Fatalf("PHC parameter %q has a non-numeric value: %v", f, err)
		}
		if seen[key] {
			t.Fatalf("PHC parameter %q appears twice in %q", key, paramStr)
		}
		seen[key] = true
		switch key {
		case "m":
			params.memory = n
		case "t":
			params.iterations = n
		case "p":
			params.parallelism = n
		default:
			t.Fatalf("unknown PHC parameter %q in %q; the encoding changed and every floor "+
				"asserted against this segment is now measuring something else", key, paramStr)
		}
	}
	return params
}

// The assertion that makes the parse above evidence rather than a second opinion.
//
// The floors are read off the encoded parameter segment, which would be worth
// nothing if the hasher could encode one cost and derive with another: the test
// would report 46 MiB while every stored password was derived at 8. Verification
// re-derives the key using exactly the parsed parameters, so a hash that verifies
// against the password that produced it is a hash whose encoded parameters are
// the ones the derivation used. Editing the encoded m without changing the
// derivation, or the reverse, breaks this.
func TestArgon2Params_TheEncodedParametersAreTheOnesTheHashWasComputedWith(t *testing.T) {
	const password = "test-argon2-parameter-honesty"
	hash, err := vaultcrypto.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := vaultcrypto.VerifyPassword(password, hash)
	if err != nil || !ok {
		t.Fatalf("the hasher's own output did not verify (ok=%v err=%v)", ok, err)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("Invalid PHC format: expected 6 parts, got %d", len(parts))
	}
	params := parseArgon2Params(t, parts[3])

	// Re-encode the segment with the memory cost halved and leave the derived key
	// untouched. Verification now derives at a cost the key was not derived at, so
	// it must refuse — which is what proves the segment is load-bearing.
	parts[3] = strings.Replace(parts[3], "m="+strconv.Itoa(params.memory),
		"m="+strconv.Itoa(params.memory/2), 1)
	ok, err = vaultcrypto.VerifyPassword(password, strings.Join(parts, "$"))
	if err != nil {
		t.Fatalf("verifying against a re-encoded parameter segment errored: %v", err)
	}
	if ok {
		t.Fatal("a hash whose declared memory cost was halved still verified; the encoded " +
			"parameters are not what the derivation uses, so the floors asserted against " +
			"them mean nothing")
	}
}
