package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	password := "correct-horse-battery-staple-15chars"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	// Verify format
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash should start with $argon2id$, got %s", hash[:20])
	}

	// Correct password should verify
	ok, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("correct password should verify")
	}

	// Wrong password should not verify
	ok, err = VerifyPassword("wrong-password-here!", hash)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("wrong password should not verify")
	}
}

func TestHashPasswordUniqueSalts(t *testing.T) {
	password := "same-password-different-salts!!"
	h1, _ := HashPassword(password)
	h2, _ := HashPassword(password)
	if h1 == h2 {
		t.Error("same password should produce different hashes (different salts)")
	}
}

// HashPassword draws its salt with crypto/rand.Read, which has no error return
// to check on this toolchain: a Reader failure calls the runtime fatal handler
// and terminates the process. The property the removed check was nominally
// guarding is asserted here directly instead: the encoded salt is the full
// argon2SaltLen of material and is never a zero buffer. An all-zero salt would
// make every hash of a given password identical across the fleet, which is
// exactly what a rainbow table needs.
func TestHashPasswordSaltIsFullLengthAndNonZero(t *testing.T) {
	salt := func(hash string) []byte {
		t.Helper()
		parts := strings.Split(hash, "$")
		if len(parts) != 6 {
			t.Fatalf("hash %q does not have the 6 PHC fields", hash)
		}
		raw, err := base64.RawStdEncoding.DecodeString(parts[4])
		if err != nil {
			t.Fatalf("decode salt %q: %v", parts[4], err)
		}
		return raw
	}

	h1, err := HashPassword("salt-entropy-probe-password!!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	h2, err := HashPassword("salt-entropy-probe-password!!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	s1, s2 := salt(h1), salt(h2)
	if len(s1) != argon2SaltLen {
		t.Errorf("salt is %d bytes, want %d: rand.Read returned a short fill", len(s1), argon2SaltLen)
	}
	zero := make([]byte, argon2SaltLen)
	if string(s1) == string(zero) {
		t.Error("salt is all zero: the buffer was never filled with entropy")
	}
	if string(s1) == string(s2) {
		t.Error("two hashes of the same password share a salt")
	}
}

func TestVerifyPasswordMalformedHash(t *testing.T) {
	// Should not panic on malformed input, should return error
	ok, err := VerifyPassword("password", "not-a-valid-hash")
	if ok {
		t.Error("malformed hash should not verify")
	}
	if err == nil {
		t.Error("malformed hash should return error")
	}
}

func TestArgon2Parameters(t *testing.T) {
	hash, _ := HashPassword("test-password-15chars!")
	// Verify parameters are encoded in hash
	if !strings.Contains(hash, "m=47104") {
		t.Error("hash should contain m=47104 (46 MiB)")
	}
	if !strings.Contains(hash, "t=1") {
		t.Error("hash should contain t=1")
	}
	if !strings.Contains(hash, "p=1") {
		t.Error("hash should contain p=1")
	}
}
