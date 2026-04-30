package crypto

import (
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
