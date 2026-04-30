package crypto

import (
	"strings"
	"testing"
)

func TestArgon2UpperBoundsIterations(t *testing.T) {
	// Craft a hash with iterations=99 — should be rejected
	hash := "$argon2id$v=19$m=47104,t=99,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ok, err := VerifyPassword("password", hash)
	if ok {
		t.Error("hash with excessive iterations should not verify")
	}
	if err == nil || !strings.Contains(err.Error(), "iterations exceed maximum") {
		t.Errorf("expected iterations exceed maximum error, got: %v", err)
	}
}

func TestArgon2UpperBoundsParallelism(t *testing.T) {
	hash := "$argon2id$v=19$m=47104,t=1,p=99$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ok, err := VerifyPassword("password", hash)
	if ok {
		t.Error("hash with excessive parallelism should not verify")
	}
	if err == nil || !strings.Contains(err.Error(), "parallelism exceeds maximum") {
		t.Errorf("expected parallelism exceeds maximum error, got: %v", err)
	}
}

func TestArgon2UpperBoundsMemory(t *testing.T) {
	// memory = 999999 KiB > 128 MiB (131072 KiB)
	hash := "$argon2id$v=19$m=999999,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ok, err := VerifyPassword("password", hash)
	if ok {
		t.Error("hash with excessive memory should not verify")
	}
	if err == nil || !strings.Contains(err.Error(), "memory exceeds maximum") {
		t.Errorf("expected memory exceeds maximum error, got: %v", err)
	}
}

func TestArgon2MemoryTooSmall(t *testing.T) {
	// memory = 1 < 8*p=8
	hash := "$argon2id$v=19$m=1,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ok, err := VerifyPassword("password", hash)
	if ok {
		t.Error("hash with too-small memory should not verify")
	}
	if err == nil || !strings.Contains(err.Error(), "memory too small") {
		t.Errorf("expected memory too small error, got: %v", err)
	}
}

func TestArgon2ZeroIterations(t *testing.T) {
	hash := "$argon2id$v=19$m=47104,t=0,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ok, err := VerifyPassword("password", hash)
	if ok {
		t.Error("hash with zero iterations should not verify")
	}
	if err == nil || !strings.Contains(err.Error(), "iterations must be >= 1") {
		t.Errorf("expected iterations >= 1 error, got: %v", err)
	}
}

func TestArgon2ZeroParallelism(t *testing.T) {
	hash := "$argon2id$v=19$m=47104,t=1,p=0$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ok, err := VerifyPassword("password", hash)
	if ok {
		t.Error("hash with zero parallelism should not verify")
	}
	if err == nil || !strings.Contains(err.Error(), "parallelism must be >= 1") {
		t.Errorf("expected parallelism >= 1 error, got: %v", err)
	}
}

func TestArgon2EmptyHash(t *testing.T) {
	ok, err := VerifyPassword("password", "")
	if ok {
		t.Error("empty hash should not verify")
	}
	if err == nil {
		t.Error("empty hash should return error")
	}
}

func TestArgon2ValidBoundaryParams(t *testing.T) {
	// Normal parameters should still work after adding bounds
	password := "test-boundary-password!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !ok {
		t.Error("valid password should verify with valid hash")
	}
}
