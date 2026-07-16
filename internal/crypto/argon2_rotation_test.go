package crypto

import (
	"errors"
	"testing"
)

// The anti-enumeration dummy hash used to be generated once per process, so
// its salt (and therefore the Argon2id memory access pattern) stayed fixed for
// the process lifetime. A background loop now re-derives it on a slow timer
// through regenerateDummyHash. Two properties must hold across a rotation: the
// exported DummyHash sentinel is never reassigned after init (unsynchronized
// readers in other packages depend on that), and a failed regeneration keeps
// the previous hash so the constant-time burn never loses a valid
// spec-parameter hash.
func TestRegenerateDummyHash_RotatesAndFailsSafe(t *testing.T) {
	sentinel := DummyHash
	initial := currentDummyHash()

	// Saturate the semaphore: HashPassword inside the regeneration must
	// propagate ErrArgon2Overloaded, and the rotating hash must survive.
	for i := 0; i < argon2MaxConcurrent; i++ {
		argon2Sem <- struct{}{}
	}
	err := regenerateDummyHash()
	for i := 0; i < argon2MaxConcurrent; i++ {
		<-argon2Sem
	}
	if !errors.Is(err, ErrArgon2Overloaded) {
		t.Fatalf("regenerate under load: err = %v, want ErrArgon2Overloaded", err)
	}
	if currentDummyHash() != initial {
		t.Error("a failed regeneration replaced the rotating hash")
	}

	if err := regenerateDummyHash(); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	rotated := currentDummyHash()
	if rotated == initial {
		t.Error("regeneration did not produce a fresh hash")
	}
	if DummyHash != sentinel {
		t.Error("regeneration reassigned the DummyHash sentinel; unsynchronized readers would race")
	}

	// The rotated hash must keep the spec parameters, or the dummy burn would
	// take a different time than a real verification.
	salt, hash, params, err := parseArgon2Hash(rotated)
	if err != nil {
		t.Fatalf("rotated hash does not parse: %v", err)
	}
	if params.memory != argon2Memory || params.iterations != argon2Iterations || params.parallelism != argon2Parallelism {
		t.Errorf("rotated hash params m=%d,t=%d,p=%d, want m=%d,t=%d,p=%d",
			params.memory, params.iterations, params.parallelism,
			argon2Memory, argon2Iterations, argon2Parallelism)
	}
	if len(salt) != argon2SaltLen || len(hash) != argon2KeyLen {
		t.Errorf("rotated hash salt/key length %d/%d, want %d/%d",
			len(salt), len(hash), argon2SaltLen, argon2KeyLen)
	}

	// The sentinel path must burn against the rotated hash and still behave
	// like a normal failed verification for a wrong password.
	valid, err := VerifyPassword("not-the-dummy-password", DummyHash)
	if err != nil {
		t.Fatalf("sentinel VerifyPassword: %v", err)
	}
	if valid {
		t.Error("the sentinel burn validated a wrong password")
	}
}
