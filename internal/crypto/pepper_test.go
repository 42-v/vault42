package crypto

import (
	"math"
	"testing"
	"time"
)

// TestHashWithPepper verifies that a password hashed with a pepper can be
// verified using the same pepper.
func TestHashWithPepper(t *testing.T) {
	password := "correct-horse-battery-staple"
	pepper := "server-side-secret-pepper-key"

	hash, err := HashPassword(password, pepper)
	if err != nil {
		t.Fatalf("HashPassword with pepper failed: %v", err)
	}

	ok, err := VerifyPassword(password, hash, pepper)
	if err != nil {
		t.Fatalf("VerifyPassword with correct pepper failed: %v", err)
	}
	if !ok {
		t.Fatal("password hashed with pepper should verify with the same pepper")
	}
}

// TestVerifyWithWrongPepper verifies that a hash produced with pepper "A"
// does not verify when pepper "B" is supplied.
func TestVerifyWithWrongPepper(t *testing.T) {
	password := "correct-horse-battery-staple"
	pepperA := "pepper-alpha"
	pepperB := "pepper-bravo"

	hash, err := HashPassword(password, pepperA)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	ok, err := VerifyPassword(password, hash, pepperB)
	if err != nil {
		t.Fatalf("VerifyPassword should not error on wrong pepper: %v", err)
	}
	if ok {
		t.Fatal("password hashed with pepper A must not verify with pepper B")
	}
}

// TestVerifyWithEmptyPepper verifies that a hash produced with a non-empty
// pepper does not verify when an empty pepper (or no pepper) is supplied.
func TestVerifyWithEmptyPepper(t *testing.T) {
	password := "correct-horse-battery-staple"
	pepper := "non-empty-pepper-value"

	hash, err := HashPassword(password, pepper)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Verify with explicit empty pepper
	ok, err := VerifyPassword(password, hash, "")
	if err != nil {
		t.Fatalf("VerifyPassword should not error with empty pepper: %v", err)
	}
	if ok {
		t.Fatal("hash produced with pepper must not verify with empty pepper")
	}

	// Verify with no pepper argument at all
	ok, err = VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword should not error with omitted pepper: %v", err)
	}
	if ok {
		t.Fatal("hash produced with pepper must not verify with omitted pepper")
	}
}

// TestHashWithEmptyPepper verifies backwards compatibility: hashing and
// verifying with an empty (or omitted) pepper works correctly.
func TestHashWithEmptyPepper(t *testing.T) {
	password := "correct-horse-battery-staple"

	// Hash with explicit empty pepper
	hash, err := HashPassword(password, "")
	if err != nil {
		t.Fatalf("HashPassword with empty pepper failed: %v", err)
	}

	ok, err := VerifyPassword(password, hash, "")
	if err != nil {
		t.Fatalf("VerifyPassword with empty pepper failed: %v", err)
	}
	if !ok {
		t.Fatal("empty-pepper hash should verify with empty pepper")
	}

	// Also verify with no pepper argument (should behave identically)
	ok, err = VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword with omitted pepper failed: %v", err)
	}
	if !ok {
		t.Fatal("empty-pepper hash should verify with omitted pepper")
	}

	// Hash with omitted pepper, verify with explicit empty pepper
	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword with omitted pepper failed: %v", err)
	}

	ok, err = VerifyPassword(password, hash2, "")
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !ok {
		t.Fatal("omitted-pepper hash should verify with empty pepper")
	}
}

// TestPepperChangesHash verifies that hashing the same password with different
// peppers produces hashes that are not cross-verifiable. The raw hashes will
// differ due to random salts regardless, so the meaningful check is that a
// hash created with pepper A does not verify with pepper B and vice versa.
func TestPepperChangesHash(t *testing.T) {
	password := "correct-horse-battery-staple"
	pepperA := "pepper-alpha"
	pepperB := "pepper-bravo"

	hashA, err := HashPassword(password, pepperA)
	if err != nil {
		t.Fatalf("HashPassword with pepper A failed: %v", err)
	}

	hashB, err := HashPassword(password, pepperB)
	if err != nil {
		t.Fatalf("HashPassword with pepper B failed: %v", err)
	}

	// Hash A must not verify with pepper B
	ok, err := VerifyPassword(password, hashA, pepperB)
	if err != nil {
		t.Fatalf("VerifyPassword should not error: %v", err)
	}
	if ok {
		t.Fatal("hash from pepper A must not verify with pepper B")
	}

	// Hash B must not verify with pepper A
	ok, err = VerifyPassword(password, hashB, pepperA)
	if err != nil {
		t.Fatalf("VerifyPassword should not error: %v", err)
	}
	if ok {
		t.Fatal("hash from pepper B must not verify with pepper A")
	}

	// Each hash must still verify with its own pepper
	ok, err = VerifyPassword(password, hashA, pepperA)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !ok {
		t.Fatal("hash A should verify with pepper A")
	}

	ok, err = VerifyPassword(password, hashB, pepperB)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !ok {
		t.Fatal("hash B should verify with pepper B")
	}
}

// TestPepperConstantTimeVerify checks that wrong-pepper and wrong-password
// rejections take similar time, ensuring no timing side-channel leaks the
// reason for rejection.
func TestPepperConstantTimeVerify(t *testing.T) {
	password := "correct-horse-battery-staple"
	pepper := "server-side-secret-pepper-key"

	hash, err := HashPassword(password, pepper)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	const iterations = 5

	// Measure wrong-password timing
	var wrongPwTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		ok, err := VerifyPassword("completely-wrong-password!!", hash, pepper)
		wrongPwTotal += time.Since(start)
		if err != nil {
			t.Fatalf("VerifyPassword should not error on wrong password: %v", err)
		}
		if ok {
			t.Fatal("wrong password should not verify")
		}
	}

	// Measure wrong-pepper timing
	var wrongPepperTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		ok, err := VerifyPassword(password, hash, "completely-wrong-pepper!!")
		wrongPepperTotal += time.Since(start)
		if err != nil {
			t.Fatalf("VerifyPassword should not error on wrong pepper: %v", err)
		}
		if ok {
			t.Fatal("wrong pepper should not verify")
		}
	}

	avgWrongPw := wrongPwTotal / time.Duration(iterations)
	avgWrongPepper := wrongPepperTotal / time.Duration(iterations)

	// Both paths run the full Argon2id computation, so timing should be
	// within the same order of magnitude. We allow a generous 5x ratio
	// to account for OS scheduling jitter while still catching gross
	// timing leaks (e.g., early-exit on pepper mismatch).
	ratio := float64(avgWrongPw) / float64(avgWrongPepper)
	if ratio < 1 {
		ratio = 1 / ratio
	}

	const maxRatio = 5.0
	if ratio > maxRatio {
		t.Errorf("timing ratio %.2f exceeds %.1fx threshold: wrong-password=%v, wrong-pepper=%v",
			ratio, maxRatio, avgWrongPw, avgWrongPepper)
	}

	// Sanity check: both should take at least some time (Argon2id is CPU-bound)
	minExpected := 10 * time.Millisecond
	if avgWrongPw < minExpected {
		t.Errorf("wrong-password verification suspiciously fast (%v), expected >= %v", avgWrongPw, minExpected)
	}
	if avgWrongPepper < minExpected {
		t.Errorf("wrong-pepper verification suspiciously fast (%v), expected >= %v", avgWrongPepper, minExpected)
	}

	// Log timing for manual inspection
	t.Logf("wrong-password avg: %v, wrong-pepper avg: %v, ratio: %.2f",
		avgWrongPw, avgWrongPepper, math.Max(ratio, 1/ratio))
}
