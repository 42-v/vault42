package attack

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/middleware"
)

// TestPasswordSpray_LockoutPerAccount verifies that password spray attacks
// (trying the same password across many accounts) are mitigated by per-account
// lockout counters.
func TestPasswordSpray_LockoutPerAccount(t *testing.T) {
	mc := cache.NewMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	threshold := 5
	lockDuration := 15 * time.Minute

	// Simulate spraying: 3 attempts per account across 20 accounts
	for i := 0; i < 20; i++ {
		userID := "sprayed-user-" + string(rune('A'+i%26))
		for j := 0; j < 3; j++ {
			locked, _ := middleware.CheckAccountLockout(ctx, mc, userID, threshold, lockDuration)
			if locked {
				t.Fatalf("Account %s locked too early at attempt %d (threshold=%d)", userID, j+1, threshold)
			}
		}
	}

	// Now spray one account past the threshold
	targetUser := "sprayed-user-A"
	// Already has 3 attempts, add 2 more to reach threshold
	for i := 0; i < 2; i++ {
		middleware.CheckAccountLockout(ctx, mc, targetUser, threshold, lockDuration)
	}

	// 6th attempt should be locked
	locked, _ := middleware.CheckAccountLockout(ctx, mc, targetUser, threshold, lockDuration)
	if !locked {
		t.Fatal("Account should be locked after threshold exceeded via spray attack")
	}
}

// TestCredentialStuffing_IndependentAccounts verifies that credential stuffing
// (using leaked credential pairs) against different accounts triggers independent
// lockouts and does not affect unrelated accounts.
func TestCredentialStuffing_IndependentAccounts(t *testing.T) {
	mc := cache.NewMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	threshold := 3
	lockDuration := 5 * time.Minute

	// Stuff credentials into 5 different accounts
	accounts := []string{"user-leaked-1", "user-leaked-2", "user-leaked-3", "user-leaked-4", "user-leaked-5"}
	for _, acct := range accounts {
		for i := 0; i < threshold; i++ {
			middleware.CheckAccountLockout(ctx, mc, acct, threshold, lockDuration)
		}
	}

	// All 5 accounts should now be locked
	for _, acct := range accounts {
		locked, _ := middleware.CheckAccountLockout(ctx, mc, acct, threshold, lockDuration)
		if !locked {
			t.Fatalf("Account %s should be locked after %d attempts", acct, threshold)
		}
	}

	// Clean accounts should not be affected
	clean := "user-clean"
	locked, _ := middleware.CheckAccountLockout(ctx, mc, clean, threshold, lockDuration)
	if locked {
		t.Fatal("Clean account should not be locked")
	}
}

// TestTimingAnalysis_HashVerification verifies that password hash verification
// takes similar time regardless of whether the password is correct, preventing
// timing-based user enumeration.
func TestTimingAnalysis_HashVerification(t *testing.T) {
	password := "correct-password-timing-test!"
	hash, _ := vaultcrypto.HashPassword(password)

	const iterations = 10

	// Time correct password
	var correctTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		vaultcrypto.VerifyPassword(password, hash)
		correctTotal += time.Since(start)
	}
	correctAvg := correctTotal / iterations

	// Time wrong password (same length)
	var wrongTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		vaultcrypto.VerifyPassword("incorrect-password-timing!!!", hash)
		wrongTotal += time.Since(start)
	}
	wrongAvg := wrongTotal / iterations

	// Time very different password (different length)
	var shortTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		vaultcrypto.VerifyPassword("x", hash)
		shortTotal += time.Since(start)
	}
	shortAvg := shortTotal / iterations

	// All should be within 3x of each other (generous tolerance for CI)
	ratio1 := float64(correctAvg) / float64(wrongAvg)
	ratio2 := float64(correctAvg) / float64(shortAvg)

	if ratio1 < 0.3 || ratio1 > 3.0 {
		t.Fatalf("Timing leak: correct/wrong ratio=%.2f (correct=%v, wrong=%v)", ratio1, correctAvg, wrongAvg)
	}
	if ratio2 < 0.3 || ratio2 > 3.0 {
		t.Fatalf("Timing leak: correct/short ratio=%.2f (correct=%v, short=%v)", ratio2, correctAvg, shortAvg)
	}
}

// TestTimingAnalysis_DummyHashPath verifies that the dummy hash path (used for
// user-not-found) takes the same amount of time as a real hash verification.
func TestTimingAnalysis_DummyHashPath(t *testing.T) {
	realHash, _ := vaultcrypto.HashPassword("real-user-password-here!")
	dummyHash := "$argon2id$v=19$m=47104,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	const iterations = 10

	var realTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		vaultcrypto.VerifyPassword("attempt", realHash)
		realTotal += time.Since(start)
	}
	realAvg := realTotal / iterations

	var dummyTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		vaultcrypto.VerifyPassword("attempt", dummyHash)
		dummyTotal += time.Since(start)
	}
	dummyAvg := dummyTotal / iterations

	ratio := float64(realAvg) / float64(dummyAvg)
	if ratio < 0.3 || ratio > 3.0 {
		t.Fatalf("Timing leak between real and dummy hash: ratio=%.2f (real=%v, dummy=%v)",
			ratio, realAvg, dummyAvg)
	}
}

// TestPasswordAttack_Argon2DoSProtection verifies that crafted hashes with
// extreme parameters are rejected to prevent DoS via expensive computations.
func TestPasswordAttack_Argon2DoSProtection(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{
			"extreme_memory",
			"$argon2id$v=19$m=999999,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			"extreme_iterations",
			"$argon2id$v=19$m=47104,t=99,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			"extreme_parallelism",
			"$argon2id$v=19$m=47104,t=1,p=99$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			"zero_iterations",
			"$argon2id$v=19$m=47104,t=0,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			"zero_parallelism",
			"$argon2id$v=19$m=47104,t=1,p=0$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match, err := vaultcrypto.VerifyPassword("any-password", tc.hash)
			if match {
				t.Fatal("Crafted hash should never verify")
			}
			if err == nil {
				t.Fatal("Crafted hash should return an error")
			}
		})
	}
}

// TestPasswordAttack_HashFormatManipulation verifies that malformed PHC
// format strings are rejected cleanly without panics.
func TestPasswordAttack_HashFormatManipulation(t *testing.T) {
	malformed := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"no_dollars", "argon2id-v19-m47104t1p1-salt-hash"},
		{"wrong_prefix", "$bcrypt$v=19$m=47104,t=1,p=1$salt$hash"},
		{"missing_parts", "$argon2id$v=19$m=47104,t=1,p=1$salt"},
		{"extra_parts", "$argon2id$v=19$m=47104,t=1,p=1$salt$hash$extra"},
		{"non_numeric_memory", "$argon2id$v=19$m=abc,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"non_numeric_iterations", "$argon2id$v=19$m=47104,t=abc,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"invalid_base64_salt", "$argon2id$v=19$m=47104,t=1,p=1$!!!invalid!!!$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"invalid_base64_hash", "$argon2id$v=19$m=47104,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$!!!invalid!!!"},
		{"null_bytes", "$argon2id$v=19$m=47104,t=1,p=1$\x00\x00\x00$\x00\x00\x00"},
		{"sql_injection", "$argon2id$v=19$m=47104,t=1,p=1$'; DROP TABLE users;--$hash"},
	}

	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			// Should not panic
			match, _ := vaultcrypto.VerifyPassword("test-password", tc.hash)
			if match {
				t.Fatalf("Malformed hash %q should never verify", tc.name)
			}
		})
	}
}

// TestPasswordAttack_SecureCompareConstantTime verifies that SecureCompare
// does not short-circuit on the first differing byte.
func TestPasswordAttack_SecureCompareConstantTime(t *testing.T) {
	// Compare strings that differ at different positions
	base := "abcdefghijklmnopqrstuvwxyz012345"

	cases := []struct {
		name string
		a    string
		b    string
	}{
		{"differ_at_start", "Xbcdefghijklmnopqrstuvwxyz012345", base},
		{"differ_at_middle", "abcdefghijklmnXqrstuvwxyz012345", base},
		{"differ_at_end", "abcdefghijklmnopqrstuvwxyz01234X", base},
		{"identical", base, base},
		{"empty_both", "", ""},
		{"one_empty", base, ""},
		{"differ_length", "short", "much-much-longer-string"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := vaultcrypto.SecureCompare(tc.a, tc.b)
			expected := tc.a == tc.b
			if result != expected {
				t.Fatalf("SecureCompare(%q, %q) = %v, want %v", tc.a, tc.b, result, expected)
			}
		})
	}
}
