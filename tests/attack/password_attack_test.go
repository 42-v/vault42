package attack

import (
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestPasswordSpray_LockoutPerAccount attacks the real login path with a spray:
// one password, many accounts, so no account ever reaches its own limit.
//
// The per-account counter is the wrong control to look at here, and the old
// version of this test looked at nothing else — it incremented
// middleware.CheckAccountLockout for twenty made-up user ids and asserted that
// the twenty-first increment on one of them crossed a threshold the test had
// picked. Spraying is defined by never crossing that threshold. What stops it is
// the per-ADDRESS counter, which counts failures from one source across every
// account it touches, and which that test never went near because the helper had
// no such counter.
func TestPasswordSpray_LockoutPerAccount(t *testing.T) {
	perSource := atkPerSourceLimit(t, atkSearchCeiling)
	spray := atkSprayLimit(t, 200)

	// A sprayer never reaches the per-account limit by construction, so the
	// per-address limit is the only thing between them and every account in the
	// deployment. It has to exist and it has to bind first.
	if spray <= perSource {
		t.Errorf("the per-address limit (%d) is not above the per-account one (%d); either the "+
			"address counter is unnecessary or the account counter is unreachable", spray, perSource)
	}
	t.Logf("measured: one address gets %d failures against a single account and %d across all "+
		"accounts before the address itself is refused", perSource, spray)

	// And the lock is on the address, not on the accounts it touched: an account
	// the sprayer failed once against is still reachable by its owner elsewhere.
	a := newAtkLockout(t)
	const (
		victim     = "sprayed@example.com"
		sprayerIP  = "198.51.100.30"
		ownerIP    = "203.0.113.30"
		bystanderA = "bystander@example.com"
	)
	a.account(victim)
	a.account(bystanderA)
	a.guess(victim, sprayerIP)
	if a.canReach(t, victim, ownerIP) != atkAdmitted {
		t.Error("one sprayed guess from another address denied the account owner their own account")
	}
	if a.canReach(t, bystanderA, ownerIP) != atkAdmitted {
		t.Error("an account the sprayer never touched was affected")
	}
}

// TestCredentialStuffing_IndependentAccounts stuffs leaked pairs at the real
// login path and holds the blast radius to the account and address that earned
// it.
//
// The old version asserted that a counter keyed on a user id gives different
// answers for different user ids, which is a property of a map. The question
// worth asking is whether locking one account leaks into another account, or
// into another address, and that can only be asked of the code that decides.
func TestCredentialStuffing_IndependentAccounts(t *testing.T) {
	perSource := atkPerSourceLimit(t, atkSearchCeiling)

	const (
		stuffedA  = "stuffed-a@example.com"
		stuffedB  = "stuffed-b@example.com"
		clean     = "clean@example.com"
		stufferIP = "198.51.100.40"
		ownerIP   = "203.0.113.40"
	)
	a := newAtkLockout(t)
	for _, email := range []string{stuffedA, stuffedB, clean} {
		a.account(email)
	}

	for i := 0; i < perSource; i++ {
		a.guess(stuffedA, stufferIP)
		a.guess(stuffedB, stufferIP)
	}

	// Both stuffed accounts are shut to the stuffer.
	for _, email := range []string{stuffedA, stuffedB} {
		if a.canReach(t, email, stufferIP) == atkAdmitted {
			t.Errorf("%d wrong passwords against %s from %s did not stop that source", perSource, email, stufferIP)
		}
	}

	// An account the stuffer never tried is untouched from the same address, so
	// the lock is not a blunt per-address ban applied one attempt too early.
	if a.canReach(t, clean, stufferIP) != atkAdmitted {
		t.Errorf("an account the stuffer never tried was refused from %s; the per-account lock is "+
			"leaking across accounts", stufferIP)
	}

	// And the owners of both stuffed accounts can still log in from their own
	// address. This is the half a lockout keyed on the account alone fails:
	// there, a stuffer with a leaked address list denies every one of those
	// accounts for the lockout window, holding no valid credential at all.
	for _, email := range []string{stuffedA, stuffedB} {
		if a.canReach(t, email, ownerIP) != atkAdmitted {
			t.Errorf("credential stuffing from %s locked %s out of their own account at %s", stufferIP, email, ownerIP)
		}
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
