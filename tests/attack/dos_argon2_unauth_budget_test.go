package attack

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

func dosHashPassword(t *testing.T, password string) string {
	t.Helper()
	var last error
	for i := 0; i < 30; i++ {
		hash, err := vaultcrypto.HashPassword(password)
		if err == nil {
			return hash
		}
		last = err
		if !errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			t.Fatalf("HashPassword: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("HashPassword still overloaded after retries: %v", last)
	return ""
}

func dosVerify(t *testing.T, password, encoded string) (bool, error) {
	t.Helper()
	var lastErr error
	for i := 0; i < 30; i++ {
		ok, err := vaultcrypto.VerifyPassword(password, encoded)
		if err == nil || !errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			return ok, err
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return false, lastErr
}

// TestDoS_UnauthenticatedArgon2Budget computes the RAM an internet client
// can pin without a credential, using the process's real issuing parameters
// and the real semaphore. It does not run the hash under flood (that is
// TestArgon2Attack_MeasureQueueingUnderFlood); it checks the arithmetic the
// report quotes, so a parameter change that silently doubles the peak fails
// here rather than in a comment.
func TestDoS_UnauthenticatedArgon2Budget(t *testing.T) {
	hash := dosHashPassword(t, "dos-review-budget-probe-password")
	// PHC: $argon2id$v=19$m=47104,t=1,p=1$...
	parts := strings.Split(hash, "$")
	if len(parts) < 4 {
		t.Fatalf("issued hash is not PHC: %q", hash)
	}
	var memKiB, iters, para int
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("bad param %q in %q", kv, parts[3])
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("param %s: %v", k, err)
		}
		switch k {
		case "m":
			memKiB = n
		case "t":
			iters = n
		case "p":
			para = n
		}
	}
	if memKiB <= 0 || iters <= 0 || para <= 0 {
		t.Fatalf("parsed issued params m=%d t=%d p=%d from %q", memKiB, iters, para, parts[3])
	}

	slots := vaultcrypto.Argon2MaxConcurrent()
	issuedPeakMiB := slots * memKiB / 1024
	verifyCeilKiB := int(vaultcrypto.Argon2MaxVerifyMemory())
	verifyPeakMiB := slots * verifyCeilKiB / 1024

	t.Logf("issued hash: m=%d KiB (%d MiB) t=%d p=%d", memKiB, memKiB/1024, iters, para)
	t.Logf("semaphore: %d slots, acquire queues up to 5s then ErrArgon2Overloaded", slots)
	t.Logf("unauthenticated peak (login/register/reset/client-token dummy or real hash): %d MiB", issuedPeakMiB)
	t.Logf("stored-hash peak (needs a row the parser accepts): %d MiB", verifyPeakMiB)

	// Spec parameters. A silent drop below the OWASP 19 MiB floor or a
	// raise that no longer fits a 512 MiB pod is the thing to catch.
	if memKiB < 19*1024 {
		t.Errorf("issued memory %d KiB is below the OWASP 19 MiB floor", memKiB)
	}
	if issuedPeakMiB > 256 {
		t.Errorf("unauthenticated attacker can pin %d MiB via %d concurrent issued-parameter hashes; "+
			"the semaphore comment budgets 184 MiB common / 256 MiB worst against a 512 MiB pod",
			issuedPeakMiB, slots)
	}
	if verifyPeakMiB > 256 {
		t.Errorf("verify ceiling × slots = %d MiB, over the 256 MiB worst-case budget", verifyPeakMiB)
	}

	// /client/token is the cheapest unauthenticated argon2 lever: 10
	// requests/minute/IP versus login's 5/15 minutes. IPs needed to keep
	// every slot busy = slots / (per-IP rate), independent of hash time
	// only if the hash is faster than the spacing; with ~150 ms hashes
	// the process does ~slots/0.15 ≈ 27 ops/s and each IP contributes
	// 10/60 ≈ 0.17 ops/s, so ~160 IPs suffice. We pin the *rate* here
	// (the limiter constants live in server.go; a source contract test
	// checks they have not been silently raised).
	if slots != 4 {
		t.Errorf("Argon2MaxConcurrent = %d, report and RAM arithmetic assume 4", slots)
	}
}

// TestDoS_DummyHashIsIssuedParameterPHC is the anti-enumeration path an
// unauthenticated client hits on a missing user, a missing client, or a
// password-reset probe. VerifyPassword substitutes DummyHash for the
// rotating hash and then takes the semaphore; a sentinel that failed to
// parse would still burn a hash (the malformed branch) but a sentinel
// that VerifyPassword rejected before acquireArgon2 would let a probe
// skip the cost. The call must therefore return (false, nil), not an
// error, and the stored string must carry the issued parameters.
func TestDoS_DummyHashIsIssuedParameterPHC(t *testing.T) {
	if vaultcrypto.DummyHash == "" {
		t.Fatal("DummyHash is empty; the not-found path would not run a real verify")
	}
	if !strings.HasPrefix(vaultcrypto.DummyHash, "$argon2id$") {
		t.Fatalf("DummyHash = %q, want issued-parameter PHC", vaultcrypto.DummyHash)
	}
	ok, err := dosVerify(t, "not-the-dummy-password", vaultcrypto.DummyHash)
	if err != nil {
		t.Fatalf("VerifyPassword(DummyHash) = %v; a parse/overload error here means the "+
			"not-found path no longer pays the issued-parameter cost (or the semaphore is full)", err)
	}
	if ok {
		t.Fatal("DummyHash verified the probe password; the sentinel is not a dummy")
	}
}
