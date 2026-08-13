package attack

import (
	"encoding/base64"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// Argon2id is the most expensive thing vault42 does per request, and the
// semaphore in internal/crypto/argon2.go is the only thing standing between a
// login flood and an OOM kill. These tests measure what that semaphore actually
// buys, rather than reading the constants and believing the comment.

// saturate holds every argon2 slot by running real HashPassword calls, the way
// a flood of logins would. The semaphore is unexported, so it cannot be filled
// directly from this package; that is deliberate here, because filling it with
// real work is what an attacker does.
//
// Returns a stop function that releases the pressure and waits for the workers.
func saturate(t *testing.T, workers int) func() {
	t.Helper()
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = vaultcrypto.HashPassword("flood")
			}
		}()
	}

	// Wait until the semaphore is genuinely full rather than sleeping a guess.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if vaultcrypto.Argon2ActiveCount() >= int64(vaultcrypto.Argon2MaxConcurrent()) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	return func() {
		close(stop)
		wg.Wait()
	}
}

// The cost of one argon2id verification, measured, because every throughput
// number below is derived from it.
func TestArgon2Attack_MeasureSingleOperationCost(t *testing.T) {
	hash, err := vaultcrypto.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	const runs = 5
	var total time.Duration
	for i := 0; i < runs; i++ {
		start := time.Now()
		if _, err := vaultcrypto.VerifyPassword("correct horse battery staple", hash); err != nil {
			t.Fatalf("VerifyPassword: %v", err)
		}
		total += time.Since(start)
	}
	mean := total / runs

	capacity := float64(vaultcrypto.Argon2MaxConcurrent()) / mean.Seconds()
	t.Logf("argon2id verify: mean %v over %d runs", mean, runs)
	t.Logf("process-wide ceiling: %d slots / %v = %.1f password operations per second, "+
		"for the WHOLE process, across login, registration, password reset, password "+
		"change, account deletion and client-secret verification",
		vaultcrypto.Argon2MaxConcurrent(), mean, capacity)

	if capacity > 100 {
		t.Logf("ceiling is high enough that saturation is not cheap; re-rank the DoS finding")
	}
}

// What the semaphore actually does under a flood, measured across concurrency
// levels rather than asserted.
//
// The result is not the one the code's comments imply. The semaphore does not
// shed load at four concurrent operations; it QUEUES, and the queue is bounded
// only by the five-second acquire timeout. A legitimate login therefore does
// not get rejected under pressure, it gets slow, and it gets slow linearly in
// the number of concurrent password operations.
//
// The consequence worth acting on is observability, not availability:
// argon2Rejected, the counter exposed as Argon2RejectedCount and the only
// signal the package emits for overload, stays at zero through the whole
// degradation. An operator watching it sees a healthy service while every
// login is taking a second.
func TestArgon2Attack_MeasureQueueingUnderFlood(t *testing.T) {
	if testing.Short() || atkRaceDetector {
		t.Skip("latency measurement: meaningless under -race, skipped in -short")
	}

	type sample struct {
		workers  int
		wait     time.Duration
		rejected int64
	}
	var samples []sample

	for _, workers := range []int{8, 32, 128} {
		rejectedBefore := vaultcrypto.Argon2RejectedCount()
		release := saturate(t, workers)

		const probes = 3
		var total time.Duration
		for i := 0; i < probes; i++ {
			start := time.Now()
			_, err := vaultcrypto.VerifyPassword("victim password", vaultcrypto.DummyHash)
			total += time.Since(start)
			if errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
				t.Logf("workers=%d: probe %d was rejected outright", workers, i)
			}
		}
		release()

		samples = append(samples, sample{
			workers:  workers,
			wait:     total / probes,
			rejected: vaultcrypto.Argon2RejectedCount() - rejectedBefore,
		})
	}

	for _, s := range samples {
		t.Logf("%3d concurrent password operations: legitimate login waits %-14v, "+
			"Argon2RejectedCount +%d", s.workers, s.wait, s.rejected)
	}

	first, last := samples[0], samples[len(samples)-1]
	perRequest := float64(last.wait-first.wait) / float64(last.workers-first.workers)
	t.Logf("victim latency grows about %.1fms per concurrent password operation",
		perRequest/float64(time.Millisecond))
	t.Logf("extrapolating to the %v acquire timeout: roughly %.0f concurrent operations "+
		"are needed before ANY caller is rejected",
		5*time.Second, float64(5*time.Second)/perRequest)

	// The finding: real degradation with no signal. If a future change makes
	// the semaphore shed load early, this stops being true and the test should
	// be revisited.
	if last.rejected == 0 && last.wait > 500*time.Millisecond {
		t.Errorf("at %d concurrent operations a legitimate login already waits %v, "+
			"yet Argon2RejectedCount is still 0. The only overload signal the package "+
			"exports does not fire until the queue is deep enough to burn the full %v "+
			"acquire timeout, so the degradation is invisible to monitoring.",
			last.workers, last.wait, 5*time.Second)
	}
}

// The user plane is careful: every one of its password paths tests for
// ErrArgon2Overloaded and answers 503 rather than counting the attempt as a
// wrong password. internal/service/auth.go, internal/handler/auth.go,
// account.go, client.go and password.go all do it. The admin gateway is the one
// that does not.
//
// internal/adminapi/auth.go, in Login:
//
//	valid, err := vaultcrypto.VerifyPassword(req.Password, admin.PasswordHash, h.pepper)
//	if err != nil || !valid {
//	    h.handleFailedLogin(ctx, admin, clientIP, r.UserAgent())
//	    httputil.WriteError(w, http.StatusUnauthorized, "invalid_credentials")
//
// ErrArgon2Overloaded lands in that err, so an overload is recorded by
// handleFailedLogin as a failed attempt, audited with reason "wrong_password",
// and counted toward the five-attempt lockout. Five overloads lock the admin
// out of the gateway, and the audit trail blames a password the admin typed
// correctly.
//
// How hard it is to TRIGGER is a separate question, and the honest answer is
// "very". TestArgon2Attack_MeasureQueueingUnderFlood shows the semaphore queues
// rather than sheds, so ErrArgon2Overloaded needs hundreds of concurrent
// password operations before it fires at all, and the admin gateway is
// loopback-only, mTLS-gated and rate limited to ten login attempts a minute
// (AR-8). This is a latent correctness bug on a path that is hard to reach, not
// a remote lockout primitive, and the report ranks it that way.
//
// What makes it worth fixing anyway is that the failure is silent and
// misattributed: the audit record says the admin got their password wrong.
func TestArgon2Attack_AdminLoginCountsOverloadAsWrongPassword(t *testing.T) {
	// Counting the guards is load-independent and does not go stale the way a
	// copied snippet would.
	userPlane := countOverloadGuards(t, filepath.Join("..", "..", "internal", "service", "auth.go")) +
		countOverloadGuards(t, filepath.Join("..", "..", "internal", "handler", "auth.go"))
	adminPlane := countOverloadGuards(t, filepath.Join("..", "..", "internal", "adminapi", "auth.go"))

	t.Logf("ErrArgon2Overloaded guards: user plane %d, admin plane %d", userPlane, adminPlane)

	if userPlane == 0 {
		t.Fatal("no overload guards found in the user plane; the parser is wrong, not the code")
	}
	if adminPlane == 0 {
		t.Errorf("internal/adminapi/auth.go calls VerifyPassword and never checks for "+
			"ErrArgon2Overloaded, while the user plane checks it in %d places. An overload "+
			"is therefore treated as a wrong password: it increments the admin's failed "+
			"login counter, is audited as reason=\"wrong_password\", and after maxFailed "+
			"attempts locks the account via handleFailedLogin.", userPlane)
	}
}

// countOverloadGuards counts references to ErrArgon2Overloaded in a file.
func countOverloadGuards(t *testing.T, path string) int {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	n := 0
	ast.Inspect(file, func(node ast.Node) bool {
		if sel, ok := node.(*ast.SelectorExpr); ok && sel.Sel.Name == "ErrArgon2Overloaded" {
			n++
		}
		return true
	})
	return n
}

// The semaphore's sizing comment states the safety argument:
//
//	"Each operation allocates ~46 MiB; 4 concurrent = ~184 MiB peak.
//	 With 512 MiB pod memory, leaves ~328 MiB for Go runtime + heap"
//
// That is true for hashes vault42 issues, which are always m=47104,t=1,p=1. It
// is not true for hashes vault42 will VERIFY. parseArgon2Hash reads m, t and p
// out of the stored string and passes them to argon2.IDKey, capped at 128 MiB,
// 10 iterations and parallelism 4. Four concurrent verifications of a 128 MiB
// hash is 512 MiB, the entire documented pod budget, and the semaphore permits
// it by construction because it counts operations, not bytes.
//
// Reachability is the honest limit on this one: nothing in the product writes a
// non-spec hash. Registration, password change and reset all go through
// HashPassword, and the admin import API imports no password material. It takes
// a direct write to auth.users.password_hash. Ranked accordingly, but the
// safety argument in the comment is still false as written, and the fix is one
// line.
func TestArgon2Attack_VerifyHonorsParametersFarAboveTheSemaphoreBudget(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	body := base64.RawStdEncoding.EncodeToString(make([]byte, 32))

	// The maximum parseArgon2Hash accepts: 128 MiB, 10 passes, parallelism 4.
	worst := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", 128*1024, 10, 4, salt, body)
	spec := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", 47104, 1, 1, salt, body)

	measure := func(encoded string) (time.Duration, uint64) {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		valid, err := vaultcrypto.VerifyPassword("guess", encoded)
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatalf("VerifyPassword rejected %q: %v", encoded[:40], err)
		}
		if valid {
			t.Fatal("a random hash body verified")
		}
		return elapsed, after.TotalAlloc - before.TotalAlloc
	}

	specTime, specAlloc := measure(spec)
	worstTime, worstAlloc := measure(worst)

	t.Logf("spec  hash (m=47104,t=1,p=1): %v, %d MiB allocated", specTime, specAlloc/(1024*1024))
	t.Logf("worst hash (m=131072,t=10,p=4): %v, %d MiB allocated", worstTime, worstAlloc/(1024*1024))
	t.Logf("cost ratio: %.1fx time, %.1fx memory",
		float64(worstTime)/float64(specTime), float64(worstAlloc)/float64(specAlloc))
	t.Logf("%d concurrent worst-case verifications = %d MiB, against the %d MiB pod budget "+
		"the semaphore comment sizes for",
		vaultcrypto.Argon2MaxConcurrent(),
		uint64(vaultcrypto.Argon2MaxConcurrent())*worstAlloc/(1024*1024),
		512)

	// The failing assertion: the semaphore is documented as bounding peak
	// memory, and it does not, because it counts operations rather than cost.
	peakMiB := uint64(vaultcrypto.Argon2MaxConcurrent()) * worstAlloc / (1024 * 1024)
	if peakMiB > 184 {
		t.Errorf("the semaphore admits %d concurrent verifications whose peak is %d MiB, "+
			"but its sizing comment claims '4 concurrent = ~184 MiB peak' and budgets "+
			"against 512 MiB of pod memory. The bound holds only for hashes vault42 "+
			"issued itself; parseArgon2Hash accepts up to m=131072,t=10,p=4 from the "+
			"stored string.", vaultcrypto.Argon2MaxConcurrent(), peakMiB)
	}
}

// The parser's accepted parameter range, enumerated, so the report can state it
// exactly rather than approximately. Nothing here fails: it is the evidence for
// the finding above.
func TestArgon2Attack_ParameterBoundsAccepted(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	body := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	mk := func(m, iter, par int) string {
		return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, iter, par, salt, body)
	}

	for _, tc := range []struct {
		name       string
		hash       string
		wantAccept bool
	}{
		{"spec parameters", mk(47104, 1, 1), true},
		{"memory at the cap", mk(128*1024, 1, 1), true},
		{"memory over the cap", mk(128*1024+1, 1, 1), false},
		{"iterations at the cap", mk(47104, 10, 1), true},
		{"iterations over the cap", mk(47104, 11, 1), false},
		{"parallelism at the cap", mk(47104, 1, 4), true},
		{"parallelism over the cap", mk(47104, 1, 5), false},
		{"zero iterations", mk(47104, 0, 1), false},
		{"zero parallelism", mk(47104, 1, 0), false},
		{"memory below 8*parallelism", mk(8, 1, 4), false},
		{"everything at the cap", mk(128*1024, 10, 4), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := vaultcrypto.VerifyPassword("guess", tc.hash)
			accepted := err == nil
			if accepted != tc.wantAccept {
				t.Errorf("accepted=%v want=%v (err=%v)", accepted, tc.wantAccept, err)
			}
		})
	}
}

// The enumeration burn. A user that does not exist is verified against
// DummyHash so the response time matches a user that does. The substitution to
// the rotating hash happens before the semaphore is acquired, and the rotating
// hash always carries spec parameters, so the two paths should be
// indistinguishable. Measured rather than asserted from the code.
func TestArgon2Attack_MeasureUserExistsTimingGap(t *testing.T) {
	if testing.Short() || atkRaceDetector {
		t.Skip("timing measurement: meaningless under -race, skipped in -short")
	}

	realHash, err := vaultcrypto.HashPassword("the real user's password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	// Medians over an interleaved, alternating-order schedule. Means over a
	// fixed order are what produced a spurious 7% gap on the first attempt:
	// whichever arm runs first pays the cache and frequency-ramp cost, and a
	// mean lets a handful of scheduler outliers dominate.
	const runs = 41
	existing := make([]time.Duration, 0, runs)
	missing := make([]time.Duration, 0, runs)

	timeOne := func(hash string) time.Duration {
		start := time.Now()
		_, _ = vaultcrypto.VerifyPassword("attacker guess", hash)
		return time.Since(start)
	}

	for i := 0; i < runs; i++ {
		if i%2 == 0 {
			existing = append(existing, timeOne(realHash))
			missing = append(missing, timeOne(vaultcrypto.DummyHash))
		} else {
			missing = append(missing, timeOne(vaultcrypto.DummyHash))
			existing = append(existing, timeOne(realHash))
		}
	}

	medExisting := median(existing)
	medMissing := median(missing)
	gap := medExisting - medMissing
	if gap < 0 {
		gap = -gap
	}
	ratio := float64(gap) / float64(medExisting)

	t.Logf("existing user: median %v over %d runs", medExisting, len(existing))
	t.Logf("missing  user: median %v over %d runs", medMissing, len(missing))
	t.Logf("gap: %v (%.2f%% of the operation)", gap, ratio*100)

	// A gap worth exploiting over a network would have to survive jitter. Five
	// percent of a 35ms operation is well under the noise floor of any real
	// network path; the measured value is what the report quotes.
	if ratio > 0.05 {
		t.Errorf("user existence is distinguishable by timing: %v gap, %.1f%% of the "+
			"operation. The DummyHash burn is supposed to make these equal.", gap, ratio*100)
	}
}

// median sorts a copy and returns the middle sample.
func median(d []time.Duration) time.Duration {
	c := append([]time.Duration(nil), d...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}
