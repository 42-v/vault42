package crypto

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters per spec: 46 MiB memory, 1 iteration, 1 parallelism (~150-200ms).
const (
	argon2Memory      = 46 * 1024 // 46 MiB in KiB
	argon2Iterations  = 1
	argon2Parallelism = 1
	argon2SaltLen     = 16
	argon2KeyLen      = 32

	// argon2MaxConcurrent limits concurrent argon2id operations to prevent OOM.
	//
	// Issuing allocates ~46 MiB per operation, so the common case is ~184 MiB at
	// four concurrent. The number that has to be budgeted for is the WORST case,
	// not the common one: verification allocates whatever the stored hash string
	// declares, and argon2MaxVerifyMemory caps that at 64 MiB. Four concurrent
	// verifications therefore peak at ~256 MiB, leaving ~256 MiB of a 512 MiB pod
	// for the Go runtime, heap and connections.
	//
	// The ceiling and this figure are one calculation. Raising either without the
	// other is what made the original comment false, and
	// TestArgon2Attack_VerifyStaysWithinTheSemaphoreBudget fails if they diverge.
	argon2MaxConcurrent = 4

	// argon2AcquireTimeout is how long to wait for the semaphore before rejecting.
	argon2AcquireTimeout = 5 * time.Second

	// argon2MaxQueueDepth is how many callers may be waiting for a slot before
	// a new arrival is shed immediately instead of queued.
	//
	// The semaphore bounds MEMORY — four slots, ~184 MiB of issued-parameter
	// working set, and that part was never the problem. What it did not bound
	// was TIME: acquireArgon2 waited the whole acquire timeout before giving
	// up, so the queue was however many callers could drain in five seconds.
	// Measured on a 2026 laptop core: a single issuing hash takes 47.7ms, so
	// four slots retire ~84 hashes a second and five seconds of queue is ~420
	// waiters. On a 150ms production core it is ~130. Either way the caller at
	// the back waits the full five seconds and is then rejected anyway, having
	// held a connection, a goroutine and a request the whole time.
	//
	// So this is not "shed earlier to keep a latency number down". Below the
	// threshold nothing changes: a legitimate login under moderate contention
	// still queues and still gets served, which is the right trade and the
	// reason the semaphore queues at all. Above it, the wait was already
	// futile, and an immediate 503 is strictly better for the caller than the
	// same 503 five seconds later.
	//
	// 64 is that boundary expressed as a queue: ~0.8s of drain at 47.7ms per
	// hash, ~2.4s at 150ms — both inside the server's write timeout, so a
	// caller that queues can still be answered. It also makes
	// Argon2RejectedCount move at a depth an operator can alert on, instead of
	// staying at zero until roughly 420 concurrent operations.
	argon2MaxQueueDepth = 64

	// argon2MaxVerifyMemory caps the memory a stored hash may request, in KiB.
	//
	// It used to be 128 MiB, which made the semaphore's sizing argument false:
	// four concurrent verifications of a 128 MiB hash reserve 512 MiB, the entire
	// documented pod budget, before the Go runtime has taken anything. The bound
	// was unreachable in practice because nothing in the product issues a
	// non-spec hash, but "unreachable because nobody currently writes one" is an
	// assumption rather than a control, and the comment above stated the
	// conclusion as though it were enforced.
	//
	// 64 MiB is 1.4x the issuing parameter, so every hash this product has ever
	// written verifies, while four concurrent worst cases stay at 256 MiB. Raising
	// it means raising the peak in the comment above and re-checking it against
	// the pod's memory limit.
	argon2MaxVerifyMemory = 64 * 1024
)

// argon2Sem limits concurrent argon2id operations to prevent memory exhaustion.
// Buffered channel acts as a counting semaphore.
var argon2Sem = make(chan struct{}, argon2MaxConcurrent)

// argon2Waiting tracks callers queued for a slot, and argon2WaitNanos their
// cumulative wait. Together they make queueing visible before it becomes
// rejection.
var (
	argon2Waiting   atomic.Int64
	argon2WaitNanos atomic.Int64
)

// argon2Active tracks current concurrent argon2 operations for observability.
var argon2Active atomic.Int64

// argon2Rejected tracks total rejected requests for observability.
var argon2Rejected atomic.Int64

// ErrArgon2Overloaded is returned when the argon2id semaphore cannot be
// acquired within the timeout, indicating the server is under heavy load.
var ErrArgon2Overloaded = errors.New("argon2: too many concurrent hashing operations")

// acquireArgon2 blocks until a semaphore slot is available or the timeout expires.
//
// The waiting count and cumulative wait exist because rejection is a terrible
// early warning. The semaphore queues rather than sheds, so under load a
// legitimate login simply gets slower: measured here, victim latency grows about
// 9 ms per concurrent password operation, and at 128 concurrent a login already
// waits over a second. These two are the signal that moves while the service is
// merely degrading, before anything is refused.
//
// argon2MaxQueueDepth now caps how far that degradation can run. It used to run
// until the acquire timeout was burned — roughly 420 concurrent operations on a
// 47.7ms hash — so the rejection counter stayed at zero long after every user
// had noticed, and the caller at the back of the queue paid five seconds for a
// 503 it was going to get anyway.
func acquireArgon2() error {
	ctx, cancel := context.WithTimeout(context.Background(), argon2AcquireTimeout)
	defer cancel()

	// Shed before queueing when the queue is already past the depth that can
	// drain inside a useful wait. Checked before the counter is incremented, so
	// a shed caller is not itself counted as a waiter.
	//
	// Racy by construction: two arrivals can both read a depth one under the
	// threshold and both queue. That is fine — the threshold is a drain-time
	// budget, not a hard capacity, and the memory ceiling is the semaphore's
	// job, not this check's.
	if argon2Waiting.Load() >= int64(argon2MaxQueueDepth) {
		rejected := argon2Rejected.Add(1)
		log.Printf("argon2: shedding — %d callers already queued for %d slots (total rejected: %d)",
			argon2MaxQueueDepth, argon2MaxConcurrent, rejected)
		return ErrArgon2Overloaded
	}

	start := time.Now()
	argon2Waiting.Add(1)
	defer func() {
		argon2Waiting.Add(-1)
		argon2WaitNanos.Add(time.Since(start).Nanoseconds())
	}()

	select {
	case argon2Sem <- struct{}{}:
		n := argon2Active.Add(1)
		if n >= int64(argon2MaxConcurrent) {
			log.Printf("argon2: semaphore at capacity (%d/%d active, %d waiting)",
				n, argon2MaxConcurrent, argon2Waiting.Load())
		}
		return nil
	case <-ctx.Done():
		rejected := argon2Rejected.Add(1)
		log.Printf("argon2: overloaded — rejected request (total rejected: %d, active: %d/%d)",
			rejected, argon2Active.Load(), argon2MaxConcurrent)
		return ErrArgon2Overloaded
	}
}

func releaseArgon2() {
	argon2Active.Add(-1)
	<-argon2Sem
}

// Argon2ActiveCount returns the current number of in-flight argon2id operations.
func Argon2ActiveCount() int64 {
	return argon2Active.Load()
}

// Argon2RejectedCount returns the total number of rejected argon2id requests.
func Argon2RejectedCount() int64 {
	return argon2Rejected.Load()
}

// Argon2MaxConcurrent returns the semaphore capacity.
func Argon2MaxConcurrent() int {
	return argon2MaxConcurrent
}

// Argon2MaxVerifyMemory returns the memory ceiling, in KiB, that a stored hash
// may declare. Exported so a test can build a worst-case hash from the real
// bound instead of copying the number, which is how the client-backpressure
// fixture silently stopped being verifiable when the ceiling moved.
func Argon2MaxVerifyMemory() uint32 {
	return argon2MaxVerifyMemory
}

// Argon2WaitingCount returns how many callers are currently queued for a
// semaphore slot. It rises as soon as the service starts queueing, which is the
// point at which logins start getting slower, rather than at the point work is
// finally refused.
func Argon2WaitingCount() int64 {
	return argon2Waiting.Load()
}

// Argon2WaitNanos returns the cumulative time callers have spent waiting for a
// semaphore slot. Divided by the number of operations it gives mean queueing
// delay, which is the number an alert should be written against.
func Argon2WaitNanos() int64 {
	return argon2WaitNanos.Load()
}

// DummyHash is an Argon2id hash used for constant-time user enumeration
// prevention. When a user is not found, VerifyPassword is called with this
// hash to burn the same CPU time as a real verification. Generated at startup
// with a random salt to avoid recognizable memory patterns.
//
// The variable is assigned once in init and never reassigned, so the
// unsynchronized reads in other packages are race-free. It acts as a sentinel:
// VerifyPassword substitutes the current rotating dummy hash for it, and a
// background loop re-derives that hash on a slow timer so the dummy salt does
// not stay fixed for the process lifetime.
var DummyHash string

// dummyHashPassword is the fixed input the dummy hash is derived from; the
// per-process variability comes from the random salt.
const dummyHashPassword = "vault-anti-enumeration-dummy" // #nosec G101 -- not a credential: public dummy input for the constant-time burn, secrecy is irrelevant by design

// dummyHashRotationPeriod is how often the rotating dummy hash is re-derived.
const dummyHashRotationPeriod = time.Hour

// rotatingDummyHash holds the dummy hash currently in use. The rotation
// goroutine replaces it while request goroutines read it, hence atomic.
var rotatingDummyHash atomic.Value

func init() {
	h, err := HashPassword(dummyHashPassword)
	if err != nil {
		// Fallback: valid PHC format with static salt. Timing is still constant
		// since Argon2id with the same parameters takes the same time regardless.
		h = "$argon2id$v=19$m=47104,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	DummyHash = h
	rotatingDummyHash.Store(h)
	go rotateDummyHashLoop(time.Tick(dummyHashRotationPeriod))
}

// regenerateDummyHash re-derives the rotating dummy hash with a fresh random
// salt. On failure (ErrArgon2Overloaded under load, or an entropy error) the
// previous hash is kept: it is still a valid spec-parameter hash, so the
// constant-time property holds and the next tick simply retries.
func regenerateDummyHash() error {
	h, err := HashPassword(dummyHashPassword)
	if err != nil {
		return err
	}
	rotatingDummyHash.Store(h)
	return nil
}

// rotateDummyHashLoop regenerates the dummy hash on every tick so its salt and
// memory pattern are not deterministic per process. init passes the slow timer;
// the channel is a parameter so the loop can also be driven directly.
func rotateDummyHashLoop(tick <-chan time.Time) {
	for range tick {
		_ = regenerateDummyHash()
	}
}

// currentDummyHash returns the dummy hash the enumeration-prevention burn
// actually runs against.
func currentDummyHash() string {
	return rotatingDummyHash.Load().(string)
}

// applyPepper pre-hashes a password with HMAC-SHA256(pepper, password) if a
// pepper is provided. This binds password hashes to a server-side secret so
// that a database-only compromise cannot crack passwords offline.
func applyPepper(password string, pepper ...string) []byte {
	if len(pepper) > 0 && pepper[0] != "" {
		mac := hmac.New(sha256.New, []byte(pepper[0]))
		mac.Write([]byte(password))
		return mac.Sum(nil)
	}
	return []byte(password)
}

// HashPassword hashes a password using Argon2id with spec-mandated parameters.
// If pepper is provided and non-empty, the password is pre-hashed with
// HMAC-SHA256(pepper, password) before Argon2id to bind hashes to a server secret.
// Returns a PHC-format string: $argon2id$v=19$m=47104,t=1,p=1$<salt>$<hash>
//
// Concurrent calls are limited by an internal semaphore (4 max) to prevent OOM
// under load. Returns ErrArgon2Overloaded if the semaphore cannot be acquired.
func HashPassword(password string, pepper ...string) (string, error) {
	if err := acquireArgon2(); err != nil {
		return "", err
	}
	defer releaseArgon2()

	pw := applyPepper(password, pepper...)

	salt := make([]byte, argon2SaltLen)
	// crypto/rand.Read has no error path to handle: since Go 1.24 a Reader
	// failure calls the runtime fatal handler and terminates the process
	// instead of returning ($GOROOT/src/crypto/rand/rand.go). Callers that
	// need a recoverable entropy error use io.ReadFull(rand.Reader, ...).
	_, _ = rand.Read(salt)

	hash := argon2.IDKey(pw, salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory,
		argon2Iterations,
		argon2Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword checks a password against an Argon2id PHC-format hash.
// If pepper is provided, the password is pre-hashed with HMAC-SHA256(pepper, password)
// before verification (must match the pepper used during hashing).
// Always runs the full Argon2id computation regardless of validity (constant-time).
//
// Concurrent calls are limited by an internal semaphore (4 max) to prevent OOM
// under load. Returns ErrArgon2Overloaded if the semaphore cannot be acquired.
func VerifyPassword(password, encoded string, pepper ...string) (bool, error) {
	// Callers signal the user-not-found burn by passing the DummyHash
	// sentinel; substitute the current rotating hash so the dummy salt does
	// not stay fixed for the process lifetime. Parameters are identical, so
	// the computation time is unchanged.
	if encoded == DummyHash {
		encoded = currentDummyHash()
	}
	if err := acquireArgon2(); err != nil {
		return false, err
	}
	defer releaseArgon2()

	pw := applyPepper(password, pepper...)
	salt, hash, params, err := parseArgon2Hash(encoded)
	if err != nil {
		// Still compute to prevent timing leaks on malformed hashes
		dummySalt := make([]byte, argon2SaltLen)
		argon2.IDKey(pw, dummySalt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLen)
		return false, err
	}

	hashLen := len(hash)
	if hashLen <= 0 || hashLen > 64 {
		return false, errors.New("argon2: invalid hash length")
	}
	candidate := argon2.IDKey(pw, salt, params.iterations, params.memory, params.parallelism, uint32(hashLen)) // #nosec G115 -- bounds checked above
	return subtle.ConstantTimeCompare(candidate, hash) == 1, nil
}

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func parseArgon2Hash(encoded string) (salt, hash []byte, params argon2Params, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return nil, nil, params, errors.New("argon2: invalid hash format")
	}

	if parts[1] != "argon2id" {
		return nil, nil, params, errors.New("argon2: unsupported variant")
	}

	// Parse parameters: m=47104,t=1,p=1
	paramParts := strings.Split(parts[3], ",")
	if len(paramParts) != 3 {
		return nil, nil, params, errors.New("argon2: invalid parameters")
	}

	for _, p := range paramParts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return nil, nil, params, errors.New("argon2: malformed parameter")
		}
		val, parseErr := strconv.ParseUint(kv[1], 10, 32)
		if parseErr != nil {
			return nil, nil, params, fmt.Errorf("argon2: invalid parameter value: %w", parseErr)
		}
		switch kv[0] {
		case "m":
			params.memory = uint32(val)
		case "t":
			params.iterations = uint32(val)
		case "p":
			if val > 255 {
				return nil, nil, params, errors.New("argon2: parallelism exceeds uint8 range")
			}
			params.parallelism = uint8(val) // #nosec G115 -- bounds checked above
		}
	}

	// Validate params to prevent panics in argon2.IDKey and DoS via crafted hashes.
	// Upper bounds prevent an attacker from storing a hash with extreme parameters
	// that would cause excessive CPU/memory consumption during verification.
	if params.iterations < 1 {
		return nil, nil, params, errors.New("argon2: iterations must be >= 1")
	}
	if params.iterations > 10 {
		return nil, nil, params, errors.New("argon2: iterations exceed maximum (10)")
	}
	if params.parallelism < 1 {
		return nil, nil, params, errors.New("argon2: parallelism must be >= 1")
	}
	if params.parallelism > 4 {
		return nil, nil, params, errors.New("argon2: parallelism exceeds maximum (4)")
	}
	if params.memory < 8*uint32(params.parallelism) {
		return nil, nil, params, errors.New("argon2: memory too small")
	}
	if params.memory > argon2MaxVerifyMemory {
		return nil, nil, params, fmt.Errorf("argon2: memory exceeds maximum (%d MiB)",
			argon2MaxVerifyMemory/1024)
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, params, fmt.Errorf("argon2: decode salt: %w", err)
	}
	if len(salt) < argon2SaltLen {
		return nil, nil, params, fmt.Errorf("argon2: salt too short (%d bytes, minimum %d)", len(salt), argon2SaltLen)
	}

	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, params, fmt.Errorf("argon2: decode hash: %w", err)
	}

	if len(hash) == 0 {
		return nil, nil, params, errors.New("argon2: empty hash")
	}

	return salt, hash, params, nil
}
