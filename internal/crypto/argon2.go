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
	// Each operation allocates ~46 MiB; 4 concurrent = ~184 MiB peak.
	// With 512 MiB pod memory, leaves ~328 MiB for Go runtime + heap + connections.
	argon2MaxConcurrent = 4

	// argon2AcquireTimeout is how long to wait for the semaphore before rejecting.
	argon2AcquireTimeout = 5 * time.Second
)

// argon2Sem limits concurrent argon2id operations to prevent memory exhaustion.
// Buffered channel acts as a counting semaphore.
var argon2Sem = make(chan struct{}, argon2MaxConcurrent)

// argon2Active tracks current concurrent argon2 operations for observability.
var argon2Active atomic.Int64

// argon2Rejected tracks total rejected requests for observability.
var argon2Rejected atomic.Int64

// ErrArgon2Overloaded is returned when the argon2id semaphore cannot be
// acquired within the timeout, indicating the server is under heavy load.
var ErrArgon2Overloaded = errors.New("argon2: too many concurrent hashing operations")

// acquireArgon2 blocks until a semaphore slot is available or the timeout expires.
func acquireArgon2() error {
	ctx, cancel := context.WithTimeout(context.Background(), argon2AcquireTimeout)
	defer cancel()
	select {
	case argon2Sem <- struct{}{}:
		n := argon2Active.Add(1)
		if n >= int64(argon2MaxConcurrent) {
			log.Printf("argon2: semaphore at capacity (%d/%d active)", n, argon2MaxConcurrent)
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
	go rotateDummyHashLoop()
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

// rotateDummyHashLoop regenerates the dummy hash on a slow timer for the life
// of the process so its salt and memory pattern are not deterministic per
// process.
func rotateDummyHashLoop() {
	for range time.Tick(dummyHashRotationPeriod) {
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
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

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
	if params.memory > 128*1024 { // 128 MiB maximum
		return nil, nil, params, errors.New("argon2: memory exceeds maximum (128 MiB)")
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
