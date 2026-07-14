package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// Argon2id is deliberately memory-hard: each hash costs ~46MB. That is what makes it a
// good password hash and also what makes it a denial-of-service primitive pointed at
// yourself — an unbounded flood of logins would have the process allocating gigabytes
// and being OOM-killed. The semaphore caps concurrency at 4 and rejects callers that
// cannot get a slot within the timeout, which is what turns "the server dies" into "the
// server answers 503".
//
// That rejection path had no test. Both entry points must take it, and both must return
// ErrArgon2Overloaded rather than a nil error with an empty hash — a caller that read
// ("", nil) from HashPassword would store an empty password hash, and one that read
// (false, nil) from VerifyPassword would simply deny a legitimate login.
//
// The semaphore is saturated here and both calls are made concurrently, so the test
// costs one acquire-timeout rather than two.
func TestArgon2_OverloadedRejectsBothEntryPoints(t *testing.T) {
	for i := 0; i < argon2MaxConcurrent; i++ {
		argon2Sem <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < argon2MaxConcurrent; i++ {
			<-argon2Sem
		}
	})

	var wg sync.WaitGroup
	wg.Add(2)

	var hashErr, verifyErr error
	var hash string
	var valid bool

	go func() {
		defer wg.Done()
		hash, hashErr = HashPassword("correct horse battery staple")
	}()
	go func() {
		defer wg.Done()
		valid, verifyErr = VerifyPassword("correct horse battery staple", DummyHash)
	}()

	wg.Wait()

	if !errors.Is(hashErr, ErrArgon2Overloaded) {
		t.Errorf("HashPassword err = %v, want ErrArgon2Overloaded", hashErr)
	}
	if hash != "" {
		t.Errorf("a rejected HashPassword returned a hash (%q) — it would be stored as the user's password", hash)
	}
	if !errors.Is(verifyErr, ErrArgon2Overloaded) {
		t.Errorf("VerifyPassword err = %v, want ErrArgon2Overloaded", verifyErr)
	}
	if valid {
		t.Error("a rejected VerifyPassword returned valid=true — overload would authenticate anyone")
	}
}

// The decoded hash length is fed to argon2.IDKey as the output size. A hash claiming a
// length outside the sane range must be rejected rather than passed through: it is
// attacker-controlled if a bad hash ever reaches the table, and the value is converted
// to uint32 on the way in.
func TestVerifyPassword_RejectsImplausibleHashLength(t *testing.T) {
	oversized := base64.RawStdEncoding.EncodeToString(make([]byte, 65)) // > 64 bytes
	encoded := fmt.Sprintf("$argon2id$v=19$m=47104,t=1,p=1$%s$%s",
		base64.RawStdEncoding.EncodeToString(make([]byte, argon2SaltLen)),
		oversized,
	)

	valid, err := VerifyPassword("whatever", encoded)
	if err == nil {
		t.Error("a hash with an implausible length was accepted for verification")
	}
	if valid {
		t.Error("verification against a malformed hash returned valid=true")
	}
}
