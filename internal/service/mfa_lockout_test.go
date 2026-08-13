package service

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/tests/mocks"
)

// Audit H2: repeated MFA failures must trip the per-account lockout (the same
// counter the password path uses), and a successful completion clears it.
func TestMFAVerifyLockout(t *testing.T) {
	ctx := context.Background()
	// The user repository is not optional here. Every cache implementation
	// reports a miss as an error, and the lockout check answers a cache error
	// from the durable failed-login count, so the very first call reads the user
	// table. NewAuthService always supplies the repository; a service built
	// without one is a shape production never has.
	s := &AuthService{cache: cache.NewMemoryCache(), users: &mocks.MockUserRepo{}}
	const uid = "user-mfa-lock"

	if s.MFAVerifyLocked(ctx, uid) {
		t.Fatal("fresh account should not be locked")
	}

	// lockoutThreshold (5) failures → locked.
	for i := 0; i < lockoutThreshold; i++ {
		s.RecordMFAFailure(ctx, uid, "1.2.3.4", "ua")
	}
	if !s.MFAVerifyLocked(ctx, uid) {
		t.Fatalf("account should be locked after %d MFA failures", lockoutThreshold)
	}

	// Successful MFA completion clears the counter.
	s.clearLockout(ctx, uid)
	if s.MFAVerifyLocked(ctx, uid) {
		t.Fatal("lockout should clear after success")
	}
}

// Below the threshold the account stays usable (no premature lockout).
func TestMFAVerifyLockout_BelowThreshold(t *testing.T) {
	ctx := context.Background()
	s := &AuthService{cache: cache.NewMemoryCache(), users: &mocks.MockUserRepo{}}
	const uid = "user-mfa-few"
	for i := 0; i < lockoutThreshold-1; i++ {
		s.RecordMFAFailure(ctx, uid, "1.2.3.4", "ua")
	}
	if s.MFAVerifyLocked(ctx, uid) {
		t.Fatalf("account should not lock below %d failures", lockoutThreshold)
	}
}

// With no cache, lockout falls back to the DB failed-login counter. A user under
// threshold is not locked; RecordMFAFailure is a safe no-op without a cache.
func TestMFAVerifyLocked_NilCacheDBFallback(t *testing.T) {
	s := &AuthService{users: &mocks.MockUserRepo{}} // nil cache, DB fallback
	if s.MFAVerifyLocked(context.Background(), "x") {
		t.Fatal("no-cache user under threshold must not report locked")
	}
	s.RecordMFAFailure(context.Background(), "x", "ip", "ua") // must not panic
}
