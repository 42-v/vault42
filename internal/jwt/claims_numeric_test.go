package jwt

import (
	"errors"
	"testing"
	"time"
)

// TestMapClaimsReadsAnExpOfZeroAsExpiredNotAsAbsent pins the difference between
// a claim that is missing and a claim whose value is the epoch.
//
// mapNumericDate returned nil for both, and validateClaims reads nil as "this
// token carries no expiry" and skips the expiry check entirely. So a payload
// saying exp 0, which is 1970 and the most expired a token can be, validated as
// a token that never expires. RegisteredClaims, parsing the same payload into a
// *NumericDate, calls it expired. Two claim types disagreeing about the same
// bytes is how a token rejected on one code path gets accepted on another.
//
// The live consumer of MapClaims is oauth2.VerifyIDToken, which also passes
// WithExpirationRequired and so turns the nil into a missing-claim rejection.
// That is one option away from a bearer identity with no expiry at all, and the
// package's own contract already says ErrTokenExpired covers an exp at or
// before now.
func TestMapClaimsReadsAnExpOfZeroAsExpiredNotAsAbsent(t *testing.T) {
	claims := MapClaims{"sub": "alice", "exp": float64(0)}

	got := claims.GetExpirationTime()
	if got == nil {
		t.Fatal("exp 0 read back as no expiry; a token stamped 1970 would never expire")
	}
	if !got.Equal(time.Unix(0, 0)) {
		t.Fatalf("exp 0 read back as %v, want the epoch", got.Time)
	}

	if err := validateClaims(claims, &validationConfig{}); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("validateClaims: err = %v, want ErrTokenExpired", err)
	}
}

// TestMapClaimsStillReportsAnAbsentExpAsAbsent is the counterweight. If the
// presence check regressed into always returning a date, a token with no exp
// would read as expired at the epoch, and WithExpirationRequired would stop
// being able to tell the two apart, so the required-claim error would never fire
// again.
func TestMapClaimsStillReportsAnAbsentExpAsAbsent(t *testing.T) {
	claims := MapClaims{"sub": "alice"}

	if got := claims.GetExpirationTime(); got != nil {
		t.Fatalf("absent exp read back as %v, want nil", got.Time)
	}
	if err := validateClaims(claims, &validationConfig{}); err != nil {
		t.Fatalf("a token with no exp and no requirement must validate: %v", err)
	}
	err := validateClaims(claims, &validationConfig{requireExp: true})
	if !errors.Is(err, ErrTokenRequiredClaimMissing) {
		t.Fatalf("with requireExp: err = %v, want ErrTokenRequiredClaimMissing", err)
	}
}

// TestMapClaimsReadsANotBeforeOfZeroAsAlreadyReached covers the same
// presence-versus-zero split on nbf and iat. Both directions are harmless on
// their own, but leaving one getter zero-blind and the others not is how the
// next reader concludes the blindness was deliberate somewhere it is not.
func TestMapClaimsReadsANotBeforeOfZeroAsAlreadyReached(t *testing.T) {
	claims := MapClaims{"sub": "alice", "nbf": float64(0), "iat": float64(0)}

	nbf := claims.GetNotBefore()
	if nbf == nil || !nbf.Equal(time.Unix(0, 0)) {
		t.Fatalf("nbf 0 read back as %v, want the epoch", nbf)
	}
	iat := claims.GetIssuedAt()
	if iat == nil || !iat.Equal(time.Unix(0, 0)) {
		t.Fatalf("iat 0 read back as %v, want the epoch", iat)
	}
	if err := validateClaims(claims, &validationConfig{verifyIat: true}); err != nil {
		t.Fatalf("an epoch nbf and iat are both in the past and must validate: %v", err)
	}
}
