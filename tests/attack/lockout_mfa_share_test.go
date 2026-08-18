package attack

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/httputil"
)

// =============================================================================
// The second factor and the password share a lockout, and the sharing has to be
// keyed on the source or it becomes the weapon.
//
// Audit H2: the per-IP rate limit alone is defeated by rotating addresses, so
// without a per-account gate on MFA verify a six-digit second factor is
// brute-forceable inside the challenge window by an attacker who already holds
// the password. RecordMFAFailure and MFAVerifyLocked are that gate, and they are
// the same two counters the password path advances — an attacker cannot get a
// fresh budget by switching from guessing passwords to guessing codes.
//
// The counter used to be keyed on the user id alone, which made the shared
// counter a liability: MFA failures an attacker generated from their own address
// denied the account to its owner, so the victim could not climb out with the
// second factor they held. Sharing is right; sharing a key that ignores the
// source was not. Nothing in this repository attacked the pair together.
// =============================================================================

// TestMFALockout_SharesTheLoginCounterPerSource drives failures through the MFA
// gate and reads the answer at the login path, and then the reverse, so the two
// entry points cannot silently stop agreeing about what a failure is.
func TestMFALockout_SharesTheLoginCounterPerSource(t *testing.T) {
	limit := atkPerSourceLimit(t, atkSearchCeiling)

	const (
		email      = "mfa-share@example.com"
		attackerIP = "198.51.100.120"
		victimIP   = "203.0.113.120"
	)

	t.Run("mfa failures close the password path for that source", func(t *testing.T) {
		a := newAtkLockout(t)
		uid := a.account(email)
		ctx := httputil.WithClientIP(context.Background(), attackerIP)

		for i := 0; i < limit; i++ {
			a.svc.RecordMFAFailure(ctx, uid, attackerIP, "AttackAgent")
		}
		if a.canReach(t, email, attackerIP) == atkAdmitted {
			t.Errorf("%d failed second-factor attempts from %s left the password path open from the "+
				"same address. An attacker who exhausts the MFA budget just switches back to guessing "+
				"passwords on a fresh counter.", limit, attackerIP)
		}
		if !a.svc.MFAVerifyLocked(ctx, uid) {
			t.Errorf("%d failed second-factor attempts did not lock the MFA gate itself; the second "+
				"factor is brute-forceable within the challenge window", limit)
		}
	})

	t.Run("password failures close the mfa path for that source", func(t *testing.T) {
		a := newAtkLockout(t)
		uid := a.account(email)
		ctx := httputil.WithClientIP(context.Background(), attackerIP)

		for i := 0; i < limit; i++ {
			a.guess(email, attackerIP)
		}
		if !a.svc.MFAVerifyLocked(ctx, uid) {
			t.Errorf("%d wrong passwords from %s left the MFA gate open to the same address; the two "+
				"paths do not share a budget and an attacker gets both in full", limit, attackerIP)
		}
	})

	t.Run("mfa failures from an attacker do not lock the owner out", func(t *testing.T) {
		a := newAtkLockout(t)
		uid := a.account(email)
		attackerCtx := httputil.WithClientIP(context.Background(), attackerIP)
		victimCtx := httputil.WithClientIP(context.Background(), victimIP)

		for i := 0; i < limit+1; i++ {
			a.svc.RecordMFAFailure(attackerCtx, uid, attackerIP, "AttackAgent")
		}
		if a.canReach(t, email, victimIP) != atkAdmitted {
			t.Errorf("%d second-factor failures at %s locked the owner out of their own account at %s. "+
				"This is the cheapest denial of service in the product: no credential, no valid "+
				"session, just a known email address and a handful of requests.", limit+1, attackerIP, victimIP)
		}
		if a.svc.MFAVerifyLocked(victimCtx, uid) {
			t.Errorf("the MFA gate was closed to %s by failures at %s, so the owner cannot escape with "+
				"the second factor they hold either", victimIP, attackerIP)
		}
	})
}
