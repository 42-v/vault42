package service

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/dpop"
)

// The two bindings were built independently and both changed the same issuance
// signatures, so a merge could keep either one and still compile: dropping the
// AuthContext argument leaves a DPoP-bound token that says nothing about the
// login, and dropping ctx leaves a described login nobody can constrain to a key.
// Each feature's own tests pass in that state, because each only asserts its own
// half. This asserts they land on one token together.
func TestOneTokenCarriesBothTheProofBindingAndTheAuthContext(t *testing.T) {
	svc, key := newTestTokenService(t)
	ctx := dpop.WithThumbprint(context.Background(), testJKT)

	at := time.Unix(1_700_000_000, 0)
	auth := NewAuthContext(at, []string{MethodPassword, MethodTOTP}, false)

	pair, err := svc.IssueTokenPairWithAuth(ctx, "user-1", []string{"user"}, []string{"read"}, "client-1", "fp", "", false, auth)
	if err != nil {
		t.Fatalf("IssueTokenPairWithAuth: %v", err)
	}
	claims := parseTestClaims(t, pair.AccessToken, key)

	if claims.Confirmation == nil || claims.Confirmation.JKT != testJKT {
		t.Errorf("cnf.jkt = %+v, want %q: the DPoP binding was dropped from the authenticated path",
			claims.Confirmation, testJKT)
	}
	if claims.ACR != "urn:vault42:aal:2" {
		t.Errorf("acr = %q, want urn:vault42:aal:2: the authentication context was dropped", claims.ACR)
	}
	if want := []string{"pwd", "otp", "mfa"}; !slices.Equal(claims.AMR, want) {
		t.Errorf("amr = %v, want %v", claims.AMR, want)
	}
	if claims.AuthTime != at.Unix() {
		t.Errorf("auth_time = %d, want %d", claims.AuthTime, at.Unix())
	}
}

// A rotation keeps the sender constraint and keeps auth_time, and still declines
// to restate acr and amr for an authentication it did not observe. The two
// designs meet here: the rotation reasoning is the AuthContext half, the binding
// is the ctx half, and a merge that kept only one of them loses a line of this.
func TestARotationKeepsTheBindingAndTheOriginalAuthTimeWithoutRestatingFactors(t *testing.T) {
	svc, key := newTestTokenService(t)
	ctx := dpop.WithThumbprint(context.Background(), testJKT)

	origin := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	pair, err := svc.IssueRotatedPair(ctx, "user-1", []string{"user"}, []string{"read"}, "", "fp", "family-1", origin)
	if err != nil {
		t.Fatalf("IssueRotatedPair: %v", err)
	}
	claims := parseTestClaims(t, pair.AccessToken, key)

	if claims.Confirmation == nil || claims.Confirmation.JKT != testJKT {
		t.Errorf("a rotated token lost cnf.jkt (%+v); a client could downgrade out of "+
			"sender-constraining by refreshing", claims.Confirmation)
	}
	if claims.AuthTime != origin.Unix() {
		t.Errorf("auth_time = %d, want the family origin %d", claims.AuthTime, origin.Unix())
	}
	if claims.ACR != "" || len(claims.AMR) != 0 {
		t.Errorf("rotation asserted acr=%q amr=%v; a refresh observes no factors", claims.ACR, claims.AMR)
	}
}

// The challenge token is the one credential both features had to reach: it is
// sender-constrained like every other token, and it carries the factors already
// completed so the second-factor verify can state the full combination.
func TestAChallengeTokenCarriesBothTheBindingAndThePriorFactors(t *testing.T) {
	svc, key := newTestTokenService(t)
	ctx := dpop.WithThumbprint(context.Background(), testJKT)

	token, err := svc.IssueChallengeToken(ctx, "user-1", "fp", MethodPassword)
	if err != nil {
		t.Fatalf("IssueChallengeToken: %v", err)
	}
	claims := parseTestClaims(t, token, key)

	if claims.Confirmation == nil || claims.Confirmation.JKT != testJKT {
		t.Errorf("the 2FA challenge token is not bound (%+v)", claims.Confirmation)
	}
	if want := []string{MethodPassword}; !slices.Equal(claims.Factors, want) {
		t.Errorf("factors = %v, want %v: CompleteMFALogin reads these to name the full "+
			"combination on the token it issues", claims.Factors, want)
	}
}
