package service

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"sync"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// The refresh TTL says how long one token lives. The absolute session lifetime
// says how long the family may live, however often it rotates. Where the two
// disagree the shorter one has to win, or the bound is advisory.

func TestIssueTokenPair_ClampsANewFamilyToTheAbsoluteLifetime(t *testing.T) {
	svc, _ := newTestTokenService(t)
	svc.SetMaxSessionLifetime(30 * time.Minute)

	before := time.Now()
	pair, err := svc.IssueTokenPair("u-1", []string{"user"}, []string{"read"}, "", "fp", "", false)
	if err != nil {
		t.Fatalf("IssueTokenPair: %v", err)
	}

	if remaining := pair.RefreshExpAt.Sub(before); remaining > 31*time.Minute {
		t.Errorf("refresh expiry is %v out, want no more than the 30m bound: the first token already outlives the session", remaining)
	}
}

// remember_me asks for the longest window in the system, so it is the one most
// likely to walk past a short bound.
func TestIssueTokenPair_ClampsRememberMeToTheAbsoluteLifetime(t *testing.T) {
	svc, _ := newTestTokenService(t)
	svc.SetMaxSessionLifetime(24 * time.Hour)

	before := time.Now()
	pair, err := svc.IssueTokenPair("u-1", []string{"user"}, []string{"read"}, "", "fp", "", true)
	if err != nil {
		t.Fatalf("IssueTokenPair: %v", err)
	}

	if remaining := pair.RefreshExpAt.Sub(before); remaining > 25*time.Hour {
		t.Errorf("remember-me refresh expiry is %v out, want no more than the 24h bound", remaining)
	}
}

func TestIssueTokenPair_LeavesTheRefreshTTLAloneWhenTheBoundIsLonger(t *testing.T) {
	svc, _ := newTestTokenService(t)
	svc.SetMaxSessionLifetime(90 * 24 * time.Hour)

	before := time.Now()
	pair, err := svc.IssueTokenPair("u-1", []string{"user"}, []string{"read"}, "", "fp", "", false)
	if err != nil {
		t.Fatalf("IssueTokenPair: %v", err)
	}

	if remaining := pair.RefreshExpAt.Sub(before); remaining < 6*24*time.Hour {
		t.Errorf("refresh expiry is only %v out; a far-off bound must not shorten the ordinary 7d TTL", remaining)
	}
}

func TestIssueRotatedPair_ClampsToTheFamilyDeadline(t *testing.T) {
	const maxLifetime = 7 * 24 * time.Hour
	svc, _ := newTestTokenService(t)
	svc.SetMaxSessionLifetime(maxLifetime)

	origin := time.Now().Add(-maxLifetime + 5*time.Minute)
	pair, err := svc.IssueRotatedPair("u-1", []string{"user"}, []string{"read"}, "", "fp", "fam-1", origin)
	if err != nil {
		t.Fatalf("IssueRotatedPair: %v", err)
	}

	deadline := origin.Add(maxLifetime)
	if pair.RefreshExpAt.After(deadline) {
		t.Errorf("rotated refresh expiry %v is past the family deadline %v; rotation renewed the session's own bound", pair.RefreshExpAt, deadline)
	}
	if pair.FamilyID != "fam-1" {
		t.Errorf("FamilyID = %q, want the family being rotated", pair.FamilyID)
	}
}

// A zero origin is the "age unknown" signal. Clamping it would date every session
// to the epoch and expire the whole estate, so the contract is that the caller
// rejects instead — which AuthService.Refresh does.
func TestIssueRotatedPair_AZeroOriginDoesNotClamp(t *testing.T) {
	svc, _ := newTestTokenService(t)
	svc.SetMaxSessionLifetime(7 * 24 * time.Hour)

	before := time.Now()
	pair, err := svc.IssueRotatedPair("u-1", []string{"user"}, []string{"read"}, "", "fp", "fam-1", time.Time{})
	if err != nil {
		t.Fatalf("IssueRotatedPair: %v", err)
	}

	if pair.RefreshExpAt.Before(before) {
		t.Errorf("refresh expiry %v is in the past; a zero origin was treated as the epoch", pair.RefreshExpAt)
	}
}

func TestMaxSessionLifetime_DefaultsToUnbounded(t *testing.T) {
	svc, _ := newTestTokenService(t)
	if got := svc.MaxSessionLifetime(); got != 0 {
		t.Errorf("MaxSessionLifetime = %v, want 0: the bound must be opt-in at the service and set from config", got)
	}
}

// A rotated-out signing key is spent secret material that would otherwise sit in
// the heap for the life of the process. Wiping it is only sound because signing
// holds the read lock, so acquiring the write lock drains every signer first.

func TestUpdateSigningKey_WipesTheKeyItRotatesOut(t *testing.T) {
	svc, old := newTestTokenService(t)

	next, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	svc.UpdateSigningKey(next, testKID2)

	if old.D.Sign() != 0 {
		t.Error("the private exponent of the rotated-out key is still in memory")
	}
	for i, p := range old.Primes {
		if p.Sign() != 0 {
			t.Errorf("prime %d of the rotated-out key is still in memory", i)
		}
	}
	for name, v := range map[string]*big.Int{
		"Dp": old.Precomputed.Dp, "Dq": old.Precomputed.Dq, "Qinv": old.Precomputed.Qinv,
	} {
		if v != nil && v.Sign() != 0 {
			t.Errorf("precomputed %s of the rotated-out key is still in memory", name)
		}
	}
	// The modulus is public and a JWKS may still publish it for tokens the key
	// already signed, so it must survive.
	if old.N.Sign() == 0 {
		t.Error("the public modulus was wiped; already-issued tokens become unverifiable")
	}
}

func TestUpdateSigningKey_RotatingToTheSameKeyDoesNotWipeIt(t *testing.T) {
	svc, key := newTestTokenService(t)

	svc.UpdateSigningKey(key, testKID2)

	if key.D.Sign() == 0 {
		t.Fatal("the live signing key was wiped; the service can no longer sign")
	}
	if _, err := svc.IssueChallengeToken("u-1", "fp"); err != nil {
		t.Fatalf("signing after a no-op rotation failed: %v", err)
	}
}

// The wipe and the lock discipline are one change: a signer that read the key
// pointer and then signed outside the lock would work on half-zeroed values and
// mint tokens that do not verify. This is the test that would catch that, and it
// is worth running under -race.
func TestUpdateSigningKey_ConcurrentSigningStaysValid(t *testing.T) {
	svc, first := newTestTokenService(t)

	next, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]*rsa.PublicKey{
		testKID1: &first.PublicKey,
		testKID2: &next.PublicKey,
	}

	var wg sync.WaitGroup
	tokens := make(chan string, 128)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				tok, err := svc.IssueChallengeToken("u-1", "fp")
				if err != nil {
					t.Errorf("IssueChallengeToken: %v", err)
					return
				}
				tokens <- tok
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		svc.UpdateSigningKey(next, testKID2)
	}()
	wg.Wait()
	close(tokens)

	for tok := range tokens {
		claims, err := vaultcrypto.ParseAndValidate(tok, func(token *vjwt.Token) (interface{}, error) {
			kid, _ := token.Header["kid"].(string)
			pub, ok := keys[kid]
			if !ok {
				t.Errorf("token signed with unknown kid %q", kid)
				return nil, vjwt.ErrTokenUnverifiable
			}
			return pub, nil
		}, "test-issuer", "test-audience")
		if err != nil {
			t.Fatalf("a token minted across a key rotation does not verify: %v", err)
		}
		if claims.Subject != "u-1" {
			t.Errorf("subject = %q, want u-1", claims.Subject)
		}
	}
}
