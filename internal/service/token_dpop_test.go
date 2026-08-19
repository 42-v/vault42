package service

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/dpop"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// The defect, stated as an invariant: cnf.jkt was declared on VaultClaims and
// assigned by nothing, so no token vault42 ever issued was sender-constrained.
// The DPoP middleware's thumbprint comparison was therefore unreachable, and any
// well-formed proof for any key passed — a proof of possession of nothing.
const testJKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

func parseTestClaims(t *testing.T, token string, key *rsa.PrivateKey) *vaultcrypto.VaultClaims {
	t.Helper()
	claims, err := vaultcrypto.ParseAndValidate(token, func(*vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, "test-issuer", "test-audience")
	if err != nil {
		t.Fatalf("parse issued token: %v", err)
	}
	return claims
}

func TestAnAccessTokenIssuedUnderAValidatedProofCarriesCnfJkt(t *testing.T) {
	svc, key := newTestTokenService(t)
	ctx := dpop.WithThumbprint(context.Background(), testJKT)

	pair, err := svc.IssueTokenPair(ctx, "user-1", []string{"user"}, []string{"read"}, "client-1", "fp", "", false)
	if err != nil {
		t.Fatalf("IssueTokenPair: %v", err)
	}

	claims := parseTestClaims(t, pair.AccessToken, key)
	if claims.Confirmation == nil {
		t.Fatal("the access token carries no cnf claim; nothing binds it to the key the caller proved, " +
			"so the middleware's thumbprint comparison never runs")
	}
	if claims.Confirmation.JKT != testJKT {
		t.Errorf("cnf.jkt = %q, want the proven key's thumbprint %q", claims.Confirmation.JKT, testJKT)
	}
}

// A rotation must not silently drop the binding: a refresh that returned an
// unbound token would let a client downgrade itself out of sender-constraining by
// refreshing, which is the same as not having it.
func TestARotatedPairKeepsTheBinding(t *testing.T) {
	svc, key := newTestTokenService(t)
	ctx := dpop.WithThumbprint(context.Background(), testJKT)

	pair, err := svc.IssueRotatedPair(ctx, "user-1", []string{"user"}, []string{"read"}, "", "fp", "family-1", time.Now())
	if err != nil {
		t.Fatalf("IssueRotatedPair: %v", err)
	}
	claims := parseTestClaims(t, pair.AccessToken, key)
	if claims.Confirmation == nil || claims.Confirmation.JKT != testJKT {
		t.Fatalf("a rotated access token lost its cnf.jkt (%+v)", claims.Confirmation)
	}
}

// The challenge token is what POST /auth/2fa/verify authenticates. Leaving it
// bearer-equivalent would put an unconstrained credential in the middle of an
// otherwise sender-constrained login.
func TestAChallengeTokenIssuedUnderAProofIsAlsoBound(t *testing.T) {
	svc, key := newTestTokenService(t)
	ctx := dpop.WithThumbprint(context.Background(), testJKT)

	token, err := svc.IssueChallengeToken(ctx, "user-1", "fp")
	if err != nil {
		t.Fatalf("IssueChallengeToken: %v", err)
	}
	claims := parseTestClaims(t, token, key)
	if claims.Confirmation == nil || claims.Confirmation.JKT != testJKT {
		t.Fatalf("the 2FA challenge token is not bound (%+v)", claims.Confirmation)
	}
}

// Every client that never sends a proof must keep getting an ordinary bearer
// token, or turning VAULT_DPOP_ENABLED on breaks the deployment.
func TestATokenIssuedWithoutAProofIsNotSenderConstrained(t *testing.T) {
	svc, key := newTestTokenService(t)

	pair, err := svc.IssueTokenPair(context.Background(), "user-1", []string{"user"}, nil, "", "fp", "", false)
	if err != nil {
		t.Fatalf("IssueTokenPair: %v", err)
	}
	claims := parseTestClaims(t, pair.AccessToken, key)
	if claims.Confirmation != nil {
		t.Fatalf("an access token issued with no proof carries cnf.jkt %q; the middleware would then "+
			"demand a proof the client has no key for", claims.Confirmation.JKT)
	}

	challenge, err := svc.IssueChallengeToken(context.Background(), "user-1", "fp")
	if err != nil {
		t.Fatalf("IssueChallengeToken: %v", err)
	}
	if c := parseTestClaims(t, challenge, key).Confirmation; c != nil {
		t.Errorf("a challenge token issued with no proof carries cnf.jkt %q", c.JKT)
	}
}
