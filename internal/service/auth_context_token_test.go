package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"slices"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// AR-21 / OIDC Core §2. AALForMethods existed but had no non-test caller, so
// the assurance level a login reached was computed nowhere and asserted
// nowhere. A relying party reading a vault42 access token could not tell a
// password-only session from one that cleared a hardware authenticator, which
// is what acr, amr and auth_time exist to say.
func TestAccessTokenCarriesTheAuthenticationContext(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := "aabbccdd-11223344"
	svc := NewTokenService(key, kid, "https://vault.test", "vault42", time.Hour, 24*time.Hour, 0)

	at := time.Unix(1_700_000_000, 0)
	auth := NewAuthContext(at, []string{MethodPassword, MethodWebAuthn}, true)

	pair, err := svc.IssueTokenPairWithAuth(context.Background(), "user-1", []string{"user"}, []string{"read"}, "", "fp", "", false, auth)
	if err != nil {
		t.Fatalf("IssueTokenPairWithAuth: %v", err)
	}

	claims := parseIssuedToken(t, pair.AccessToken, key, kid)
	if claims.ACR != "urn:vault42:aal:3" {
		t.Errorf("acr = %q, want urn:vault42:aal:3", claims.ACR)
	}
	if want := []string{"pwd", "hwk", "user", "mfa"}; !slices.Equal(claims.AMR, want) {
		t.Errorf("amr = %v, want %v", claims.AMR, want)
	}
	if claims.AuthTime != at.Unix() {
		t.Errorf("auth_time = %d, want %d", claims.AuthTime, at.Unix())
	}
}

// A rotation cannot re-run the authentication, so it carries the instant the
// family was created — which is the authentication event — and omits acr and
// amr rather than restating factors it did not observe.
func TestRotatedTokenCarriesTheOriginalAuthTime(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := "bbccddee-22334455"
	svc := NewTokenService(key, kid, "https://vault.test", "vault42", time.Hour, 24*time.Hour, 0)

	origin := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	pair, err := svc.IssueRotatedPair(context.Background(), "user-1", []string{"user"}, []string{"read"}, "", "fp", "family-1", origin)
	if err != nil {
		t.Fatalf("IssueRotatedPair: %v", err)
	}

	claims := parseIssuedToken(t, pair.AccessToken, key, kid)
	if claims.AuthTime != origin.Unix() {
		t.Errorf("auth_time = %d, want the family origin %d", claims.AuthTime, origin.Unix())
	}
	if claims.ACR != "" || len(claims.AMR) != 0 {
		t.Errorf("rotation asserted acr=%q amr=%v; a refresh observes no factors", claims.ACR, claims.AMR)
	}
}

// An issuance with no recorded authentication event emits no auth_time at all,
// rather than the Unix epoch.
func TestTokenWithoutAnAuthenticationEventOmitsAuthTime(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := "ccddeeff-33445566"
	svc := NewTokenService(key, kid, "https://vault.test", "vault42", time.Hour, 24*time.Hour, 0)

	pair, err := svc.IssueTokenPair(context.Background(), "client-1", nil, []string{"kms:unwrap"}, "client-1", "", "", false)
	if err != nil {
		t.Fatalf("IssueTokenPair: %v", err)
	}

	claims := parseIssuedToken(t, pair.AccessToken, key, kid)
	if claims.AuthTime != 0 {
		t.Errorf("auth_time = %d, want it absent", claims.AuthTime)
	}
}

func parseIssuedToken(t *testing.T, token string, key *rsa.PrivateKey, kid string) *vaultcrypto.VaultClaims {
	t.Helper()
	claims, err := vaultcrypto.ParseAndValidate(token, func(tok *vjwt.Token) (any, error) {
		if got, _ := tok.Header["kid"].(string); got != kid {
			t.Fatalf("kid = %q, want %q", got, kid)
		}
		return &key.PublicKey, nil
	}, "https://vault.test", "vault42")
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	return claims
}
