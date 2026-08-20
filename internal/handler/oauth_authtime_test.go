package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// oidcCallbackAuthTimeNonce is the login attempt these tests replay. The state
// nonce and the id_token nonce have to be the same value or VerifyIDToken
// refuses the token before any of this reaches the claim under test.
const oidcCallbackAuthTimeNonce = "authtime-nonce"

// The issuer and audience the access token under test is minted for and read
// back with.
const (
	oidcCallbackTokenIssuer   = "https://vault.test"
	oidcCallbackTokenAudience = "vault42"
)

// oidcCallbackClaims drives the OIDC callback to completion against an issuer
// whose id_token carries the claims mutate leaves behind, and returns the claims
// of the access token the callback issued.
//
// It goes through a real OIDCProvider rather than a mockProvider because the
// path under test spans both: the provider reads auth_time off the signed
// id_token, and the handler decides what the issued token says when it reads
// nothing. A mock supplying UserInfo directly would leave the first half
// untested.
func oidcCallbackClaims(t *testing.T, mutate func(vjwt.MapClaims)) *vaultcrypto.VaultClaims {
	t.Helper()

	// The JWKS loader enforces a 2048-bit minimum modulus.
	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	var idToken string
	srv := newOIDCTestIssuer(t, &idpKey.PublicKey, &idToken)
	provider := oauth2.NewOIDCProvider("okta", srv.URL, "client-1", "secret", "https://vault.test/cb", "")

	idClaims := vjwt.MapClaims{
		"iss": srv.URL, "aud": "client-1", "sub": "authtime-sub",
		"email": "authtime@example.com", "email_verified": true, "name": "AuthTime User",
		"nonce": oidcCallbackAuthTimeNonce,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(idClaims)
	}
	signed, err := vjwt.SignRS256WithHeader(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"}, idClaims, idpKey)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	idToken = signed

	// The callback never puts the access token in the redirect; it stores it
	// under a one-time exchange code, so the cache write is where a test can
	// read the token it issued.
	var accessToken string
	cache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "test-verifier", nil },
		SetFn: func(_ context.Context, key, value string, _ time.Duration) error {
			if !strings.HasPrefix(key, "oauth_code:") {
				return nil
			}
			var data OAuthExchangeData
			if err := json.Unmarshal([]byte(value), &data); err != nil {
				t.Errorf("decode exchange payload: %v", err)
				return nil
			}
			accessToken = data.AccessToken
			return nil
		},
	}
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, EmailVerified: true}, nil
		},
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: "user-authtime-1"}, nil
		},
	}
	tokens := &mocks.MockRefreshTokenRepo{}

	// The issued token is read back through vault42's own verifier, so this test
	// sees exactly what a relying party sees rather than whatever a hand-rolled
	// base64 split would yield. That verifier requires a hex kid, which the kid
	// newTestTokenService picks is not, so the service is built here.
	signingKey := newTestRSAKey(t)
	tokenSvc := service.NewTokenService(signingKey, "aabbccdd-11223344",
		oidcCallbackTokenIssuer, oidcCallbackTokenAudience, 5*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLog := newTestAuditLogger()
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	authSvc := service.NewAuthService(
		users, tokens, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLog, nil, cache, nil,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)
	h := NewOAuthHandler(
		map[string]oauth2.Provider{"okta": provider},
		hmacSecret, cache, "https://vault.test",
		users, social, tokens, authSvc, tokenSvc, nil, auditLog, false,
	)

	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("okta", oidcCallbackAuthTimeNonce, expiry, hmacSecret)
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/okta?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "okta")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("callback status %d, want 302 (%s)", rec.Code, rec.Body.String())
	}
	if accessToken == "" {
		t.Fatal("the callback stored no access token; nothing to read auth_time from")
	}
	claims, err := vaultcrypto.ParseAndValidate(accessToken, func(*vjwt.Token) (any, error) {
		return &signingKey.PublicKey, nil
	}, oidcCallbackTokenIssuer, oidcCallbackTokenAudience)
	if err != nil {
		t.Fatalf("parse issued access token: %v", err)
	}
	return claims
}

// A federated login authenticates nobody: the identity provider did, possibly
// hours earlier and possibly out of an SSO session that prompted the user for
// nothing. auth_time is the claim that says when that happened, so it has to be
// the instant the provider asserted. Dating it to the callback is what makes a
// relying party enforcing max_age accept a stale session as freshly
// reauthenticated, which is the entire check it thinks it is running.
func TestOAuth_Callback_AuthTimeIsTheProviderAssertedInstant(t *testing.T) {
	asserted := time.Now().Add(-90 * time.Minute).Truncate(time.Second)

	claims := oidcCallbackClaims(t, func(c vjwt.MapClaims) {
		c["auth_time"] = float64(asserted.Unix())
	})

	if claims.AuthTime != asserted.Unix() {
		t.Fatalf("auth_time = %d, want %d, the instant the id_token asserted; a token that "+
			"restates the callback instant reports a 90-minute-old authentication as current",
			claims.AuthTime, asserted.Unix())
	}
}

// auth_time is OPTIONAL in OIDC Core §2 unless the request sent max_age or asked
// for it as an essential claim, so most issuers omit it and the login must still
// succeed. What it must not do is date the session to the epoch: the token
// service drops a zero instant, and any value near it would claim the user
// authenticated in 1970. The callback instant is the honest substitute, because
// it is the one moment vault42 witnessed anything.
func TestOAuth_Callback_AuthTimeFallsBackToTheCallbackInstant(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(vjwt.MapClaims)
	}{
		{"issuer omits the claim", nil},
		{"issuer sends the epoch", func(c vjwt.MapClaims) { c["auth_time"] = float64(0) }},
		{"issuer sends a string", func(c vjwt.MapClaims) { c["auth_time"] = "1700000000" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := time.Now().Add(-time.Second).Unix()
			claims := oidcCallbackClaims(t, tc.mutate)
			after := time.Now().Add(time.Second).Unix()

			if claims.AuthTime == 0 {
				t.Fatal("auth_time = 0, so the issued token carries no authentication instant at all; " +
					"the callback is itself the authentication event vault42 observed")
			}
			if claims.AuthTime < before || claims.AuthTime > after {
				t.Fatalf("auth_time = %d, want the callback instant in [%d, %d]", claims.AuthTime, before, after)
			}
		})
	}
}
