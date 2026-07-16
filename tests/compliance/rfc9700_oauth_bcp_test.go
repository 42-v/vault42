package compliance

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/repository/postgres"
	"github.com/42-v/vault42/internal/service"
)

// =============================================================================
// RFC 9700 -- Best Current Practice for OAuth 2.0 Security
// https://www.rfc-editor.org/rfc/rfc9700
// =============================================================================

// rfc9700OIDCIssuer serves an OIDC discovery document plus a JWKS containing
// pub (kid "rfc9700-k1"), so a generic OIDCProvider can resolve endpoints and
// verify ID tokens without any real network.
func rfc9700OIDCIssuer(t *testing.T, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "rfc9700-k1", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	})
	t.Cleanup(srv.Close)
	return srv
}

func rfc9700SignIDToken(t *testing.T, key *rsa.PrivateKey, claims vjwt.MapClaims) string {
	t.Helper()
	tok, err := vjwt.SignRS256WithHeader(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "rfc9700-k1"}, claims, key)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return tok
}

// rfc9700DPoPProof builds an RSA-signed DPoP proof JWT (RFC 9449) with the
// jwk carried in the header, as ValidateDPoPProof requires.
func rfc9700DPoPProof(t *testing.T, key *rsa.PrivateKey, method, uri, ath string) string {
	t.Helper()
	claims := vjwt.MapClaims{
		"htm": method,
		"htu": uri,
		"iat": time.Now().Unix(),
		"jti": "rfc9700-jti-1",
	}
	if ath != "" {
		claims["ath"] = ath
	}
	header := map[string]any{
		"alg": "RS256",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		},
	}
	proof, err := vjwt.SignRS256WithHeader(header, claims, key)
	if err != nil {
		t.Fatalf("sign dpop proof: %v", err)
	}
	return proof
}

// rfc9700ApplyUserMigrations layers the auth.users column migrations (roles,
// account-state flags, account import) on top of the 001 schema applied by
// setupPostgres. AuthService.Refresh re-fetches the user via GetByID, which
// selects those columns.
func rfc9700ApplyUserMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, f := range []string{"003_user_roles.sql", "004_user_account_flags.sql", "006_account_import.sql"} {
		migSQL, err := os.ReadFile("../../migrations/" + f)
		if err != nil {
			t.Fatalf("read migration %s: %v", f, err)
		}
		if _, err := pool.Exec(ctx, string(migSQL)); err != nil {
			t.Fatalf("apply migration %s: %v", f, err)
		}
	}
}

// --- 2.1.1 / 4.8.2: PKCE on every authorization request ---

func TestRFC9700_2_1_1_PKCEOnAllAuthorizeURLs(t *testing.T) {
	// RFC 9700 Section 2.1.1: clients MUST use PKCE (or nonce) to protect the
	// authorization code. Section 4.8.2: S256 is the only acceptable code
	// challenge method (plain offers no protection against leakage).
	// Every configured provider's AuthURL must carry the challenge verbatim
	// plus code_challenge_method=S256.
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	srv := rfc9700OIDCIssuer(t, &key.PublicKey)

	const challenge = "challenge-s256-value"
	tests := []struct {
		name     string
		provider oauth2.Provider
	}{
		{"google", oauth2.NewGoogleProvider("client-id", "client-secret", "https://app.test/cb")},
		{"github", oauth2.NewGitHubProvider("client-id", "client-secret", "https://app.test/cb")},
		{"facebook", oauth2.NewFacebookProvider("client-id", "client-secret", "https://app.test/cb")},
		{"oidc", oauth2.NewOIDCProvider("okta", srv.URL, "client-id", "client-secret", "https://app.test/cb", "")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.provider.AuthURL("state-1", "nonce-1", challenge)
			if raw == "" {
				t.Fatalf("2.1.1: %s AuthURL returned empty", tc.name)
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("2.1.1: %s AuthURL is not a valid URL: %v", tc.name, err)
			}
			q := u.Query()
			if got := q.Get("code_challenge"); got != challenge {
				t.Fatalf("2.1.1: %s code_challenge = %q, want %q", tc.name, got, challenge)
			}
			if got := q.Get("code_challenge_method"); got != "S256" {
				t.Fatalf("4.8.2: %s code_challenge_method = %q, want S256", tc.name, got)
			}
		})
	}
}

// --- 4.1.1: CSRF -- integrity-protected state parameter ---

func TestRFC9700_4_1_1_StateHMACIntegrity(t *testing.T) {
	// RFC 9700 Section 4.1.1: the state parameter must be protected against
	// forgery. The handler mints state as "provider.nonce.expiry.csrfHash"
	// signed with HMAC-SHA256; any tampered payload, forged signature, or
	// wrong key must fail HMACVerify.
	secret := []byte("rfc9700-state-hmac-secret-32byte")
	nonce := "6e6f6e63652d666f722d7266633937"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	csrfHash := vaultcrypto.SHA256Hex("csrf-token-value")

	payload := fmt.Sprintf("google.%s.%s.%s", nonce, expiry, csrfHash)
	sig := vaultcrypto.HMACSign([]byte(payload), secret)

	if !vaultcrypto.HMACVerify([]byte(payload), secret, sig) {
		t.Fatal("4.1.1: authentic state signature must verify")
	}

	flippedSig := sig[:len(sig)-1] + "0"
	if flippedSig == sig {
		flippedSig = sig[:len(sig)-1] + "1"
	}

	tampered := []struct {
		name    string
		payload string
		key     []byte
		sig     string
	}{
		{"provider_swapped", fmt.Sprintf("github.%s.%s.%s", nonce, expiry, csrfHash), secret, sig},
		{"expiry_extended", fmt.Sprintf("google.%s.%s9.%s", nonce, expiry, csrfHash), secret, sig},
		{"csrf_hash_swapped", fmt.Sprintf("google.%s.%s.%s", nonce, expiry, vaultcrypto.SHA256Hex("attacker-csrf")), secret, sig},
		{"signature_flipped", payload, secret, flippedSig},
		{"wrong_key", payload, []byte("rfc9700-wrong-hmac-key-32-bytes!"), sig},
	}

	for _, tc := range tampered {
		t.Run(tc.name, func(t *testing.T) {
			if vaultcrypto.HMACVerify([]byte(tc.payload), tc.key, tc.sig) {
				t.Fatalf("4.1.1: %s state must be rejected", tc.name)
			}
		})
	}
}

// --- 4.5.3: OIDC nonce binds the ID token to the login attempt ---

func TestRFC9700_4_5_3_OIDCNonceBinding(t *testing.T) {
	// RFC 9700 Section 4.5.3: OpenID Connect nonce prevents authorization code
	// and ID token injection. The authorize URL must carry the nonce, and
	// VerifyIDToken must reject a token whose nonce claim does not match the
	// value minted at /authorize.
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	srv := rfc9700OIDCIssuer(t, &key.PublicKey)
	p := oauth2.NewOIDCProvider("okta", srv.URL, "client-1", "client-secret", "https://app.test/cb", "")
	ctx := context.Background()

	claims := func(nonce string) vjwt.MapClaims {
		return vjwt.MapClaims{
			"iss": srv.URL, "aud": "client-1", "sub": "subject-9700",
			"email": "user@rfc9700.test", "email_verified": true,
			"nonce": nonce,
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Add(-time.Minute).Unix(),
		}
	}

	t.Run("authorize_url_carries_nonce", func(t *testing.T) {
		raw := p.AuthURL("state-1", "nonce-42", "challenge-1")
		if raw == "" {
			t.Fatal("4.5.3: AuthURL returned empty")
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("4.5.3: AuthURL is not a valid URL: %v", err)
		}
		if got := u.Query().Get("nonce"); got != "nonce-42" {
			t.Fatalf("4.5.3: nonce = %q, want nonce-42", got)
		}
	})

	t.Run("matching_nonce_accepted", func(t *testing.T) {
		tok := rfc9700SignIDToken(t, key, claims("nonce-42"))
		info, err := p.VerifyIDToken(ctx, tok, "nonce-42")
		if err != nil {
			t.Fatalf("4.5.3: ID token with matching nonce rejected: %v", err)
		}
		if info.ID != "subject-9700" {
			t.Fatalf("4.5.3: sub = %q, want subject-9700", info.ID)
		}
	})

	t.Run("mismatched_nonce_rejected", func(t *testing.T) {
		tok := rfc9700SignIDToken(t, key, claims("nonce-42"))
		_, err := p.VerifyIDToken(ctx, tok, "different-nonce")
		if err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
			t.Fatalf("4.5.3: want nonce mismatch error, got %v", err)
		}
	})
}

// --- 4.3.2: tokens are never transported in URLs or response bodies ---

func TestRFC9700_4_3_2_TokensOutOfURLs(t *testing.T) {
	// RFC 9700 Section 4.3.2: access tokens must not be transmitted in URIs
	// (browser history, logs, referrers). Vault delivers the refresh token via
	// an HttpOnly cookie only: LoginResult.RefreshToken and CookieMaxAge carry
	// json:"-" so no serializer can ever place them in a body or redirect.
	typ := reflect.TypeOf(service.LoginResult{})

	for _, name := range []string{"RefreshToken", "CookieMaxAge"} {
		f, ok := typ.FieldByName(name)
		if !ok {
			t.Fatalf("4.3.2: LoginResult.%s field missing", name)
		}
		if tag := f.Tag.Get("json"); tag != "-" {
			t.Fatalf("4.3.2: LoginResult.%s json tag = %q, want \"-\"", name, tag)
		}
	}
}

// --- 4.10.1: sender-constrained tokens via DPoP ---

func TestRFC9700_4_10_1_SenderConstrainedDPoP(t *testing.T) {
	// RFC 9700 Section 4.10.1: sender-constraining (DPoP, RFC 9449) prevents a
	// stolen token from being replayed by another party. A valid proof must be
	// accepted; proofs bound to a different method, URI, or access token must
	// be rejected with the specific mismatch error.
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	const method = "POST"
	const uri = "https://vault.test/auth/token"
	ath := vaultcrypto.SHA256Base64URL("access-token-bound")

	t.Run("valid_proof_accepted", func(t *testing.T) {
		proof := rfc9700DPoPProof(t, key, method, uri, ath)
		thumbprint, jti, err := vaultcrypto.ValidateDPoPProof(proof, method, uri, ath)
		if err != nil {
			t.Fatalf("4.10.1: valid DPoP proof rejected: %v", err)
		}
		if thumbprint == "" {
			t.Fatal("4.10.1: thumbprint must not be empty")
		}
		if jti != "rfc9700-jti-1" {
			t.Fatalf("4.10.1: jti = %q, want rfc9700-jti-1", jti)
		}
	})

	t.Run("htm_mismatch_rejected", func(t *testing.T) {
		proof := rfc9700DPoPProof(t, key, method, uri, "")
		_, _, err := vaultcrypto.ValidateDPoPProof(proof, "GET", uri, "")
		if err == nil || !strings.Contains(err.Error(), "htm mismatch") {
			t.Fatalf("4.10.1: want htm mismatch error, got %v", err)
		}
	})

	t.Run("htu_mismatch_rejected", func(t *testing.T) {
		proof := rfc9700DPoPProof(t, key, method, uri, "")
		_, _, err := vaultcrypto.ValidateDPoPProof(proof, method, "https://evil.test/auth/token", "")
		if err == nil || !strings.Contains(err.Error(), "htu mismatch") {
			t.Fatalf("4.10.1: want htu mismatch error, got %v", err)
		}
	})

	t.Run("wrong_ath_rejected", func(t *testing.T) {
		proof := rfc9700DPoPProof(t, key, method, uri, vaultcrypto.SHA256Base64URL("some-other-token"))
		_, _, err := vaultcrypto.ValidateDPoPProof(proof, method, uri, ath)
		if err == nil || !strings.Contains(err.Error(), "ath mismatch") {
			t.Fatalf("4.10.1: want ath mismatch error, got %v", err)
		}
	})
}

// --- 4.14.2: refresh token rotation with replay-triggered family revocation ---

func TestRFC9700_4_14_2_RefreshRotationReplay(t *testing.T) {
	// RFC 9700 Section 4.14.2: refresh tokens must be rotated on use, and a
	// replay of an already-used token must revoke the whole token family so
	// neither the attacker's nor the victim's descendant survives.
	pool, cleanup := setupPostgres(t)
	defer cleanup()
	rfc9700ApplyUserMigrations(t, pool)
	ctx := context.Background()

	db := &postgres.DB{Pool: pool}
	userRepo := postgres.NewUserRepo(db)
	tokenRepo := postgres.NewRefreshTokenRepo(db)
	auditLog := audit.NewLogger(postgres.NewAuditRepo(db), 0)
	mc := cache.NewMemoryCache()
	defer mc.Close()

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := service.NewTokenService(key, kid, "vault-test", "vault-client",
		15*time.Minute, 7*24*time.Hour, 30*24*time.Hour)
	authSvc := service.NewAuthService(userRepo, tokenRepo, nil, nil, tokenSvc, nil,
		auditLog, nil, mc, nil, "https://vault.test", "vault42", "", 15, false,
		[]byte("rfc9700-refresh-hmac-secret-32by"))

	userID, _ := vaultcrypto.RandomUUID()
	now := time.Now()
	if err := userRepo.Create(ctx, &model.User{
		ID: userID, Email: "rfc9700-refresh@test.com", EmailVerified: true,
		PasswordHash: "!rfc9700", Locale: "en", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	raw, _ := vaultcrypto.RandomHex(32)
	familyID, _ := vaultcrypto.RandomUUID()
	rtID, _ := vaultcrypto.RandomUUID()
	if err := tokenRepo.Create(ctx, &model.RefreshToken{
		ID: rtID, UserID: userID, TokenHash: vaultcrypto.SHA256Hex(raw),
		FamilyID: familyID, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	const ip = "203.0.113.7"
	const ua = "rfc9700-test-agent"

	rotated, err := authSvc.Refresh(ctx, raw, ip, ua, vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatalf("4.14.2: first refresh must rotate: %v", err)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == raw {
		t.Fatal("4.14.2: rotation must issue a new refresh token")
	}

	_, err = authSvc.Refresh(ctx, raw, ip, ua, vaultcrypto.FingerprintInput{})
	if !errors.Is(err, service.ErrReplayDetected) {
		t.Fatalf("4.14.2: replaying the consumed token must return ErrReplayDetected, got %v", err)
	}

	_, err = authSvc.Refresh(ctx, rotated.RefreshToken, ip, ua, vaultcrypto.FingerprintInput{})
	if !errors.Is(err, service.ErrTokenInvalid) {
		t.Fatalf("4.14.2: rotated descendant must be dead after family revocation, got %v", err)
	}

	var revoked int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM auth.refresh_tokens WHERE family_id = $1 AND revoked = TRUE`,
		familyID).Scan(&revoked); err != nil {
		t.Fatalf("count revoked family rows: %v", err)
	}
	if revoked != 2 {
		t.Fatalf("4.14.2: expected 2 revoked tokens in the family (seed + rotation), got %d", revoked)
	}
}
