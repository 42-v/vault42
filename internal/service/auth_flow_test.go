package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// Login with 2FA: TOTP path (~8 subtests)
// ---------------------------------------------------------------------------

func TestLoginMFA_TOTPChallengeTokenContainsUserID(t *testing.T) {
	hash := validPasswordHash(t)
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{},
		false,
	)
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLogger := audit.NewLogger(&mocks.MockAuditRepo{}, 0)

	svc := NewAuthService(
		&mocks.MockUserRepo{
			GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
				return &model.User{
					ID: "user-totp-1", Email: "totp@example.com",
					PasswordHash: hash, EmailVerified: true,
				}, nil
			},
		},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{},
		tokenSvc, mfaSvc, auditLogger, NewHIBPClient(),
		&mocks.MockCache{}, &mocks.MockEmailSender{},
		"https://vault.test", "TestVault", "", 15, false, nil,
	)

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "totp@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}

	// Verify challenge token is a valid JWT containing the user ID
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}
	claims, err := vaultcrypto.ParseAndValidate(result.ChallengeToken, keyFunc, "https://vault.test", "https://vault.test")
	if err != nil {
		t.Fatalf("challenge token should be valid JWT: %v", err)
	}
	sub := claims.GetSubject()
	if sub != "user-totp-1" {
		t.Errorf("challenge token subject = %q, want user-totp-1", sub)
	}
	if claims.TokenType != "2fa_challenge" {
		t.Errorf("challenge token type = %q, want 2fa_challenge", claims.TokenType)
	}
}

func TestLoginMFA_TOTPNoAccessTokenIssued(t *testing.T) {
	hash := validPasswordHash(t)
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{},
		false,
	)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "totp-no-access@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "totp-no-access@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}

	if result.AccessToken != "" {
		t.Error("access token should be empty when 2FA is required")
	}
	if result.RefreshToken != "" {
		t.Error("refresh token should be empty when 2FA is required")
	}
	if result.TokenType != "" {
		t.Error("token type should be empty when 2FA is required")
	}
	if result.ExpiresIn != 0 {
		t.Errorf("expires_in should be 0, got %d", result.ExpiresIn)
	}
}

func TestLoginMFA_TOTPChallengeTokenExpiry(t *testing.T) {
	hash := validPasswordHash(t)
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{},
		false,
	)
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLogger := audit.NewLogger(&mocks.MockAuditRepo{}, 0)

	svc := NewAuthService(
		&mocks.MockUserRepo{
			GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
				return &model.User{
					ID: "user-1", Email: "totp-exp@example.com",
					PasswordHash: hash, EmailVerified: true,
				}, nil
			},
		},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{},
		tokenSvc, mfaSvc, auditLogger, NewHIBPClient(),
		&mocks.MockCache{}, &mocks.MockEmailSender{},
		"https://vault.test", "TestVault", "", 15, false, nil,
	)

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "totp-exp@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}

	// Parse challenge token and verify ~5 min expiry
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}
	claims, _ := vaultcrypto.ParseAndValidate(result.ChallengeToken, keyFunc, "https://vault.test", "https://vault.test")
	exp := claims.GetExpirationTime()
	ttl := time.Until(exp.Time)
	if ttl < 4*time.Minute || ttl > 6*time.Minute {
		t.Errorf("challenge token TTL should be ~5 minutes, got %v", ttl)
	}
}

func TestLoginMFA_TOTPStatusCheckError(t *testing.T) {
	hash := validPasswordHash(t)
	// Every MFA lookup errors, so the status is undetermined. Login must fail
	// closed rather than read the empty method set as "no second factor" and
	// issue tokens; this test used to assert the opposite (the fail-open bug).
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
				return nil, errors.New("totp repo error")
			},
		},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return nil, errors.New("webauthn repo error")
			},
		},
		&mocks.MockBackupCodeRepo{
			ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
				return nil, errors.New("backup repo error")
			},
		},
		false,
	)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "mfa-err@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	// An undetermined MFA status must refuse the login, not proceed: a factor may
	// exist that the failed reads could not see.
	result, err := svc.Login(context.Background(), LoginInput{
		Email: "mfa-err@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err == nil {
		t.Fatalf("login must fail closed when the MFA status cannot be determined, got result %+v", result)
	}
}

// ---------------------------------------------------------------------------
// Login with 2FA: WebAuthn path (~5 subtests)
// ---------------------------------------------------------------------------

func TestLoginMFA_WebAuthnChallengeAvailableMethods(t *testing.T) {
	hash := validPasswordHash(t)
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{
					{ID: "cred-1"},
					{ID: "cred-2"},
				}, nil
			},
		},
		&mocks.MockBackupCodeRepo{},
		false,
	)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "webauthn-methods@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "webauthn-methods@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Requires2FA {
		t.Fatal("should require 2FA with WebAuthn credentials")
	}
	if len(result.AvailableMethods) != 1 {
		t.Fatalf("should have 1 method, got %v", result.AvailableMethods)
	}
	if result.AvailableMethods[0] != "webauthn" {
		t.Errorf("method should be webauthn, got %q", result.AvailableMethods[0])
	}
}

func TestLoginMFA_WebAuthnNoRefreshTokenStored(t *testing.T) {
	hash := validPasswordHash(t)
	var refreshTokenCreated bool
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{{ID: "cred-1"}}, nil
			},
		},
		&mocks.MockBackupCodeRepo{},
		false,
	)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "webauthn-nort@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
		o.tokenRepo.CreateFn = func(_ context.Context, _ *model.RefreshToken) error {
			refreshTokenCreated = true
			return nil
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "webauthn-nort@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if refreshTokenCreated {
		t.Error("refresh token should NOT be created when 2FA challenge is issued")
	}
}

// ---------------------------------------------------------------------------
// Login with 2FA: backup code path (~4 subtests)
// ---------------------------------------------------------------------------

func TestLoginMFA_BackupCodeAvailable(t *testing.T) {
	hash := validPasswordHash(t)
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{
			ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
				return []*model.BackupCode{{ID: "bc-1"}, {ID: "bc-2"}, {ID: "bc-3"}}, nil
			},
		},
		false,
	)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "backup-avail@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "backup-avail@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Requires2FA {
		t.Fatal("should require 2FA")
	}

	// Should have both totp and backup_code
	methodSet := map[string]bool{}
	for _, m := range result.AvailableMethods {
		methodSet[m] = true
	}
	if !methodSet["totp"] {
		t.Error("available methods should include totp")
	}
	if !methodSet["backup_code"] {
		t.Error("available methods should include backup_code")
	}
}

func TestLoginMFA_AllThreeMethodsAvailable(t *testing.T) {
	hash := validPasswordHash(t)
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{{ID: "cred-1"}}, nil
			},
		},
		&mocks.MockBackupCodeRepo{
			ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
				return []*model.BackupCode{{ID: "bc-1"}}, nil
			},
		},
		false,
	)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "all-mfa@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "all-mfa@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.AvailableMethods) != 3 {
		t.Fatalf("should have 3 methods, got %v", result.AvailableMethods)
	}
	methodSet := map[string]bool{}
	for _, m := range result.AvailableMethods {
		methodSet[m] = true
	}
	for _, expected := range []string{"totp", "webauthn", "backup_code"} {
		if !methodSet[expected] {
			t.Errorf("missing method %q in %v", expected, result.AvailableMethods)
		}
	}
}

// ---------------------------------------------------------------------------
// Email verification flow (~6 subtests)
// ---------------------------------------------------------------------------

func TestSendVerificationEmail_URLContainsOrigin(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	mockCache.SetFn = func(_ context.Context, _, _ string, _ time.Duration) error {
		return nil
	}

	var capturedText string
	mockEmail.SendFn = func(_ context.Context, _, _, _, text string) error {
		capturedText = text
		return nil
	}

	svc.sendVerificationEmail(context.Background(), "user@example.com", "user-123", "", "")

	if !strings.Contains(capturedText, "https://vault.test/verify-email?token=") {
		t.Errorf("email should contain origin URL, got %q", capturedText)
	}
}

func TestSendVerificationEmail_TokenIs64HexChars(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	var cachedKey string
	mockCache.SetFn = func(_ context.Context, key, _ string, _ time.Duration) error {
		cachedKey = key
		return nil
	}
	mockEmail.SendFn = func(_ context.Context, _, _, _, _ string) error {
		return nil
	}

	svc.sendVerificationEmail(context.Background(), "user@example.com", "user-123", "", "")

	// Key is "verify:" + SHA256 hex of the token (64 hex chars)
	if !strings.HasPrefix(cachedKey, "verify:") {
		t.Fatalf("key should start with verify:, got %q", cachedKey)
	}
	hashPart := strings.TrimPrefix(cachedKey, "verify:")
	if len(hashPart) != 64 {
		t.Errorf("token hash should be 64 hex chars, got %d chars: %q", len(hashPart), hashPart)
	}
}

func TestSendVerificationEmail_CacheTTLIs24Hours(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	var cachedTTL time.Duration
	mockCache.SetFn = func(_ context.Context, _, _ string, ttl time.Duration) error {
		cachedTTL = ttl
		return nil
	}
	mockEmail.SendFn = func(_ context.Context, _, _, _, _ string) error {
		return nil
	}

	svc.sendVerificationEmail(context.Background(), "user@example.com", "user-123", "", "")

	if cachedTTL != 24*time.Hour {
		t.Errorf("cache TTL should be 24 hours, got %v", cachedTTL)
	}
}

func TestSendVerificationEmail_CacheStoresUserID(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	var cachedValue string
	mockCache.SetFn = func(_ context.Context, _, value string, _ time.Duration) error {
		cachedValue = value
		return nil
	}
	mockEmail.SendFn = func(_ context.Context, _, _, _, _ string) error {
		return nil
	}

	svc.sendVerificationEmail(context.Background(), "user@example.com", "user-xyz-789", "", "")

	if cachedValue != "user-xyz-789" {
		t.Errorf("cached value should be user ID 'user-xyz-789', got %q", cachedValue)
	}
}

func TestSendVerificationEmail_RedirectEncoded(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	mockCache.SetFn = func(_ context.Context, _, _ string, _ time.Duration) error {
		return nil
	}

	var capturedText string
	mockEmail.SendFn = func(_ context.Context, _, _, _, text string) error {
		capturedText = text
		return nil
	}

	svc.sendVerificationEmail(context.Background(), "user@example.com", "user-123", "", "/settings/profile")

	// The redirect should be URL-encoded
	if !strings.Contains(capturedText, "redirect=") {
		t.Error("should include redirect param")
	}
	if !strings.Contains(capturedText, "%2F") || !strings.Contains(capturedText, "settings") {
		t.Errorf("redirect should be URL-encoded with %%2F, got: %s", capturedText)
	}
}

func TestSendVerificationEmail_HTMLAndTextBothContainURL(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	mockCache.SetFn = func(_ context.Context, _, _ string, _ time.Duration) error {
		return nil
	}

	var capturedHTML, capturedText string
	mockEmail.SendFn = func(_ context.Context, _, _, html, text string) error {
		capturedHTML = html
		capturedText = text
		return nil
	}

	svc.sendVerificationEmail(context.Background(), "user@example.com", "user-123", "", "")

	if !strings.Contains(capturedHTML, "verify-email?token=") {
		t.Error("HTML body should contain verification URL")
	}
	if !strings.Contains(capturedText, "verify-email?token=") {
		t.Error("text body should contain verification URL")
	}
}

// ---------------------------------------------------------------------------
// Token service edge cases (~8 subtests)
// ---------------------------------------------------------------------------

func TestTokenService_IssueTokenPairUniqueJTIs(t *testing.T) {
	svc, _ := newTestTokenService(t)

	jtis := make(map[string]bool)
	for i := 0; i < 10; i++ {
		pair, err := svc.IssueTokenPair(context.Background(), "user-1", []string{"user"}, nil, "client", "fp", "", false)
		if err != nil {
			t.Fatal(err)
		}
		// Parse the token to extract JTI
		token, _ := vjwt.ParseUnverified(pair.AccessToken, &vaultcrypto.VaultClaims{})
		if claims, ok := token.Claims.(*vaultcrypto.VaultClaims); ok {
			jti := claims.GetExpirationTime()
			// Use full token ID as uniqueness check
			if jtis[claims.ID] {
				t.Errorf("duplicate JTI detected: %s", claims.ID)
			}
			jtis[claims.ID] = true
			_ = jti
		}
	}
	if len(jtis) != 10 {
		t.Errorf("expected 10 unique JTIs, got %d", len(jtis))
	}
}

func TestTokenService_IssueTokenPairEmptyRolesAndScopes(t *testing.T) {
	svc, key := newTestTokenService(t)

	pair, err := svc.IssueTokenPair(context.Background(), "user-1", nil, nil, "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}

	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}
	claims, err := vaultcrypto.ParseAndValidate(pair.AccessToken, keyFunc, "test-issuer", "test-audience")
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Roles) != 0 {
		t.Errorf("roles should be empty, got %v", claims.Roles)
	}
	if len(claims.Scopes) != 0 {
		t.Errorf("scopes should be empty, got %v", claims.Scopes)
	}
}

func TestTokenService_ChallengeTokenUniquePerCall(t *testing.T) {
	svc, _ := newTestTokenService(t)

	token1, err := svc.IssueChallengeToken(context.Background(), "user-1", "fp")
	if err != nil {
		t.Fatal(err)
	}
	token2, err := svc.IssueChallengeToken(context.Background(), "user-1", "fp")
	if err != nil {
		t.Fatal(err)
	}
	if token1 == token2 {
		t.Error("each challenge token should be unique due to unique JTI")
	}
}

func TestTokenService_UpdateSigningKeyConcurrentSafe(t *testing.T) {
	svc, _ := newTestTokenService(t)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			svc.UpdateSigningKey(newKey, "new-kid")
		}
		close(done)
	}()

	for i := 0; i < 100; i++ {
		_, err := svc.IssueChallengeToken(context.Background(), "user-1", "fp")
		if err != nil {
			t.Fatalf("concurrent token issuance should not fail: %v", err)
		}
	}
	<-done
}

func TestTokenService_IssueTokenPairAccessTokenTTL(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	svc := NewTokenService(key, "kid-1", "iss", "aud",
		5*time.Minute, 1*time.Hour, 7*24*time.Hour)

	pair, err := svc.IssueTokenPair(context.Background(), "user-1", nil, nil, "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}

	ttl := time.Until(pair.ExpiresAt)
	if ttl < 4*time.Minute || ttl > 6*time.Minute {
		t.Errorf("access token TTL should be ~5 minutes, got %v", ttl)
	}
}

func TestTokenService_IssueTokenPairRefreshTTLNormal(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	svc := NewTokenService(key, "kid-1", "iss", "aud",
		15*time.Minute, 7*24*time.Hour, 30*24*time.Hour)

	pair, err := svc.IssueTokenPair(context.Background(), "user-1", nil, nil, "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}

	refreshTTL := time.Until(pair.RefreshExpAt)
	if refreshTTL < 6*24*time.Hour || refreshTTL > 8*24*time.Hour {
		t.Errorf("refresh TTL should be ~7 days, got %v", refreshTTL)
	}
}

func TestTokenService_IssueTokenPairRefreshTTLRememberMe(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	svc := NewTokenService(key, "kid-1", "iss", "aud",
		15*time.Minute, 7*24*time.Hour, 30*24*time.Hour)

	pair, err := svc.IssueTokenPair(context.Background(), "user-1", nil, nil, "", "", "", true)
	if err != nil {
		t.Fatal(err)
	}

	refreshTTL := time.Until(pair.RefreshExpAt)
	if refreshTTL < 29*24*time.Hour || refreshTTL > 31*24*time.Hour {
		t.Errorf("remember-me refresh TTL should be ~30 days, got %v", refreshTTL)
	}
}

func TestTokenService_IssueTokenPairFingerprintInClaims(t *testing.T) {
	svc, key := newTestTokenService(t)

	pair, err := svc.IssueTokenPair(context.Background(), "user-1", nil, nil, "", "sha256-fingerprint-value", "", false)
	if err != nil {
		t.Fatal(err)
	}

	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}
	claims, _ := vaultcrypto.ParseAndValidate(pair.AccessToken, keyFunc, "test-issuer", "test-audience")
	if claims.Fingerprint != "sha256-fingerprint-value" {
		t.Errorf("fingerprint = %q, want sha256-fingerprint-value", claims.Fingerprint)
	}
}

// ---------------------------------------------------------------------------
// Register: additional edge cases (~6 subtests)
// ---------------------------------------------------------------------------

func TestRegisterUnicodePassword(t *testing.T) {
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil
		}
	})

	// Unicode characters: each counts as 1 rune, total 15 runes
	result, err := svc.Register(context.Background(), RegisterInput{
		Email:    "unicode@example.com",
		Password: strings.Repeat("\u00e9", 15), // 15 accented e's
	}, "1.2.3.4")
	if err != nil {
		t.Fatalf("15-rune unicode password should be accepted: %v", err)
	}
	if result.UserID == "" {
		t.Error("user should be created")
	}
}

func TestRegisterUnicodePasswordTooShort(t *testing.T) {
	svc, _ := newMockAuthService(t)

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "unicodeshort@example.com",
		Password: strings.Repeat("\u00e9", 14), // 14 runes
	}, "1.2.3.4")
	if !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("14-rune password should be rejected, got %v", err)
	}
}

func TestRegisterEmailTrimmedAndLowered(t *testing.T) {
	var savedEmail string
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, email string) (*model.User, error) {
			savedEmail = email
			return nil, nil
		}
	})

	svc.Register(context.Background(), RegisterInput{
		Email:    "  USER@Example.COM  ",
		Password: "correct-horse-battery-staple",
	}, "1.2.3.4")

	if savedEmail != "user@example.com" {
		t.Errorf("email should be trimmed+lowered, got %q", savedEmail)
	}
}

func TestRegisterLocaleValidCustom(t *testing.T) {
	var savedUser *model.User
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil
		}
		o.userRepo.CreateFn = func(_ context.Context, u *model.User) error {
			savedUser = u
			return nil
		}
	})

	svc.Register(context.Background(), RegisterInput{
		Email:    "locale-sk@example.com",
		Password: "correct-horse-battery-staple",
		Locale:   "sk-SK",
	}, "1.2.3.4")

	if savedUser == nil {
		t.Fatal("user should be saved")
	}
	if savedUser.Locale != "sk-sk" {
		t.Errorf("locale should be 'sk-sk', got %q", savedUser.Locale)
	}
}

func TestRegisterLocaleInvalidFallsBackToEn(t *testing.T) {
	var savedUser *model.User
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil
		}
		o.userRepo.CreateFn = func(_ context.Context, u *model.User) error {
			savedUser = u
			return nil
		}
	})

	svc.Register(context.Background(), RegisterInput{
		Email:    "locale-bad@example.com",
		Password: "correct-horse-battery-staple",
		Locale:   "invalid<script>",
	}, "1.2.3.4")

	if savedUser == nil {
		t.Fatal("user should be saved")
	}
	if savedUser.Locale != "en" {
		t.Errorf("invalid locale should fallback to 'en', got %q", savedUser.Locale)
	}
}

func TestRegisterNoCacheNilEmailSenderSkipsVerification(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLogger := audit.NewLogger(&mocks.MockAuditRepo{}, 0)

	svc := NewAuthService(
		&mocks.MockUserRepo{
			GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
				return nil, nil
			},
		},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLogger, NewHIBPClient(),
		nil, nil, // nil cache and nil emailSender
		"https://vault.test", "TestVault", "", 15, false, nil,
	)

	result, err := svc.Register(context.Background(), RegisterInput{
		Email:    "nocache@example.com",
		Password: "correct-horse-battery-staple",
	}, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if result.UserID == "" {
		t.Error("user should be created even without cache/email")
	}
}

// ---------------------------------------------------------------------------
// Refresh: additional edge cases (~6 subtests)
// ---------------------------------------------------------------------------

func TestRefreshTokenHashMatchesStoredHash(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	rawRefreshToken := "test-refresh-token-value"
	expectedHash := vaultcrypto.SHA256Hex(rawRefreshToken)
	var queriedHash string

	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, hash string) (*model.RefreshToken, error) {
			queriedHash = hash
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: fp,
				ExpiresAt:       time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return true, nil
		}
	})

	svc.Refresh(context.Background(), rawRefreshToken, "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})

	if queriedHash != expectedHash {
		t.Errorf("queried hash should match SHA256 of raw token")
	}
}

func TestRefreshRejectsBannedUserAndRevokesFamily(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{IP: "1.2.3.4", UserAgent: "TestAgent"})
	revokedFamily := ""
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: fp, ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) { return true, nil }
		o.tokenRepo.RevokeFamilyFn = func(_ context.Context, fam string) error { revokedFamily = fam; return nil }
		o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Banned: true}, nil
		}
	})

	_, err := svc.Refresh(context.Background(), "tok", "1.2.3.4", "TestAgent", vaultcrypto.FingerprintInput{})
	if !errors.Is(err, ErrAccountBanned) {
		t.Fatalf("banned user refresh should return ErrAccountBanned, got %v", err)
	}
	if revokedFamily != "fam-1" {
		t.Fatalf("banned refresh must revoke the token family, revoked=%q", revokedFamily)
	}
}

func TestRefreshNewTokenInSameFamily(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	var newFamilyID string
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "original-family",
				FingerprintHash: fp, DeviceID: "dev-1",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return true, nil
		}
		o.tokenRepo.CreateFn = func(_ context.Context, rt *model.RefreshToken) error {
			newFamilyID = rt.FamilyID
			return nil
		}
	})

	_, err := svc.Refresh(context.Background(), "valid-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatal(err)
	}
	if newFamilyID != "original-family" {
		t.Errorf("new token family = %q, want original-family", newFamilyID)
	}
}

func TestRefreshPreservesDeviceID(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	var newDeviceID string
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: fp, DeviceID: "device-42",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return true, nil
		}
		o.tokenRepo.CreateFn = func(_ context.Context, rt *model.RefreshToken) error {
			newDeviceID = rt.DeviceID
			return nil
		}
	})

	_, err := svc.Refresh(context.Background(), "valid-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatal(err)
	}
	if newDeviceID != "device-42" {
		t.Errorf("new token device_id = %q, want device-42", newDeviceID)
	}
}

func TestRefreshResultTokenTypeBearer(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: fp,
				ExpiresAt:       time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return true, nil
		}
	})

	result, err := svc.Refresh(context.Background(), "valid-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatal(err)
	}
	if result.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", result.TokenType)
	}
}

func TestRefreshRevokedAndUsedBothInvalid(t *testing.T) {
	tests := []struct {
		name    string
		revoked bool
		used    bool
		wantErr error
	}{
		{"revoked_only", true, false, ErrTokenInvalid},
		{"used_only", false, true, ErrReplayDetected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
				o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
					return &model.RefreshToken{
						ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
						Revoked:   tt.revoked,
						Used:      tt.used,
						ExpiresAt: time.Now().Add(1 * time.Hour),
					}, nil
				}
			})

			_, err := svc.Refresh(context.Background(), "token", "1.2.3.4", "TestAgent",
				vaultcrypto.FingerprintInput{})
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRefreshFingerprintMatchSameIPAndUA(t *testing.T) {
	// Verify that matching fingerprint allows refresh
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "10.0.0.1", UserAgent: "Chrome/120",
	})
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: fp,
				ExpiresAt:       time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return true, nil
		}
	})

	result, err := svc.Refresh(context.Background(), "valid-token", "10.0.0.1", "Chrome/120",
		vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatalf("matching fingerprint should allow refresh: %v", err)
	}
	if result.AccessToken == "" {
		t.Error("access token should be issued on matching fingerprint")
	}
}

// ---------------------------------------------------------------------------
// Logout: additional tests (~3 subtests)
// ---------------------------------------------------------------------------

func TestLogoutSuccess(t *testing.T) {
	// Verify logout completes without error when repo succeeds
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.RevokeAllForUserFn = func(_ context.Context, _ string) error {
			return nil
		}
	})

	err := svc.Logout(context.Background(), "user-99", "9.9.9.9", "LogoutAgent")
	if err != nil {
		t.Fatalf("logout should succeed: %v", err)
	}
}

func TestLogoutCorrectUserRevoked(t *testing.T) {
	var revokedUserID string
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.RevokeAllForUserFn = func(_ context.Context, userID string) error {
			revokedUserID = userID
			return nil
		}
	})

	svc.Logout(context.Background(), "specific-user-id", "1.2.3.4", "Agent")

	if revokedUserID != "specific-user-id" {
		t.Errorf("revoked user = %q, want specific-user-id", revokedUserID)
	}
}

func TestLogoutDBErrorPropagated(t *testing.T) {
	dbErr := errors.New("connection pool exhausted")
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.RevokeAllForUserFn = func(_ context.Context, _ string) error {
			return dbErr
		}
	})

	err := svc.Logout(context.Background(), "user-1", "1.2.3.4", "Agent")
	if !errors.Is(err, dbErr) {
		t.Errorf("should propagate DB error, got %v", err)
	}
}
