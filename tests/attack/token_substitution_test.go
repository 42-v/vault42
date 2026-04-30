package attack

import (
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestTokenSubstitution_DifferentSubject verifies that a token signed for user A
// retains user A's claims and cannot be confused with user B.
func TestTokenSubstitution_DifferentSubject(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Sign a token for user A
	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-A",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles:  []string{"admin"},
		Scopes: []string{"write"},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	// Parse and verify claims belong to user A
	claims, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err != nil {
		t.Fatalf("ParseAndValidate failed: %v", err)
	}

	if claims.Subject != "user-A" {
		t.Fatalf("Subject should be user-A, got %q", claims.Subject)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Fatalf("Roles should be [admin], got %v", claims.Roles)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "write" {
		t.Fatalf("Scopes should be [write], got %v", claims.Scopes)
	}
}

// TestTokenSubstitution_WrongAudience verifies that a token signed for
// audience A is rejected when validated against audience B.
func TestTokenSubstitution_WrongAudience(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	audiences := []struct {
		signAud     string
		validateAud string
	}{
		{"app-frontend", "app-admin"},
		{"user-service", "payment-service"},
		{"mobile-app", "web-app"},
	}

	for _, tt := range audiences {
		t.Run(tt.signAud+"->"+tt.validateAud, func(t *testing.T) {
			tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject:   "user-123",
					Issuer:    "vault",
					Audience:  vjwt.ClaimStrings{tt.signAud},
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
			}, key, kid)

			_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", tt.validateAud)
			if err == nil {
				t.Fatalf("Token for audience %q accepted with audience %q", tt.signAud, tt.validateAud)
			}
		})
	}
}

// TestTokenSubstitution_DifferentKey verifies that tokens signed with one key
// are rejected when validated against a different key.
func TestTokenSubstitution_DifferentKey(t *testing.T) {
	keyA, _ := vaultcrypto.GenerateRSAKeyPair()
	keyB, _ := vaultcrypto.GenerateRSAKeyPair()
	kidA, _ := vaultcrypto.RandomUUID()

	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, keyA, kidA)

	// Validate with key B instead of key A
	keyFuncB := func(t *vjwt.Token) (any, error) {
		return &keyB.PublicKey, nil
	}

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFuncB, "vault", "app")
	if err == nil {
		t.Fatal("Token signed with key A should be rejected when validated with key B")
	}
}

// TestTokenSubstitution_CrossIssuer verifies tokens from issuer A are rejected
// when validated by issuer B.
func TestTokenSubstitution_CrossIssuer(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "auth-server-1",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "auth-server-2", "app")
	if err == nil {
		t.Fatal("Token from issuer-1 should be rejected when validated against issuer-2")
	}
}

// TestTokenSubstitution_ClaimsPreservation verifies all custom claims survive
// sign/parse round-trip.
func TestTokenSubstitution_ClaimsPreservation(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	original := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-456",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles:     []string{"user", "moderator"},
		Scopes:    []string{"read", "write", "admin"},
		ClientID:  "frontend-v2",
		TokenType: "access",
	}

	tokenStr, _ := vaultcrypto.SignToken(original, key, kid)
	parsed, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err != nil {
		t.Fatalf("ParseAndValidate failed: %v", err)
	}

	if parsed.Subject != "user-456" {
		t.Errorf("Subject mismatch: got %q", parsed.Subject)
	}
	if parsed.ClientID != "frontend-v2" {
		t.Errorf("ClientID mismatch: got %q", parsed.ClientID)
	}
	if parsed.TokenType != "access" {
		t.Errorf("TokenType mismatch: got %q", parsed.TokenType)
	}
	if len(parsed.Roles) != 2 {
		t.Errorf("Roles count mismatch: got %d", len(parsed.Roles))
	}
	if len(parsed.Scopes) != 3 {
		t.Errorf("Scopes count mismatch: got %d", len(parsed.Scopes))
	}
}
