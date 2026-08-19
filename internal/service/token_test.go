package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

const (
	testKID1 = "a1b2c3d4-e5f6-0000-1111-aabbccddeeff"
	testKID2 = "f1e2d3c4-b5a6-0000-2222-112233445566"
)

func newTestTokenService(t *testing.T) (*TokenService, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewTokenService(key, testKID1, "test-issuer", "test-audience",
		15*time.Minute, 7*24*time.Hour, 30*24*time.Hour)
	return svc, key
}

func TestIssueTokenPair(t *testing.T) {
	svc, key := newTestTokenService(t)

	pair, err := svc.IssueTokenPair(context.Background(), "user-1", []string{"user"}, []string{"read"}, "client-1", "fp-hash", "", false)
	if err != nil {
		t.Fatal(err)
	}

	if pair.AccessToken == "" {
		t.Error("access token should not be empty")
	}
	if pair.RefreshToken == "" {
		t.Error("refresh token should not be empty")
	}
	if pair.FamilyID == "" {
		t.Error("family ID should not be empty")
	}

	// Verify the access token is a valid RS256 JWT
	keyFunc := func(token *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}
	_, err = vaultcrypto.ParseAndValidate(pair.AccessToken, keyFunc, "test-issuer", "test-audience")
	if err != nil {
		t.Errorf("access token should be a valid JWT: %v", err)
	}

	// Verify expiry is in the right range
	expectedExpiry := time.Now().Add(15 * time.Minute)
	if pair.ExpiresAt.Before(expectedExpiry.Add(-1*time.Second)) || pair.ExpiresAt.After(expectedExpiry.Add(1*time.Second)) {
		t.Errorf("ExpiresAt %v not within expected range around %v", pair.ExpiresAt, expectedExpiry)
	}
}

func TestIssueTokenPairClaims(t *testing.T) {
	svc, key := newTestTokenService(t)

	pair, err := svc.IssueTokenPair(context.Background(), "user-42", []string{"admin", "user"}, []string{"read", "write"}, "client-x", "fp-abc", "fam-1", false)
	if err != nil {
		t.Fatal(err)
	}

	keyFunc := func(token *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}
	claims, err := vaultcrypto.ParseAndValidate(pair.AccessToken, keyFunc, "test-issuer", "test-audience")
	if err != nil {
		t.Fatal(err)
	}

	// Subject
	sub := claims.GetSubject()
	if sub != "user-42" {
		t.Errorf("subject = %q, want user-42", sub)
	}

	// Issuer
	iss := claims.GetIssuer()
	if iss != "test-issuer" {
		t.Errorf("issuer = %q, want test-issuer", iss)
	}

	// Audience
	aud := claims.GetAudience()
	if len(aud) != 1 || aud[0] != "test-audience" {
		t.Errorf("audience = %v, want [test-audience]", aud)
	}

	// Roles
	if len(claims.Roles) != 2 || claims.Roles[0] != "admin" || claims.Roles[1] != "user" {
		t.Errorf("roles = %v, want [admin user]", claims.Roles)
	}

	// Scopes
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "read" || claims.Scopes[1] != "write" {
		t.Errorf("scopes = %v, want [read write]", claims.Scopes)
	}

	// Fingerprint
	if claims.Fingerprint != "fp-abc" {
		t.Errorf("fingerprint = %q, want fp-abc", claims.Fingerprint)
	}

	// ClientID
	if claims.ClientID != "client-x" {
		t.Errorf("client_id = %q, want client-x", claims.ClientID)
	}

	// TokenType
	if claims.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", claims.TokenType)
	}
}

func TestIssueTokenPairNewFamily(t *testing.T) {
	svc, _ := newTestTokenService(t)

	pair, err := svc.IssueTokenPair(context.Background(), "user-1", nil, nil, "client-1", "fp", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if pair.FamilyID == "" {
		t.Error("empty familyID should generate a new UUID")
	}
	// UUID format: 8-4-4-4-12
	if len(pair.FamilyID) != 36 {
		t.Errorf("generated family ID should be UUID format (36 chars), got %d: %q", len(pair.FamilyID), pair.FamilyID)
	}
}

func TestIssueTokenPairExistingFamily(t *testing.T) {
	svc, _ := newTestTokenService(t)

	pair, err := svc.IssueTokenPair(context.Background(), "user-1", nil, nil, "client-1", "fp", "existing-family-id", false)
	if err != nil {
		t.Fatal(err)
	}
	if pair.FamilyID != "existing-family-id" {
		t.Errorf("familyID = %q, want existing-family-id", pair.FamilyID)
	}
}

func TestIssueTokenPairRememberMe(t *testing.T) {
	svc, _ := newTestTokenService(t)

	// Without rememberMe
	pairNormal, err := svc.IssueTokenPair(context.Background(), "user-1", nil, nil, "client-1", "fp", "fam", false)
	if err != nil {
		t.Fatal(err)
	}

	// With rememberMe
	pairRemember, err := svc.IssueTokenPair(context.Background(), "user-1", nil, nil, "client-1", "fp", "fam", true)
	if err != nil {
		t.Fatal(err)
	}

	// rememberMe should have a later RefreshExpAt (30 days vs 7 days)
	normalDuration := time.Until(pairNormal.RefreshExpAt)
	rememberDuration := time.Until(pairRemember.RefreshExpAt)

	// Normal should be ~7 days
	if normalDuration < 6*24*time.Hour || normalDuration > 8*24*time.Hour {
		t.Errorf("normal refresh TTL should be ~7 days, got %v", normalDuration)
	}

	// Remember should be ~30 days
	if rememberDuration < 29*24*time.Hour || rememberDuration > 31*24*time.Hour {
		t.Errorf("remember refresh TTL should be ~30 days, got %v", rememberDuration)
	}

	if !pairRemember.RefreshExpAt.After(pairNormal.RefreshExpAt) {
		t.Error("rememberMe RefreshExpAt should be after normal RefreshExpAt")
	}
}

func TestIssueChallengeToken(t *testing.T) {
	svc, key := newTestTokenService(t)

	token, err := svc.IssueChallengeToken(context.Background(), "user-1", "fp-challenge")
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("challenge token should not be empty")
	}

	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}
	claims, err := vaultcrypto.ParseAndValidate(token, keyFunc, "test-issuer", "test-audience")
	if err != nil {
		t.Fatal(err)
	}

	// TokenType
	if claims.TokenType != "2fa_challenge" {
		t.Errorf("token_type = %q, want 2fa_challenge", claims.TokenType)
	}

	// Subject
	sub := claims.GetSubject()
	if sub != "user-1" {
		t.Errorf("subject = %q, want user-1", sub)
	}

	// Fingerprint
	if claims.Fingerprint != "fp-challenge" {
		t.Errorf("fingerprint = %q, want fp-challenge", claims.Fingerprint)
	}

	// Expiry should be ~5 minutes
	exp := claims.GetExpirationTime()
	ttl := time.Until(exp.Time)
	if ttl < 4*time.Minute || ttl > 6*time.Minute {
		t.Errorf("challenge token TTL should be ~5 minutes, got %v", ttl)
	}
}

func TestUpdateSigningKey(t *testing.T) {
	svc, oldKey := newTestTokenService(t)

	// Issue a token with the original key
	token1, err := svc.IssueChallengeToken(context.Background(), "user-1", "fp")
	if err != nil {
		t.Fatal(err)
	}

	// Generate a new key and update
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	svc.UpdateSigningKey(newKey, testKID2)

	// Issue a token with the new key
	token2, err := svc.IssueChallengeToken(context.Background(), "user-1", "fp")
	if err != nil {
		t.Fatal(err)
	}

	// token1 should validate with old key, not new key
	oldKeyFunc := func(tok *vjwt.Token) (any, error) {
		return &oldKey.PublicKey, nil
	}
	newKeyFunc := func(tok *vjwt.Token) (any, error) {
		return &newKey.PublicKey, nil
	}

	if _, err := vaultcrypto.ParseAndValidate(token1, oldKeyFunc, "test-issuer", "test-audience"); err != nil {
		t.Errorf("token1 should validate with old key: %v", err)
	}
	if _, err := vaultcrypto.ParseAndValidate(token1, newKeyFunc, "test-issuer", "test-audience"); err == nil {
		t.Error("token1 should NOT validate with new key")
	}

	// token2 should validate with new key, not old key
	if _, err := vaultcrypto.ParseAndValidate(token2, newKeyFunc, "test-issuer", "test-audience"); err != nil {
		t.Errorf("token2 should validate with new key: %v", err)
	}
	if _, err := vaultcrypto.ParseAndValidate(token2, oldKeyFunc, "test-issuer", "test-audience"); err == nil {
		t.Error("token2 should NOT validate with old key")
	}
}
