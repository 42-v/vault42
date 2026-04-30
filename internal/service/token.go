package service

import (
	"crypto/rsa"
	"fmt"
	"sync"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TokenService handles JWT issuance and refresh token generation.
type TokenService struct {
	mu              sync.RWMutex
	privateKey      *rsa.PrivateKey
	kid             string
	issuer          string
	audience        string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	rememberMeTTL   time.Duration
}

// TokenPair is an access+refresh token pair.
type TokenPair struct {
	AccessToken  string // #nosec G117 -- internal DTO, never serialized to JSON
	RefreshToken string // #nosec G117 -- raw token (to be hashed before storage)
	ExpiresAt    time.Time
	RefreshExpAt time.Time
	FamilyID     string
}

// NewTokenService creates a new token service.
func NewTokenService(key *rsa.PrivateKey, kid, issuer, audience string, accessTTL, refreshTTL, rememberTTL time.Duration) *TokenService {
	return &TokenService{
		privateKey:      key,
		kid:             kid,
		issuer:          issuer,
		audience:        audience,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
		rememberMeTTL:   rememberTTL,
	}
}

// IssueTokenPair creates a new access+refresh token pair.
func (s *TokenService) IssueTokenPair(userID string, roles, scopes []string, clientID, fingerprint, familyID string, rememberMe bool) (*TokenPair, error) {
	now := time.Now()
	jti, err := vaultcrypto.RandomUUID()
	if err != nil {
		return nil, fmt.Errorf("generate JTI: %w", err)
	}

	s.mu.RLock()
	key := s.privateKey
	kid := s.kid
	s.mu.RUnlock()

	accessClaims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    s.issuer,
			Audience:  vjwt.ClaimStrings{s.audience},
			Subject:   userID,
			ExpiresAt: vjwt.NewNumericDate(now.Add(s.accessTokenTTL)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        jti,
		},
		Roles:       roles,
		Scopes:      scopes,
		ClientID:    clientID,
		Fingerprint: fingerprint,
		TokenType:   "Bearer",
	}

	accessToken, err := vaultcrypto.SignToken(accessClaims, key, kid)
	if err != nil {
		return nil, err
	}

	refreshToken, err := vaultcrypto.RandomToken(32)
	if err != nil {
		return nil, err
	}

	refreshTTL := s.refreshTokenTTL
	if rememberMe {
		refreshTTL = s.rememberMeTTL
	}

	if familyID == "" {
		familyID, err = vaultcrypto.RandomUUID()
		if err != nil {
			return nil, fmt.Errorf("generate family ID: %w", err)
		}
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    now.Add(s.accessTokenTTL),
		RefreshExpAt: now.Add(refreshTTL),
		FamilyID:     familyID,
	}, nil
}

// IssueChallengeToken creates a short-lived JWT for 2FA challenge.
func (s *TokenService) IssueChallengeToken(userID, fingerprint string) (string, error) {
	now := time.Now()
	jti, err := vaultcrypto.RandomUUID()
	if err != nil {
		return "", fmt.Errorf("generate challenge JTI: %w", err)
	}

	s.mu.RLock()
	key := s.privateKey
	kid := s.kid
	s.mu.RUnlock()

	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    s.issuer,
			Audience:  vjwt.ClaimStrings{s.audience},
			Subject:   userID,
			ExpiresAt: vjwt.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        jti,
		},
		Fingerprint: fingerprint,
		TokenType:   "2fa_challenge",
	}

	return vaultcrypto.SignToken(claims, key, kid)
}

// AccessTokenTTL returns the configured access token TTL.
func (s *TokenService) AccessTokenTTL() time.Duration {
	return s.accessTokenTTL
}

// UpdateSigningKey updates the signing key and kid for key rotation.
func (s *TokenService) UpdateSigningKey(key *rsa.PrivateKey, kid string) {
	s.mu.Lock()
	s.privateKey = key
	s.kid = kid
	s.mu.Unlock()
}
