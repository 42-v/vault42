package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// IdentityData represents the decrypted identity profile fields.
type IdentityData struct {
	GivenName   string       `json:"given_name,omitempty"`
	FamilyName  string       `json:"family_name,omitempty"`
	Country     string       `json:"country,omitempty"`
	DateOfBirth string       `json:"date_of_birth,omitempty"`
	Sex         string       `json:"sex,omitempty"`
	Billing     *BillingInfo `json:"billing,omitempty"`
}

// BillingInfo represents billing address fields.
type BillingInfo struct {
	AddressLine1 string `json:"address_line_1,omitempty"`
	AddressLine2 string `json:"address_line_2,omitempty"`
	City         string `json:"city,omitempty"`
	PostalCode   string `json:"postal_code,omitempty"`
	Country      string `json:"country,omitempty"`
	VATID        string `json:"vat_id,omitempty"`
}

// IdentityService manages encrypted identity profiles.
type IdentityService struct {
	repo       repository.IdentityRepository
	masterKey  []byte
	hmacSecret []byte
}

// NewIdentityService creates a new identity service.
func NewIdentityService(repo repository.IdentityRepository, masterKey, hmacSecret []byte) *IdentityService {
	return &IdentityService{repo: repo, masterKey: masterKey, hmacSecret: hmacSecret}
}

// Pseudonym computes the deterministic pseudonym for a user ID.
func (s *IdentityService) Pseudonym(userID string) string {
	return vaultcrypto.HMACSign([]byte(userID+":identity"), s.hmacSecret)
}

// Get retrieves and decrypts a user's identity profile.
func (s *IdentityService) Get(ctx context.Context, userID string) (*IdentityData, time.Time, error) {
	pseudo := s.Pseudonym(userID)
	profile, err := s.repo.GetByPseudonym(ctx, pseudo)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("identity get: %w", err)
	}
	if profile == nil {
		return nil, time.Time{}, nil
	}

	plaintext, err := vaultcrypto.Decrypt(profile.DataEnc, s.masterKey, []byte(pseudo))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("identity decrypt: %w", err)
	}

	var data IdentityData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, time.Time{}, fmt.Errorf("identity unmarshal: %w", err)
	}

	return &data, profile.UpdatedAt, nil
}

// Upsert encrypts and stores a user's identity profile.
func (s *IdentityService) Upsert(ctx context.Context, userID string, data *IdentityData) error {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("identity marshal: %w", err)
	}

	pseudo := s.Pseudonym(userID)
	enc, err := vaultcrypto.Encrypt(plaintext, s.masterKey, []byte(pseudo))
	if err != nil {
		return fmt.Errorf("identity encrypt: %w", err)
	}

	now := time.Now()
	return s.repo.Upsert(ctx, &model.IdentityProfile{
		PseudonymID: pseudo,
		DataEnc:     enc,
		Version:     1,
		UpdatedAt:   now,
		CreatedAt:   now,
	})
}

// Delete removes a user's identity profile.
func (s *IdentityService) Delete(ctx context.Context, userID string) error {
	return s.repo.Delete(ctx, s.Pseudonym(userID))
}
