package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// IdentityData represents the decrypted identity profile fields.
//
// PII lives here (AES-GCM encrypted at rest, keyed by HMAC pseudonym). New
// fields are omitempty so blobs written before they existed still decode.
// Dynamic holds opaque app-specific data (e.g. BeOn3 forum/garage state),
// namespaced by app key — vault42 treats it as encrypted, validated only for
// size and shape, never interpreting its contents.
type IdentityData struct {
	GivenName       string                     `json:"given_name,omitempty"`
	FamilyName      string                     `json:"family_name,omitempty"`
	Username        string                     `json:"username,omitempty"`
	Country         string                     `json:"country,omitempty"`
	State           string                     `json:"state,omitempty"`
	DateOfBirth     string                     `json:"date_of_birth,omitempty"`
	Sex             string                     `json:"sex,omitempty"`
	MarketingEmails *bool                      `json:"marketing_emails,omitempty"`
	Billing         *BillingInfo               `json:"billing,omitempty"`
	Dynamic         map[string]json.RawMessage `json:"dynamic,omitempty"`
}

// Identity profile validation bounds.
const (
	usernameMinLen   = 3
	usernameMaxLen   = 32
	stateMaxLen      = 3
	dynamicMaxBytes  = 64 * 1024 // total encoded size of the Dynamic map
	dynamicMaxKeyLen = 64
)

var (
	// ErrInvalidProfile is returned when identity data fails validation.
	ErrInvalidProfile = errors.New("invalid identity profile")

	// dynamicKeyRe restricts namespace keys to lowercase dotted segments,
	// e.g. "beon3.forum". Prevents control chars / oversized keys in the blob.
	dynamicKeyRe = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9]+)*$`)
	dateOnlyRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	countryRe    = regexp.MustCompile(`^[A-Za-z]{2}$`)
)

// Validate checks the identity profile against vault42's field bounds. It is
// permissive about absent fields (all are optional) but rejects malformed or
// abusive values before they are encrypted and stored.
func (d *IdentityData) Validate() error {
	if d == nil {
		return nil
	}
	if d.Username != "" {
		n := utf8.RuneCountInString(d.Username)
		if n < usernameMinLen || n > usernameMaxLen {
			return fmt.Errorf("%w: username must be %d-%d chars", ErrInvalidProfile, usernameMinLen, usernameMaxLen)
		}
	}
	if d.Country != "" && !countryRe.MatchString(d.Country) {
		return fmt.Errorf("%w: country must be a 2-letter code", ErrInvalidProfile)
	}
	if utf8.RuneCountInString(d.State) > stateMaxLen {
		return fmt.Errorf("%w: state must be <= %d chars", ErrInvalidProfile, stateMaxLen)
	}
	switch d.Sex {
	case "", "male", "female":
	default:
		return fmt.Errorf("%w: sex must be male, female, or empty", ErrInvalidProfile)
	}
	if d.DateOfBirth != "" {
		if !dateOnlyRe.MatchString(d.DateOfBirth) {
			return fmt.Errorf("%w: date_of_birth must be YYYY-MM-DD", ErrInvalidProfile)
		}
		if _, err := time.Parse("2006-01-02", d.DateOfBirth); err != nil {
			return fmt.Errorf("%w: date_of_birth is not a valid date", ErrInvalidProfile)
		}
	}
	if len(d.Dynamic) > 0 {
		for k, v := range d.Dynamic {
			if len(k) > dynamicMaxKeyLen || !dynamicKeyRe.MatchString(k) {
				return fmt.Errorf("%w: dynamic key %q must be lowercase dotted segments", ErrInvalidProfile, k)
			}
			if !json.Valid(v) {
				return fmt.Errorf("%w: dynamic[%q] is not valid JSON", ErrInvalidProfile, k)
			}
		}
		encoded, err := json.Marshal(d.Dynamic)
		if err != nil {
			return fmt.Errorf("%w: dynamic not serializable", ErrInvalidProfile)
		}
		if len(encoded) > dynamicMaxBytes {
			return fmt.Errorf("%w: dynamic exceeds %d bytes", ErrInvalidProfile, dynamicMaxBytes)
		}
	}
	return nil
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
	if err := data.Validate(); err != nil {
		return err
	}
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
