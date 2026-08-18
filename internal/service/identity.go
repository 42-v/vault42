package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/42-v/vault42/internal/config"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// IdentityData represents the decrypted identity profile fields.
//
// PII lives here (AES-GCM encrypted at rest, keyed by HMAC pseudonym). New
// fields are omitempty so blobs written before they existed still decode.
// Dynamic holds opaque app-specific data (e.g. the legacy platform forum/garage state),
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

	// MarketingConsent is the provenance of MarketingEmails. The bool alone says
	// what the user's preference is; Art. 7(1) requires the controller to be able
	// to demonstrate *that* consent was given, which needs when and how.
	MarketingConsent *ConsentRecord `json:"marketing_consent,omitempty"`
}

// Consent sources. These are recorded verbatim so a later audit can tell an
// affirmative opt-in apart from a value that was merely carried over.
const (
	// ConsentSourceRegistration — an explicit boolean supplied by a frontend at
	// sign-up. This is the only source that is unambiguously affirmative consent.
	ConsentSourceRegistration = "registration"
	// ConsentSourceProfile — the user changed the preference on their profile.
	ConsentSourceProfile = "profile"
	// ConsentSourceUnsubscribe — withdrawal via the one-click unsubscribe link.
	ConsentSourceUnsubscribe = "unsubscribe"
	// ConsentSourceImport — carried over from a migrated system. NOT affirmative
	// consent on its own: the value may be a default the user never saw. Records
	// with this source keep the imported value but are flagged for re-permission.
	ConsentSourceImport = "import"
	// ConsentSourceLegacy — the profile predates consent provenance. The value is
	// known, the origin is not; recorded honestly rather than backfilled.
	ConsentSourceLegacy = "legacy"
)

// ConsentRecord captures a single consent decision and where it came from.
type ConsentRecord struct {
	Granted bool      `json:"granted"`
	At      time.Time `json:"at"`
	Source  string    `json:"source"`
	// Origin optionally names the system a ConsentSourceImport record came from
	// (e.g. "beon3"), so an imported list can be re-permissioned selectively.
	Origin string `json:"origin,omitempty"`
}

// Affirmative reports whether the record can be relied on as consent under
// Art. 7. Imported and legacy values carry a preference but not a demonstrable
// act of consent, so they are not affirmative regardless of the flag.
func (c *ConsentRecord) Affirmative() bool {
	if c == nil || !c.Granted {
		return false
	}
	return c.Source == ConsentSourceRegistration || c.Source == ConsentSourceProfile
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
	// e.g. "legacy.forum". Prevents control chars / oversized keys in the blob.
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
	// Zero the decrypted PII buffer once decoding is done: we own this slice and
	// it is not retained past this call. Reduces the in-memory exposure window
	// for plaintext identity data (OWASP ASVS V8.3.2). The decoded struct fields
	// are copied out, so the result remains valid after the buffer is wiped.
	defer config.ZeroBytes(plaintext)

	var data IdentityData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, time.Time{}, fmt.Errorf("identity unmarshal: %w", err)
	}
	data.normalizeConsent()

	return &data, profile.UpdatedAt, nil
}

// ErrConcurrentUpdate is returned when a profile kept changing underneath a
// read-modify-write for more than consentUpdateAttempts tries.
var ErrConcurrentUpdate = errors.New("identity profile changed concurrently")

const consentUpdateAttempts = 3

// UpdateMarketingConsent changes only the marketing consent, leaving every other
// field of the profile as it was.
//
// It is a compare-and-set loop rather than a plain Get/Upsert because the profile
// is one encrypted blob: a writer must decrypt the whole thing, change its field
// and re-encrypt, so two concurrent writers would each persist their own stale
// view and one change would vanish. Losing a withdrawal that way is not an
// acceptable outcome — the user would be told they had unsubscribed while the
// stored record still said otherwise.
func (s *IdentityService) UpdateMarketingConsent(ctx context.Context, userID string, granted bool, source, origin string) error {
	for attempt := 0; attempt < consentUpdateAttempts; attempt++ {
		data, updatedAt, err := s.Get(ctx, userID)
		if err != nil {
			return err
		}
		if data == nil {
			// No profile: record the withdrawal anyway, but as an insert that must
			// not clobber a profile created in the race window (a blind Upsert here
			// would replace a real profile with an empty one carrying only consent).
			data = &IdentityData{}
			updatedAt = time.Time{}
		}
		data.StampMarketingConsent(granted, source, origin)

		ok, err := s.upsertCAS(ctx, userID, data, updatedAt)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		// Lost the race: re-read and re-apply on top of whatever landed.
	}
	return ErrConcurrentUpdate
}

// PutProfile is the full-replace profile write behind PUT /user/identity.
//
// The consent reconciliation has to happen inside the same compare-and-set as the
// write, not before a blind one. Two things go wrong otherwise:
//
//   - The prior record is read, then a concurrent unsubscribe commits, then this
//     write lands carrying the pre-withdrawal consent — silently reverting a
//     withdrawal the user was told had been honored. The CAS turns that into a
//     retry, which re-reads the withdrawal and preserves it.
//   - If the prior read fails, treating that as "no prior consent" would blank a
//     stored withdrawal and re-stamp an imported flag as affirmative. The error is
//     returned instead: a profile save is not worth guessing about consent.
//
// Returns the consent record as persisted and whether it actually changed, so the
// caller can log a consent event only when one occurred, with the value that
// really landed — and only after the write has succeeded.
func (s *IdentityService) PutProfile(ctx context.Context, userID string, incoming *IdentityData, submitted *bool) (stored *ConsentRecord, changed bool, err error) {
	for attempt := 0; attempt < consentUpdateAttempts; attempt++ {
		existing, updatedAt, err := s.Get(ctx, userID)
		if err != nil {
			return nil, false, err
		}
		var prior *ConsentRecord
		if existing != nil {
			prior = existing.MarketingConsent
		} else {
			updatedAt = time.Time{}
		}

		// Reconcile onto a fresh copy each round: a retry must re-apply against the
		// consent it just re-read, not compound the previous attempt's stamp.
		data := *incoming
		didChange := data.ReconcileMarketingConsent(submitted, prior)

		ok, err := s.upsertCAS(ctx, userID, &data, updatedAt)
		if err != nil {
			return nil, false, err
		}
		if ok {
			return data.MarketingConsent, didChange, nil
		}
	}
	return nil, false, ErrConcurrentUpdate
}

// upsertCAS encrypts and writes a profile only if the stored row is unchanged.
func (s *IdentityService) upsertCAS(ctx context.Context, userID string, data *IdentityData, expectedUpdatedAt time.Time) (bool, error) {
	if err := data.Validate(); err != nil {
		return false, err
	}
	data.normalizeConsent()
	plaintext, err := json.Marshal(data)
	if err != nil {
		return false, fmt.Errorf("identity marshal: %w", err)
	}
	pseudo := s.Pseudonym(userID)
	enc, err := vaultcrypto.Encrypt(plaintext, s.masterKey, []byte(pseudo))
	if err != nil {
		return false, fmt.Errorf("identity encrypt: %w", err)
	}
	now := time.Now()
	return s.repo.UpsertCAS(ctx, &model.IdentityProfile{
		PseudonymID: pseudo,
		DataEnc:     enc,
		Version:     1,
		UpdatedAt:   now,
		CreatedAt:   now,
	}, expectedUpdatedAt)
}

// MarketingAllowed reports whether marketing email may be sent to a user, and is
// the only thing a campaign sender should consult. It fails closed: no profile,
// no consent record, or a non-affirmative (imported/legacy) record all mean no.
//
// It has no caller, and that is the correct state rather than a gap. vault42
// sends no marketing email: there is no campaign sender in this repository, and
// internal/service cannot be imported by one outside it. Every message this
// service sends is transactional -- verification, reset, lockout, new-country --
// and none of them consults a marketing preference, because consent is not what
// authorizes them.
//
// What it exists for is to be the one place the Art. 7 rule is written
// executably. The stored preference is a bool, and a bool invites the reading
// that true means consent; it does not, because an imported true is a value the
// user was never shown (Recital 32, and Planet49 C-673/17 on pre-ticked boxes).
// Any sender built later that reads MarketingEmails directly will get that
// wrong, and it will get it wrong silently. Keeping the rule stated once, tested
// by the compliance suite, is what makes "read this, not the field" an
// instruction with something behind it.
//
// Deleting it would not remove a control, because nothing runs it. It would
// remove the definition, and leave the field.
func (s *IdentityService) MarketingAllowed(ctx context.Context, userID string) (bool, error) {
	data, _, err := s.Get(ctx, userID)
	if err != nil {
		return false, err
	}
	if data == nil {
		return false, nil
	}
	return data.MarketingConsent.Affirmative(), nil
}

// StampMarketingConsent sets the marketing preference together with its
// provenance. Always prefer this over assigning MarketingEmails directly: a bare
// bool records the preference but not the consent, which is what Art. 7(1)
// actually requires the controller to be able to produce.
func (d *IdentityData) StampMarketingConsent(granted bool, source, origin string) {
	d.MarketingEmails = &granted
	d.MarketingConsent = &ConsentRecord{
		Granted: granted,
		At:      time.Now().UTC(),
		Source:  source,
		Origin:  origin,
	}
}

// ReconcileMarketingConsent decides what consent record an incoming profile
// update should carry, given what is already stored. It exists because
// PUT /user/identity is a full replace fed by a form the client round-trips:
// without it, two things go wrong.
//
//   - Laundering. GET returns the bare bool with no provenance, so a client
//     re-submits marketing_emails=true for an imported (pre-ticked, never
//     affirmed) opt-in. Stamping that as source=profile would turn a value the
//     user never chose into demonstrable Art. 7 consent. So a submitted value
//     that is unchanged from the stored one is NOT a fresh act of consent: the
//     existing record, and its provenance, is kept exactly as it was.
//   - Erasure. A client that omits marketing_emails entirely (a partial-update
//     client, or one whose form has no checkbox) would otherwise blank the
//     stored record — destroying a recorded withdrawal along with it.
//
// Only a value that actually differs from what is stored is an affirmative act,
// and only then is it stamped with source=profile. Returns true when the caller
// should emit a consent audit event.
func (d *IdentityData) ReconcileMarketingConsent(submitted *bool, prior *ConsentRecord) (changed bool) {
	// Omitted: preserve whatever is on record, including a withdrawal.
	if submitted == nil {
		d.MarketingConsent = prior
		if prior != nil {
			granted := prior.Granted
			d.MarketingEmails = &granted
		}
		return false
	}
	// Unchanged: not a fresh act of consent — keep the original provenance, so an
	// imported or legacy value cannot be promoted by an echo of itself.
	if prior != nil && prior.Granted == *submitted {
		d.MarketingConsent = prior
		granted := prior.Granted
		d.MarketingEmails = &granted
		return false
	}
	// Genuinely changed (or first ever): the user acted, so this is affirmative.
	d.StampMarketingConsent(*submitted, ConsentSourceProfile, "")
	return true
}

// normalizeConsent keeps the legacy bool and the consent record from drifting.
// The record is authoritative when present; a profile written before consent
// provenance existed keeps its value but is labeled legacy rather than being
// backfilled with an invented timestamp.
func (d *IdentityData) normalizeConsent() {
	switch {
	case d.MarketingConsent != nil:
		granted := d.MarketingConsent.Granted
		d.MarketingEmails = &granted
	case d.MarketingEmails != nil:
		d.MarketingConsent = &ConsentRecord{
			Granted: *d.MarketingEmails,
			Source:  ConsentSourceLegacy,
		}
	}
}

// Upsert encrypts and stores a user's identity profile.
func (s *IdentityService) Upsert(ctx context.Context, userID string, data *IdentityData) error {
	if err := data.Validate(); err != nil {
		return err
	}
	data.normalizeConsent()
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
