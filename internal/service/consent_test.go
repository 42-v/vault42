package service

import (
	"testing"
	"time"
)

// The whole point of the consent record is to tell an affirmative opt-in apart
// from a value that was merely carried over. If Affirmative() ever returns true
// for an imported or legacy record, a migrated default (BeOn3's column defaults
// to true, and its consent checkbox ships pre-ticked) silently becomes consent.
func TestConsentAffirmative(t *testing.T) {
	tests := []struct {
		name   string
		record *ConsentRecord
		want   bool
	}{
		{"nil record", nil, false},
		{"registration opt-in", &ConsentRecord{Granted: true, Source: ConsentSourceRegistration}, true},
		{"profile opt-in", &ConsentRecord{Granted: true, Source: ConsentSourceProfile}, true},
		{"registration opt-out", &ConsentRecord{Granted: false, Source: ConsentSourceRegistration}, false},
		{"imported true is not consent", &ConsentRecord{Granted: true, Source: ConsentSourceImport, Origin: "beon3"}, false},
		{"legacy true is not consent", &ConsentRecord{Granted: true, Source: ConsentSourceLegacy}, false},
		{"withdrawn", &ConsentRecord{Granted: false, Source: ConsentSourceUnsubscribe}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.record.Affirmative(); got != tc.want {
				t.Errorf("Affirmative() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStampMarketingConsent(t *testing.T) {
	d := &IdentityData{}
	before := time.Now().UTC()
	d.StampMarketingConsent(true, ConsentSourceRegistration, "")

	if d.MarketingEmails == nil || !*d.MarketingEmails {
		t.Fatal("preference bool not set")
	}
	if d.MarketingConsent == nil {
		t.Fatal("consent record not stamped")
	}
	if d.MarketingConsent.Source != ConsentSourceRegistration {
		t.Errorf("source = %q, want %q", d.MarketingConsent.Source, ConsentSourceRegistration)
	}
	if d.MarketingConsent.At.Before(before) {
		t.Error("consent timestamp not recorded")
	}
	if !d.MarketingConsent.Affirmative() {
		t.Error("a registration opt-in must be affirmative consent")
	}
}

// A profile written before consent provenance existed carries a bare bool. It
// must surface as legacy — not be backfilled with an invented timestamp that
// would misrepresent it as a demonstrable act of consent.
func TestNormalizeConsent_LegacyBoolIsNotBackfilled(t *testing.T) {
	yes := true
	d := &IdentityData{MarketingEmails: &yes}
	d.normalizeConsent()

	if d.MarketingConsent == nil {
		t.Fatal("legacy bool should produce a consent record")
	}
	if d.MarketingConsent.Source != ConsentSourceLegacy {
		t.Errorf("source = %q, want %q", d.MarketingConsent.Source, ConsentSourceLegacy)
	}
	if !d.MarketingConsent.At.IsZero() {
		t.Error("legacy record must not invent a consent timestamp")
	}
	if d.MarketingConsent.Affirmative() {
		t.Error("a legacy bool is not affirmative consent")
	}
}

// The record is authoritative: if the two ever disagree, the bool must follow
// the record, or a stale bool could re-grant a withdrawn consent.
func TestNormalizeConsent_RecordWinsOverBool(t *testing.T) {
	yes := true
	d := &IdentityData{
		MarketingEmails:  &yes,
		MarketingConsent: &ConsentRecord{Granted: false, Source: ConsentSourceUnsubscribe},
	}
	d.normalizeConsent()

	if d.MarketingEmails == nil || *d.MarketingEmails {
		t.Error("withdrawal in the record must override a stale true bool")
	}
}
