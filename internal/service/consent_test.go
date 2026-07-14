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
// The laundering hole: GET returns a bare marketing_emails bool with no
// provenance, so any client that round-trips the profile form re-submits an
// imported (pre-ticked, never affirmed) true. If PUT stamped that as
// source=profile, a value the user never chose would silently become
// demonstrable Art. 7 consent — defeating the entire point of the record.
// Re-submitting an unchanged value is not an act of consent.
func TestReconcileMarketingConsent_UnchangedValueKeepsProvenance(t *testing.T) {
	tests := []struct {
		name       string
		prior      *ConsentRecord
		submitted  bool
		wantSource string
		wantAffirm bool
		wantEvent  bool
	}{
		{"imported true echoed back stays imported", &ConsentRecord{Granted: true, Source: ConsentSourceImport, Origin: "beon3"}, true, ConsentSourceImport, false, false},
		{"legacy true echoed back stays legacy", &ConsentRecord{Granted: true, Source: ConsentSourceLegacy}, true, ConsentSourceLegacy, false, false},
		{"imported true actually unticked is a real withdrawal", &ConsentRecord{Granted: true, Source: ConsentSourceImport}, false, ConsentSourceProfile, false, true},
		{"imported false actually ticked is a real opt-in", &ConsentRecord{Granted: false, Source: ConsentSourceImport}, true, ConsentSourceProfile, true, true},
		{"first ever opt-in is affirmative", nil, true, ConsentSourceProfile, true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &IdentityData{}
			submitted := tc.submitted
			gotEvent := d.ReconcileMarketingConsent(&submitted, tc.prior)

			if d.MarketingConsent == nil {
				t.Fatal("no consent record produced")
			}
			if d.MarketingConsent.Source != tc.wantSource {
				t.Errorf("source = %q, want %q", d.MarketingConsent.Source, tc.wantSource)
			}
			if got := d.MarketingConsent.Affirmative(); got != tc.wantAffirm {
				t.Errorf("Affirmative() = %v, want %v", got, tc.wantAffirm)
			}
			if gotEvent != tc.wantEvent {
				t.Errorf("consent event = %v, want %v", gotEvent, tc.wantEvent)
			}
		})
	}
}

// A client that omits marketing_emails (a partial-update client, or one whose
// form has no checkbox) must not blank the stored record. PUT is a full replace,
// so without this a save from any such client would destroy a recorded
// withdrawal — and the controller could no longer show it had been honoured.
func TestReconcileMarketingConsent_OmittedFieldPreservesWithdrawal(t *testing.T) {
	prior := &ConsentRecord{Granted: false, Source: ConsentSourceUnsubscribe, At: time.Now().UTC()}

	d := &IdentityData{}
	gotEvent := d.ReconcileMarketingConsent(nil, prior)

	if gotEvent {
		t.Error("omitting the field is not a consent change and must not emit an event")
	}
	if d.MarketingConsent == nil {
		t.Fatal("the stored withdrawal was destroyed by an update that never mentioned it")
	}
	if d.MarketingConsent.Granted || d.MarketingConsent.Source != ConsentSourceUnsubscribe {
		t.Errorf("withdrawal not preserved: %+v", d.MarketingConsent)
	}
	if d.MarketingEmails == nil || *d.MarketingEmails {
		t.Error("preference bool must follow the preserved record")
	}
}

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
