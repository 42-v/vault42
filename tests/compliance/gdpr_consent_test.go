package compliance

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// EU GDPR 2016/679 -- Consent (Art. 7, Recital 32)
// https://eur-lex.europa.eu/eli/reg/2016/679/oj
// =============================================================================

func gdprIdentityService(repo *mocks.MockIdentityRepo) *service.IdentityService {
	return service.NewIdentityService(repo, make([]byte, 32), []byte("gdpr-compliance-hmac-secret"))
}

// gdprIdentityRepo is a stateful mock: Upsert stores the encrypted profile and
// GetByPseudonym returns it, so services read back real ciphertext.
func gdprIdentityRepo() *mocks.MockIdentityRepo {
	repo := &mocks.MockIdentityRepo{}
	var stored *model.IdentityProfile
	repo.UpsertFn = func(_ context.Context, p *model.IdentityProfile) error {
		stored = p
		return nil
	}
	repo.GetByPseudonymFn = func(context.Context, string) (*model.IdentityProfile, error) {
		return stored, nil
	}
	return repo
}

func gdprStamped(granted bool, source, origin string) *service.IdentityData {
	d := &service.IdentityData{}
	d.StampMarketingConsent(granted, source, origin)
	return d
}

func gdprAuthedRequest(method, target, subject string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: subject},
	}
	return req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
}

// --- Art. 7(1): the controller shall be able to demonstrate that the data
// subject has consented ---

func TestGDPR_Art7_1_ConsentRecordProvenance(t *testing.T) {
	// Art. 7(1): a bare preference bool records what the user wants, not that
	// they ever chose it. Every stamp must carry full provenance: the value,
	// when it was recorded, how it was obtained and, for migrations, from where.
	before := time.Now().UTC()

	d := &service.IdentityData{}
	d.StampMarketingConsent(true, service.ConsentSourceImport, "beon3")

	rec := d.MarketingConsent
	if rec == nil {
		t.Fatal("Art. 7(1): no consent record stamped")
	}
	if !rec.Granted {
		t.Error("Art. 7(1): granted value not recorded")
	}
	if rec.At.Before(before) {
		t.Errorf("Art. 7(1): consent time not recorded: %v", rec.At)
	}
	if rec.Source != service.ConsentSourceImport {
		t.Errorf("Art. 7(1): source = %q, want %q", rec.Source, service.ConsentSourceImport)
	}
	if rec.Origin != "beon3" {
		t.Errorf("Art. 7(1): origin = %q, want %q", rec.Origin, "beon3")
	}
	if d.MarketingEmails == nil || !*d.MarketingEmails {
		t.Error("Art. 7(1): preference bool must follow the stamped record")
	}
}

// --- Art. 7 + Recital 32: silence, pre-ticked boxes or inactivity do not
// constitute consent ---

func TestGDPR_Art7_Recital32_AffirmativeSourcesOnly(t *testing.T) {
	// Recital 32 (and Planet49, C-673/17): only a clear affirmative act is
	// consent. A migrated or legacy true may be a pre-ticked default the user
	// never saw, so Affirmative() is an allowlist of the two sources that
	// record a real act, never a denylist of known-bad ones.
	tests := []struct {
		name   string
		record *service.ConsentRecord
		want   bool
	}{
		{"granted at registration", &service.ConsentRecord{Granted: true, Source: service.ConsentSourceRegistration}, true},
		{"granted on the profile", &service.ConsentRecord{Granted: true, Source: service.ConsentSourceProfile}, true},
		{"imported true is a pre-ticked box", &service.ConsentRecord{Granted: true, Source: service.ConsentSourceImport}, false},
		{"legacy true has no demonstrable act", &service.ConsentRecord{Granted: true, Source: service.ConsentSourceLegacy}, false},
		{"unsubscribe is always a withdrawal", &service.ConsentRecord{Granted: false, Source: service.ConsentSourceUnsubscribe}, false},
		{"not granted at registration", &service.ConsentRecord{Granted: false, Source: service.ConsentSourceRegistration}, false},
		{"unknown source fails closed", &service.ConsentRecord{Granted: true, Source: "sales_import_2024"}, false},
		{"absent record", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.record.Affirmative(); got != tc.want {
				t.Errorf("Affirmative() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- Art. 7 fail-closed gating of the consent-based purpose (P10) ---

func TestGDPR_Art7_MarketingAllowedFailsClosed(t *testing.T) {
	// MarketingAllowed is the only sanctioned gate for the marketing purpose.
	// Under Art. 7(1) the controller must be able to demonstrate consent before
	// processing, so every state where it cannot must gate to no.
	yes := true
	tests := []struct {
		name string
		seed *service.IdentityData
	}{
		{"imported opt-in is not consent", gdprStamped(true, service.ConsentSourceImport, "beon3")},
		{"legacy bare bool is not consent", &service.IdentityData{MarketingEmails: &yes}},
		{"no profile stored at all", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := gdprIdentityRepo()
			svc := gdprIdentityService(repo)
			if tc.seed != nil {
				if err := svc.Upsert(context.Background(), "user-1", tc.seed); err != nil {
					t.Fatalf("seed: %v", err)
				}
			}
			allowed, err := svc.MarketingAllowed(context.Background(), "user-1")
			if err != nil {
				t.Fatalf("MarketingAllowed: %v", err)
			}
			if allowed {
				t.Error("Art. 7: a state with no demonstrable consent must not authorise sending")
			}
		})
	}
}

func TestGDPR_Art7_MarketingAllowedRepoErrorFailsClosed(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		GetByPseudonymFn: func(context.Context, string) (*model.IdentityProfile, error) {
			return nil, errors.New("identity store unavailable")
		},
	}
	allowed, err := gdprIdentityService(repo).MarketingAllowed(context.Background(), "user-1")
	if err == nil {
		t.Error("a failed consent lookup must surface, not be swallowed")
	}
	if allowed {
		t.Error("Art. 7: a failed lookup must gate to no, never to yes")
	}
}

// --- Art. 7(1) anti-laundering: an echo of a stored value is not a new act ---

func TestGDPR_Art7_1_EchoDoesNotLaunderImport(t *testing.T) {
	// GET /user/identity returns the bare bool, so a profile form round-trips
	// marketing_emails=true for an imported flag the user never chose. If the
	// full-replace write re-stamped that echo as source=profile, the import
	// would be laundered into demonstrable Art. 7 consent. An unchanged value
	// keeps the imported record exactly as it was: source, origin and time.
	importedAt := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)
	imported := &service.ConsentRecord{
		Granted: true,
		At:      importedAt,
		Source:  service.ConsentSourceImport,
		Origin:  "beon3",
	}

	d := &service.IdentityData{}
	yes := true
	changed := d.ReconcileMarketingConsent(&yes, imported)

	if changed {
		t.Error("an unchanged round-trip is not a consent event")
	}
	rec := d.MarketingConsent
	if rec == nil {
		t.Fatal("consent record dropped by the round-trip")
	}
	if rec.Source != service.ConsentSourceImport {
		t.Errorf("Art. 7(1): source = %q, want %q -- imported consent was laundered", rec.Source, service.ConsentSourceImport)
	}
	if rec.Origin != "beon3" {
		t.Errorf("origin = %q, want %q", rec.Origin, "beon3")
	}
	if !rec.At.Equal(importedAt) {
		t.Errorf("consent time rewritten: %v, want %v", rec.At, importedAt)
	}
	if rec.Affirmative() {
		t.Error("an imported flag must not become affirmative by being echoed back")
	}
}

func TestGDPR_Art7_1_RealChangeIsStampedAsProfile(t *testing.T) {
	// Actually unticking an imported true is a real act by the user: it is
	// stamped with source=profile, sheds the import origin, and is reported as
	// a consent event for the audit trail.
	imported := &service.ConsentRecord{
		Granted: true,
		At:      time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC),
		Source:  service.ConsentSourceImport,
		Origin:  "beon3",
	}

	d := &service.IdentityData{}
	no := false
	changed := d.ReconcileMarketingConsent(&no, imported)

	if !changed {
		t.Error("a real change must be reported as a consent event")
	}
	rec := d.MarketingConsent
	if rec == nil {
		t.Fatal("no consent record stamped")
	}
	if rec.Source != service.ConsentSourceProfile {
		t.Errorf("source = %q, want %q", rec.Source, service.ConsentSourceProfile)
	}
	if rec.Granted {
		t.Error("the recorded value must be the withdrawal the user chose")
	}
	if rec.Origin != "" {
		t.Errorf("a fresh act must not inherit the import origin, got %q", rec.Origin)
	}
	if d.MarketingEmails == nil || *d.MarketingEmails {
		t.Error("preference bool must follow the withdrawal")
	}
}

// --- Art. 7(3): withdrawal shall be as easy as giving consent ---

func TestGDPR_Art7_3_UnsubscribeWithdrawsConsent(t *testing.T) {
	// Granting is one checkbox, so withdrawal is one authenticated POST with no
	// body and no confirmation step. The withdrawal must land with unsubscribe
	// provenance so the controller can show it was honoured.
	repo := gdprIdentityRepo()
	svc := gdprIdentityService(repo)
	ctx := context.Background()

	if err := svc.Upsert(ctx, "user-1", gdprStamped(true, service.ConsentSourceProfile, "")); err != nil {
		t.Fatalf("seed: %v", err)
	}

	h := handler.NewIdentityHandler(svc, nil)
	rec := httptest.NewRecorder()
	h.Unsubscribe(rec, gdprAuthedRequest(http.MethodPost, "/user/marketing/unsubscribe", "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "unsubscribed") {
		t.Errorf("body = %q, want an unsubscribed confirmation", rec.Body.String())
	}

	data, _, err := svc.Get(ctx, "user-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if data == nil || data.MarketingConsent == nil {
		t.Fatal("Art. 7(3): withdrawal was not recorded")
	}
	if data.MarketingConsent.Granted {
		t.Error("Art. 7(3): consent still granted after unsubscribe")
	}
	if data.MarketingConsent.Source != service.ConsentSourceUnsubscribe {
		t.Errorf("source = %q, want %q", data.MarketingConsent.Source, service.ConsentSourceUnsubscribe)
	}
	if data.MarketingEmails == nil || *data.MarketingEmails {
		t.Error("preference bool must follow the recorded withdrawal")
	}
}
