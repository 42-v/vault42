package adminapi

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// importConsentFixture wires a handler whose imports persist a real (encrypted)
// identity profile, and hands back the user ID the handler generated so the test
// can read the consent record back the way production would.
type importConsentFixture struct {
	h      *Handler
	svc    *service.IdentityService
	userID *string
}

func newImportConsentFixture(upsertErr error) *importConsentFixture {
	var userID string
	var stored *model.IdentityProfile

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
		CreateImportedFn: func(_ context.Context, u *model.User) error {
			userID = u.ID
			return nil
		},
	}
	identityRepo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, p *model.IdentityProfile) error {
			if upsertErr != nil {
				return upsertErr
			}
			stored = p
			return nil
		},
		GetByPseudonymFn: func(context.Context, string) (*model.IdentityProfile, error) {
			return stored, nil
		},
	}

	svc := service.NewIdentityService(identityRepo, make([]byte, 32), []byte("test-hmac-secret"))
	return &importConsentFixture{
		h:      &Handler{users: users, identity: svc},
		svc:    svc,
		userID: &userID,
	}
}

// An imported marketing flag must land as source=import with the origin recorded,
// and must NOT read as affirmative consent. BeOn3's column defaults to true and
// its consent checkbox ships pre-ticked, so a migrated `true` is indistinguishable
// from a value the user never chose — treating it as consent would mail people
// who never opted in (Recital 32; Planet49, C-673/17).
func TestImportUsers_MarketingFlagIsNotAffirmativeConsent(t *testing.T) {
	f := newImportConsentFixture(nil)

	rec, out := doImport(t, f.h, `{"source":"beon3","users":[
		{"email":"rider@example.com","marketing_emails":true}
	]}`)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if out["imported"] != float64(1) {
		t.Fatalf("imported = %v, want 1", out["imported"])
	}
	if out["consent_failed"] != float64(0) {
		t.Errorf("consent_failed = %v, want 0", out["consent_failed"])
	}

	data, _, err := f.svc.Get(context.Background(), *f.userID)
	if err != nil {
		t.Fatalf("read back profile: %v", err)
	}
	got := data.MarketingConsent
	if got == nil {
		t.Fatal("no consent record persisted for the imported account")
	}
	if !got.Granted {
		t.Error("the imported value should be preserved (granted=true)")
	}
	if got.Source != service.ConsentSourceImport {
		t.Errorf("source = %q, want %q", got.Source, service.ConsentSourceImport)
	}
	if got.Origin != "beon3" {
		t.Errorf("origin = %q, want %q", got.Origin, "beon3")
	}
	if got.Affirmative() {
		t.Error("an imported flag must never by itself authorize sending")
	}
}

// Without an identity service the accounts must still import; the preference is
// dropped, which fails closed (no consent) rather than failing the migration.
func TestImportUsers_NoIdentityServiceStillImports(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn:     func(context.Context, string) (*model.User, error) { return nil, nil },
		CreateImportedFn: func(context.Context, *model.User) error { return nil },
	}
	h := &Handler{users: users} // identity deliberately nil

	rec, out := doImport(t, h, `{"source":"beon3","users":[
		{"email":"rider@example.com","marketing_emails":true}
	]}`)

	if rec.Code != 200 || out["imported"] != float64(1) {
		t.Fatalf("import should still succeed without an identity service: status=%d out=%v", rec.Code, out)
	}
}

// A preference that cannot be stored must be counted, not swallowed — and must
// not fail the account import that already succeeded.
func TestImportUsers_ConsentWriteFailureIsCounted(t *testing.T) {
	f := newImportConsentFixture(errors.New("db down"))

	rec, out := doImport(t, f.h, `{"source":"beon3","users":[
		{"email":"rider@example.com","marketing_emails":true}
	]}`)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if out["imported"] != float64(1) {
		t.Errorf("the account import must survive a consent write failure: imported = %v", out["imported"])
	}
	if out["consent_failed"] != float64(1) {
		t.Errorf("consent_failed = %v, want 1", out["consent_failed"])
	}
}
