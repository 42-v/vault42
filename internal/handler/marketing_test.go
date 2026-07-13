package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

func testIdentityHandler(repo *mocks.MockIdentityRepo) *IdentityHandler {
	svc := service.NewIdentityService(repo, make([]byte, 32), []byte("test-hmac-secret"))
	return NewIdentityHandler(svc, newTestAuditLogger())
}

// storedConsent decrypts whatever the handler wrote back and returns the consent
// record, so the assertions are about persisted state rather than a mock call.
func storedConsent(t *testing.T, repo *mocks.MockIdentityRepo, stored **model.IdentityProfile) *service.ConsentRecord {
	t.Helper()
	if *stored == nil {
		t.Fatal("nothing was persisted")
	}
	svc := service.NewIdentityService(repo, make([]byte, 32), []byte("test-hmac-secret"))
	repo.GetByPseudonymFn = func(context.Context, string) (*model.IdentityProfile, error) {
		return *stored, nil
	}
	data, _, err := svc.Get(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	return data.MarketingConsent
}

// Withdrawal must be recorded as a withdrawal *with unsubscribe provenance*, not
// as a bare false — the source is what stops a later import from overwriting it
// with a legacy opt-in.
func TestUnsubscribe_StampsWithdrawal(t *testing.T) {
	repo := &mocks.MockIdentityRepo{}
	var stored *model.IdentityProfile

	existing := &service.IdentityData{GivenName: "Ada"}
	existing.StampMarketingConsent(true, service.ConsentSourceRegistration, "")
	svc := service.NewIdentityService(repo, make([]byte, 32), []byte("test-hmac-secret"))
	repo.UpsertFn = func(_ context.Context, p *model.IdentityProfile) error {
		stored = p
		return nil
	}
	if err := svc.Upsert(context.Background(), "user-1", existing); err != nil {
		t.Fatalf("seed: %v", err)
	}
	repo.GetByPseudonymFn = func(context.Context, string) (*model.IdentityProfile, error) {
		return stored, nil
	}

	h := testIdentityHandler(repo)
	rec := httptest.NewRecorder()
	h.Unsubscribe(rec, socialAuthedRequest(http.MethodPost, "/user/marketing/unsubscribe", "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	got := storedConsent(t, repo, &stored)
	if got == nil {
		t.Fatal("no consent record persisted")
	}
	if got.Granted {
		t.Error("consent still granted after unsubscribe")
	}
	if got.Source != service.ConsentSourceUnsubscribe {
		t.Errorf("source = %q, want %q", got.Source, service.ConsentSourceUnsubscribe)
	}
	if got.Affirmative() {
		t.Error("a withdrawal must never read as affirmative consent")
	}
}

// A user with no identity profile must still get the withdrawal persisted.
// No-opping would leave nothing on record, and a later account import carrying a
// legacy opt-in could silently re-grant a consent the user already refused.
func TestUnsubscribe_NoProfileStillRecordsWithdrawal(t *testing.T) {
	repo := &mocks.MockIdentityRepo{}
	var stored *model.IdentityProfile

	repo.GetByPseudonymFn = func(context.Context, string) (*model.IdentityProfile, error) {
		return nil, nil // no profile yet
	}
	repo.UpsertFn = func(_ context.Context, p *model.IdentityProfile) error {
		stored = p
		return nil
	}

	h := testIdentityHandler(repo)
	rec := httptest.NewRecorder()
	h.Unsubscribe(rec, socialAuthedRequest(http.MethodPost, "/user/marketing/unsubscribe", "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if stored == nil {
		t.Fatal("withdrawal was not persisted for a user with no profile")
	}

	got := storedConsent(t, repo, &stored)
	if got == nil || got.Granted || got.Source != service.ConsentSourceUnsubscribe {
		t.Errorf("expected a recorded unsubscribe withdrawal, got %+v", got)
	}
}

func TestUnsubscribe_Unauthenticated(t *testing.T) {
	h := testIdentityHandler(&mocks.MockIdentityRepo{})
	rec := httptest.NewRecorder()
	h.Unsubscribe(rec, httptest.NewRequest(http.MethodPost, "/user/marketing/unsubscribe", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestUnsubscribe_ReadFailureDoesNotClaimSuccess(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		GetByPseudonymFn: func(context.Context, string) (*model.IdentityProfile, error) {
			return nil, errors.New("db down")
		},
	}
	h := testIdentityHandler(repo)
	rec := httptest.NewRecorder()
	h.Unsubscribe(rec, socialAuthedRequest(http.MethodPost, "/user/marketing/unsubscribe", "user-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 — a failed withdrawal must not report success", rec.Code)
	}
}

func TestUnsubscribe_WriteFailureDoesNotClaimSuccess(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		GetByPseudonymFn: func(context.Context, string) (*model.IdentityProfile, error) {
			return nil, nil
		},
		UpsertFn: func(context.Context, *model.IdentityProfile) error {
			return errors.New("db down")
		},
	}
	h := testIdentityHandler(repo)
	rec := httptest.NewRecorder()
	h.Unsubscribe(rec, socialAuthedRequest(http.MethodPost, "/user/marketing/unsubscribe", "user-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 — a failed withdrawal must not report success", rec.Code)
	}
}
