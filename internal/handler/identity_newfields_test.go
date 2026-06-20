package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// WS1.4: the new the legacy platform profile fields must round-trip through PUT → GET.
func TestIdentityPut_NewFieldsRoundTrip(t *testing.T) {
	var stored *model.IdentityProfile
	repo := &mocks.MockIdentityRepo{
		UpsertFn:         func(_ context.Context, p *model.IdentityProfile) error { stored = p; return nil },
		GetByPseudonymFn: func(_ context.Context, _ string) (*model.IdentityProfile, error) { return stored, nil },
	}
	h := newTestIdentityHandler(repo)

	body := `{"given_name":"Ada","username":"ada","country":"GB","state":"ENG","sex":"female","marketing_emails":true,"dynamic":{"legacy.forum":{"reputation":42}}}`
	req := setAuthContext(httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body)), "user-123")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body=%s", rec.Code, rec.Body.String())
	}

	grec := httptest.NewRecorder()
	h.Get(grec, setAuthContext(httptest.NewRequest(http.MethodGet, "/user/identity", nil), "user-123"))
	if grec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body=%s", grec.Code, grec.Body.String())
	}
	var resp IdentityResponse
	if err := json.Unmarshal(grec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Username != "ada" || resp.State != "ENG" {
		t.Fatalf("new fields lost: %+v", resp)
	}
	if resp.MarketingEmails == nil || !*resp.MarketingEmails {
		t.Fatal("marketing flag lost")
	}
	if string(resp.Dynamic["legacy.forum"]) != `{"reputation":42}` {
		t.Fatalf("dynamic lost: %s", resp.Dynamic["legacy.forum"])
	}
}

// A malformed dynamic namespace key must be rejected as 400 (the service
// Validate gate surfaced as a client error, not a 500).
func TestIdentityPut_DynamicAbuseRejected(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error {
			t.Error("Upsert should not persist an invalid profile")
			return nil
		},
	}
	h := newTestIdentityHandler(repo)

	body := `{"dynamic":{"the legacy platform Bad Key":{"x":1}}}`
	req := setAuthContext(httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body)), "user-123")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("dynamic abuse should be 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}
