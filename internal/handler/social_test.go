package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

func socialAuthedRequest(method, target, subject string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: subject},
	}
	return req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
}

// Unlink must scope the delete to the caller. If the user ID were dropped, any
// authenticated user could unlink another account's provider by guessing a link
// ID — and the encrypted provider tokens would go with it.
func TestSocialUnlink_ScopesDeleteToCaller(t *testing.T) {
	social := &mocks.MockSocialAccountRepo{}
	var gotID, gotUserID string
	social.DeleteFn = func(_ context.Context, id, userID string) error {
		gotID, gotUserID = id, userID
		return nil
	}

	h := NewSocialHandler(social, newTestAuditLogger())

	req := socialAuthedRequest(http.MethodDelete, "/user/social/link-1", "user-1")
	req.SetPathValue("id", "link-1")
	rec := httptest.NewRecorder()

	h.Unlink(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotID != "link-1" {
		t.Errorf("link id = %q, want %q", gotID, "link-1")
	}
	if gotUserID != "user-1" {
		t.Errorf("delete not scoped to caller: user id = %q, want %q", gotUserID, "user-1")
	}
}

// The listing is what a user sees about their own federated links. It must never
// carry the encrypted provider access/refresh tokens.
func TestSocialList_OmitsProviderTokens(t *testing.T) {
	social := &mocks.MockSocialAccountRepo{}
	social.ListByUserFn = func(context.Context, string) ([]*model.SocialAccount, error) {
		return []*model.SocialAccount{{
			ID: "link-1", Provider: "google", Email: "u@example.com",
			AccessTokenEnc: "SECRET-ACCESS", RefreshTokenEnc: "SECRET-REFRESH",
		}}, nil
	}

	h := NewSocialHandler(social, newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.List(rec, socialAuthedRequest(http.MethodGet, "/user/social", "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "SECRET-") {
		t.Errorf("response leaked encrypted provider tokens: %s", body)
	}

	var resp struct {
		Accounts []socialAccountView `json:"accounts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Accounts) != 1 || resp.Accounts[0].Provider != "google" {
		t.Fatalf("unexpected accounts: %+v", resp.Accounts)
	}
}

func TestSocial_RequiresAuth(t *testing.T) {
	h := NewSocialHandler(&mocks.MockSocialAccountRepo{}, newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/user/social", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("List status = %d, want 401", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.Unlink(rec, httptest.NewRequest(http.MethodDelete, "/user/social/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Unlink status = %d, want 401", rec.Code)
	}
}

func TestSocialUnlink_MissingID(t *testing.T) {
	h := NewSocialHandler(&mocks.MockSocialAccountRepo{}, newTestAuditLogger())
	rec := httptest.NewRecorder()
	h.Unlink(rec, socialAuthedRequest(http.MethodDelete, "/user/social/", "user-1"))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// A failed unlink must not report success: the caller would believe the provider
// tokens were removed when they are still there.
func TestSocialUnlink_RepoFailureDoesNotClaimSuccess(t *testing.T) {
	social := &mocks.MockSocialAccountRepo{
		DeleteFn: func(context.Context, string, string) error { return errors.New("db down") },
	}
	h := NewSocialHandler(social, newTestAuditLogger())

	req := socialAuthedRequest(http.MethodDelete, "/user/social/link-1", "user-1")
	req.SetPathValue("id", "link-1")
	rec := httptest.NewRecorder()
	h.Unlink(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestSocialList_RepoFailure(t *testing.T) {
	social := &mocks.MockSocialAccountRepo{
		ListByUserFn: func(context.Context, string) ([]*model.SocialAccount, error) {
			return nil, errors.New("db down")
		},
	}
	h := NewSocialHandler(social, newTestAuditLogger())
	rec := httptest.NewRecorder()
	h.List(rec, socialAuthedRequest(http.MethodGet, "/user/social", "user-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// The linked-provider list hand-formatted its timestamp to whole seconds, so it
// was the one endpoint in the API whose created_at was encoded differently from
// every other created_at. A client parsing timestamps had to know which
// endpoint it was talking to.
func TestSocialList_TimestampMatchesTheRestOfTheAPI(t *testing.T) {
	created := time.Date(2026, 8, 10, 12, 34, 56, 123456000, time.UTC)

	social := &mocks.MockSocialAccountRepo{
		ListByUserFn: func(context.Context, string) ([]*model.SocialAccount, error) {
			return []*model.SocialAccount{{ID: "link-1", Provider: "google", CreatedAt: created}}, nil
		},
	}
	h := NewSocialHandler(social, newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.List(rec, socialAuthedRequest(http.MethodGet, "/user/social", "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp struct {
		Accounts []struct {
			CreatedAt string `json:"created_at"`
		} `json:"accounts"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(resp.Accounts))
	}
	if resp.Total != 1 {
		t.Errorf("total = %d, want 1", resp.Total)
	}

	want, err := created.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal reference time: %v", err)
	}
	if got := `"` + resp.Accounts[0].CreatedAt + `"`; got != string(want) {
		t.Errorf("created_at = %s, want %s: sub-second precision was dropped", got, want)
	}
}

// An account with no linked provider gets an empty array, not null.
func TestSocialList_NoLinksIsAnEmptyArray(t *testing.T) {
	social := &mocks.MockSocialAccountRepo{
		ListByUserFn: func(context.Context, string) ([]*model.SocialAccount, error) { return nil, nil },
	}
	h := NewSocialHandler(social, newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.List(rec, socialAuthedRequest(http.MethodGet, "/user/social", "user-1"))

	if body := rec.Body.String(); !strings.Contains(body, `"accounts":[]`) {
		t.Errorf("an account with no links did not serialize accounts as []: %s", body)
	}
}
