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
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// Test helpers for identity
// ---------------------------------------------------------------------------

func identityMasterKey() []byte {
	return []byte("01234567890123456789012345678901") // 32 bytes for AES-256
}

func identityHMACSecret() []byte {
	return []byte("test-hmac-secret-key-32-bytes!!")
}

func newTestIdentityService(repo *mocks.MockIdentityRepo) *service.IdentityService {
	return service.NewIdentityService(repo, identityMasterKey(), identityHMACSecret())
}

func newTestIdentityHandler(repo *mocks.MockIdentityRepo) *IdentityHandler {
	svc := newTestIdentityService(repo)
	return NewIdentityHandler(svc, newTestAuditLogger())
}

// encryptTestData encrypts data using the test master key for test data setup.
// AAD is set to the pseudonym for the given user to match the service's decrypt path.
func encryptTestData(t *testing.T, data []byte, userID string) []byte {
	t.Helper()
	svc := service.NewIdentityService(nil, identityMasterKey(), identityHMACSecret())
	pseudo := svc.Pseudonym(userID)
	enc, err := vaultcrypto.Encrypt(data, identityMasterKey(), []byte(pseudo))
	if err != nil {
		t.Fatalf("encrypt test data: %v", err)
	}
	return enc
}

// ---------------------------------------------------------------------------
// GET /user/identity
// ---------------------------------------------------------------------------

func TestIdentityGet_Success(t *testing.T) {
	data := &service.IdentityData{
		GivenName:   "Jane",
		FamilyName:  "Doe",
		Country:     "SK",
		DateOfBirth: "1990-01-15",
		Sex:         "female",
	}
	plaintext, _ := json.Marshal(data)
	enc := encryptTestData(t, plaintext, "user-123")
	now := time.Now()

	repo := &mocks.MockIdentityRepo{
		GetByPseudonymFn: func(_ context.Context, _ string) (*model.IdentityProfile, error) {
			return &model.IdentityProfile{
				PseudonymID: "pseudo-123",
				DataEnc:     enc,
				Version:     1,
				UpdatedAt:   now,
				CreatedAt:   now,
			}, nil
		},
	}

	h := NewIdentityHandler(service.NewIdentityService(repo, identityMasterKey(), identityHMACSecret()), newTestAuditLogger())

	req := httptest.NewRequest(http.MethodGet, "/user/identity", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["given_name"] != "Jane" {
		t.Fatalf("expected given_name=Jane, got %v", result["given_name"])
	}
	if result["family_name"] != "Doe" {
		t.Fatalf("expected family_name=Doe, got %v", result["family_name"])
	}
	if result["country"] != "SK" {
		t.Fatalf("expected country=SK, got %v", result["country"])
	}
	if result["sex"] != "female" {
		t.Fatalf("expected sex=female, got %v", result["sex"])
	}
}

func TestIdentityGet_WithBilling(t *testing.T) {
	data := &service.IdentityData{
		GivenName: "Test",
		Billing: &service.BillingInfo{
			AddressLine1: "Main St 1",
			City:         "Bratislava",
			Country:      "SK",
		},
	}
	plaintext, _ := json.Marshal(data)
	enc := encryptTestData(t, plaintext, "user-123")
	now := time.Now()

	repo := &mocks.MockIdentityRepo{
		GetByPseudonymFn: func(_ context.Context, _ string) (*model.IdentityProfile, error) {
			return &model.IdentityProfile{
				PseudonymID: "pseudo-123",
				DataEnc:     enc,
				Version:     1,
				UpdatedAt:   now,
				CreatedAt:   now,
			}, nil
		},
	}

	h := NewIdentityHandler(service.NewIdentityService(repo, identityMasterKey(), identityHMACSecret()), newTestAuditLogger())

	req := httptest.NewRequest(http.MethodGet, "/user/identity", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	billing, ok := result["billing"]
	if !ok || billing == nil {
		t.Fatal("expected billing in response")
	}
}

func TestIdentityGet_NotFound(t *testing.T) {
	repo := &mocks.MockIdentityRepo{} // default returns nil, nil
	h := newTestIdentityHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/user/identity", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Get(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIdentityGet_Unauthorized(t *testing.T) {
	h := newTestIdentityHandler(&mocks.MockIdentityRepo{})

	req := httptest.NewRequest(http.MethodGet, "/user/identity", nil)
	rec := httptest.NewRecorder()

	h.Get(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestIdentityGet_DBError(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		GetByPseudonymFn: func(_ context.Context, _ string) (*model.IdentityProfile, error) {
			return nil, errors.New("db connection lost")
		},
	}
	h := newTestIdentityHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/user/identity", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Get(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// PUT /user/identity
// ---------------------------------------------------------------------------

func TestIdentityPut_Success(t *testing.T) {
	var upserted bool
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, p *model.IdentityProfile) error {
			upserted = true
			if p.PseudonymID == "" {
				t.Error("expected non-empty pseudonym ID")
			}
			if len(p.DataEnc) == 0 {
				t.Error("expected non-empty encrypted data")
			}
			return nil
		},
	}
	h := newTestIdentityHandler(repo)

	body := `{"given_name":"John","family_name":"Smith","country":"US","date_of_birth":"1985-06-15","sex":"male"}`
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !upserted {
		t.Error("expected upsert to be called")
	}
}

func TestIdentityPut_WithBilling(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newTestIdentityHandler(repo)

	body := `{"given_name":"Jane","family_name":"Doe","country":"SK","billing":{"address_line_1":"Main St 1","city":"Bratislava","postal_code":"81101","country":"SK"}}`
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIdentityPut_EmptyBody(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newTestIdentityHandler(repo)

	// Empty identity (all optional fields)
	body := `{}`
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIdentityPut_InvalidCountry(t *testing.T) {
	h := newTestIdentityHandler(&mocks.MockIdentityRepo{})

	body := `{"country":"XYZ"}`
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIdentityPut_InvalidCountry_Lowercase(t *testing.T) {
	h := newTestIdentityHandler(&mocks.MockIdentityRepo{})

	body := `{"country":"sk"}`
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIdentityPut_InvalidDateOfBirth_Format(t *testing.T) {
	h := newTestIdentityHandler(&mocks.MockIdentityRepo{})

	body := `{"date_of_birth":"15/01/1990"}`
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIdentityPut_InvalidDateOfBirth_Future(t *testing.T) {
	h := newTestIdentityHandler(&mocks.MockIdentityRepo{})

	body := `{"date_of_birth":"2099-01-01"}`
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIdentityPut_InvalidBillingCountry(t *testing.T) {
	h := newTestIdentityHandler(&mocks.MockIdentityRepo{})

	body := `{"billing":{"country":"INVALID"}}`
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIdentityPut_InvalidJSON(t *testing.T) {
	h := newTestIdentityHandler(&mocks.MockIdentityRepo{})

	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader("{bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIdentityPut_Unauthorized(t *testing.T) {
	h := newTestIdentityHandler(&mocks.MockIdentityRepo{})

	body := `{"given_name":"Test"}`
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestIdentityPut_DBError(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error {
			return errors.New("db write error")
		},
	}
	h := newTestIdentityHandler(repo)

	body := `{"given_name":"Test"}`
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestIdentityPut_TruncatesLongNames(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error {
			return nil
		},
	}
	h := newTestIdentityHandler(repo)

	longName := strings.Repeat("A", 200)
	body := `{"given_name":"` + longName + `"}`
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DELETE /user/identity
// ---------------------------------------------------------------------------

func TestIdentityDelete_Success(t *testing.T) {
	var deleted bool
	repo := &mocks.MockIdentityRepo{
		DeleteFn: func(_ context.Context, _ string) error {
			deleted = true
			return nil
		},
	}
	h := newTestIdentityHandler(repo)

	req := httptest.NewRequest(http.MethodDelete, "/user/identity", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !deleted {
		t.Error("expected delete to be called")
	}
}

func TestIdentityDelete_Unauthorized(t *testing.T) {
	h := newTestIdentityHandler(&mocks.MockIdentityRepo{})

	req := httptest.NewRequest(http.MethodDelete, "/user/identity", nil)
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestIdentityDelete_DBError(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		DeleteFn: func(_ context.Context, _ string) error {
			return errors.New("db delete error")
		},
	}
	h := newTestIdentityHandler(repo)

	req := httptest.NewRequest(http.MethodDelete, "/user/identity", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

func TestValidateIdentity_ValidEmptyFields(t *testing.T) {
	input := &identityInput{}
	if err := validateIdentity(input); err != nil {
		t.Fatalf("expected no error for empty fields, got %v", err)
	}
}

func TestValidateIdentity_ValidFull(t *testing.T) {
	input := &identityInput{
		GivenName:   "Jane",
		FamilyName:  "Doe",
		Country:     "US",
		DateOfBirth: "1990-01-15",
		Sex:         "female",
		Billing: &billingInput{
			AddressLine1: "123 Main St",
			City:         "Springfield",
			PostalCode:   "62701",
			Country:      "US",
		},
	}
	if err := validateIdentity(input); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxRunes int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello", 3, "hel"},
		{"", 5, ""},
		{"日本語テスト", 3, "日本語"},
	}

	for _, tt := range tests {
		result := truncate(tt.input, tt.maxRunes)
		if result != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxRunes, result, tt.expected)
		}
	}
}
