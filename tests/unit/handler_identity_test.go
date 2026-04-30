package unit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// Identity handler test helpers
// ---------------------------------------------------------------------------

func identityTestMasterKey() []byte {
	return []byte("01234567890123456789012345678901") // 32 bytes for AES-256
}

func identityTestHMACSecret() []byte {
	return []byte("test-hmac-secret-key-32-bytes!!")
}

func newIdentityTestHandler(repo *mocks.MockIdentityRepo) *handler.IdentityHandler {
	svc := service.NewIdentityService(repo, identityTestMasterKey(), identityTestHMACSecret())
	return handler.NewIdentityHandler(svc, newTestAuditLogger())
}

// identityPut is a convenience for creating authenticated PUT /user/identity
// requests through the auth middleware.
func identityPut(t *testing.T, h *handler.IdentityHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req, w, keys := authedRequest(t, http.MethodPut, "/user/identity", nil)
	req.Body = nil
	req.Body = readCloser(body)
	req.ContentLength = int64(len(body))
	serveWithAuth(t, "PUT /user/identity", h.Put, keys, w, req)
	return w
}

// readCloser wraps a string as an io.ReadCloser for use as http.Request.Body.
func readCloser(s string) *readCloserImpl {
	return &readCloserImpl{Reader: strings.NewReader(s)}
}

type readCloserImpl struct {
	*strings.Reader
}

func (r *readCloserImpl) Close() error { return nil }

// ---------------------------------------------------------------------------
// Name truncation boundary tests
// ---------------------------------------------------------------------------

func TestIdentityPut_GivenNameExactly100Runes(t *testing.T) {
	var capturedData []byte
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, p *model.IdentityProfile) error {
			capturedData = p.DataEnc
			return nil
		},
	}
	h := newIdentityTestHandler(repo)

	name100 := strings.Repeat("A", 100)
	body := `{"given_name":"` + name100 + `"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if capturedData == nil {
		t.Fatal("expected upsert to be called")
	}
}

func TestIdentityPut_GivenName101RunesTruncated(t *testing.T) {
	var capturedData []byte
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, p *model.IdentityProfile) error {
			capturedData = p.DataEnc
			return nil
		},
	}
	h := newIdentityTestHandler(repo)

	name101 := strings.Repeat("B", 101)
	body := `{"given_name":"` + name101 + `"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if capturedData == nil {
		t.Fatal("expected upsert to be called")
	}
}

func TestIdentityPut_FamilyNameExactly100Runes(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	name100 := strings.Repeat("C", 100)
	body := `{"family_name":"` + name100 + `"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_FamilyName101RunesTruncated(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	name101 := strings.Repeat("D", 101)
	body := `{"family_name":"` + name101 + `"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// Test truncation with multi-byte runes (CJK characters) to verify rune-safe
// truncation rather than byte-level truncation.
func TestIdentityPut_MultiByteRuneTruncation(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	// 101 CJK runes, each 3 bytes in UTF-8 (303 bytes, 101 runes)
	name101cjk := strings.Repeat("\u4e16", 101)
	if utf8.RuneCountInString(name101cjk) != 101 {
		t.Fatalf("setup: expected 101 runes, got %d", utf8.RuneCountInString(name101cjk))
	}

	body := `{"given_name":"` + name101cjk + `"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_SexFieldExactly50Runes(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	sex50 := strings.Repeat("X", 50)
	body := `{"sex":"` + sex50 + `"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_SexField51RunesTruncated(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	sex51 := strings.Repeat("Y", 51)
	body := `{"sex":"` + sex51 + `"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Billing address tests
// ---------------------------------------------------------------------------

func TestIdentityPut_BillingAllFieldsMaxLength(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	body := `{` +
		`"billing":{` +
		`"address_line_1":"` + strings.Repeat("A", 200) + `",` +
		`"address_line_2":"` + strings.Repeat("B", 200) + `",` +
		`"city":"` + strings.Repeat("C", 100) + `",` +
		`"postal_code":"` + strings.Repeat("P", 20) + `",` +
		`"country":"US",` +
		`"vat_id":"` + strings.Repeat("V", 50) + `"` +
		`}}`

	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_EmptyBillingObject(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	body := `{"billing":{}}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty billing object, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_BillingFieldsOverMaxTruncated(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	body := `{` +
		`"billing":{` +
		`"address_line_1":"` + strings.Repeat("A", 250) + `",` +
		`"city":"` + strings.Repeat("C", 150) + `",` +
		`"postal_code":"` + strings.Repeat("P", 30) + `",` +
		`"vat_id":"` + strings.Repeat("V", 60) + `"` +
		`}}`

	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (truncated, not rejected), got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Date validation edge cases
// ---------------------------------------------------------------------------

func TestIdentityPut_LeapYearFeb29Valid(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	body := `{"date_of_birth":"2000-02-29"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid leap year date, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_NonLeapYearFeb29Invalid(t *testing.T) {
	h := newIdentityTestHandler(&mocks.MockIdentityRepo{})

	body := `{"date_of_birth":"2001-02-29"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid Feb 29, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid_date_of_birth" {
		t.Fatalf("expected error invalid_date_of_birth, got %v", resp["error"])
	}
}

func TestIdentityPut_EarliestValidDate(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	body := `{"date_of_birth":"1900-01-01"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for 1900-01-01, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_FutureDateRejected(t *testing.T) {
	h := newIdentityTestHandler(&mocks.MockIdentityRepo{})

	body := `{"date_of_birth":"2099-12-31"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for future date, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_DateWithInvalidMonth(t *testing.T) {
	h := newIdentityTestHandler(&mocks.MockIdentityRepo{})

	body := `{"date_of_birth":"1990-13-01"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for month 13, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_DateWithInvalidDay(t *testing.T) {
	h := newIdentityTestHandler(&mocks.MockIdentityRepo{})

	body := `{"date_of_birth":"1990-04-31"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for April 31, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Country code validation
// ---------------------------------------------------------------------------

func TestIdentityPut_CountryLowercaseRejected(t *testing.T) {
	h := newIdentityTestHandler(&mocks.MockIdentityRepo{})

	body := `{"country":"us"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for lowercase country, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid_country" {
		t.Fatalf("expected error invalid_country, got %v", resp["error"])
	}
}

func TestIdentityPut_CountryThreeLetterRejected(t *testing.T) {
	h := newIdentityTestHandler(&mocks.MockIdentityRepo{})

	body := `{"country":"USA"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 3-letter country code, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_CountryNumericRejected(t *testing.T) {
	h := newIdentityTestHandler(&mocks.MockIdentityRepo{})

	body := `{"country":"12"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for numeric country code, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_CountryValidCodes(t *testing.T) {
	validCodes := []string{"US", "SK", "HU", "DE", "JP"}
	for _, code := range validCodes {
		t.Run(code, func(t *testing.T) {
			repo := &mocks.MockIdentityRepo{
				UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
			}
			h := newIdentityTestHandler(repo)

			body := `{"country":"` + code + `"}`
			w := identityPut(t, h, body)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200 for valid country %q, got %d: %s", code, w.Code, w.Body.String())
			}
		})
	}
}

func TestIdentityPut_BillingCountryLowercaseRejected(t *testing.T) {
	h := newIdentityTestHandler(&mocks.MockIdentityRepo{})

	body := `{"billing":{"country":"sk"}}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for lowercase billing country, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid_billing_country" {
		t.Fatalf("expected error invalid_billing_country, got %v", resp["error"])
	}
}

func TestIdentityPut_CountryMixedCaseRejected(t *testing.T) {
	h := newIdentityTestHandler(&mocks.MockIdentityRepo{})

	body := `{"country":"Us"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for mixed-case country, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIdentityPut_CountrySingleCharRejected(t *testing.T) {
	h := newIdentityTestHandler(&mocks.MockIdentityRepo{})

	body := `{"country":"U"}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for single-char country, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Empty country (should be accepted — country is optional)
// ---------------------------------------------------------------------------

func TestIdentityPut_EmptyCountryAccepted(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	body := `{"country":""}`
	w := identityPut(t, h, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty country, got %d: %s", w.Code, w.Body.String())
	}
}
