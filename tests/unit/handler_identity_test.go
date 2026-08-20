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

// The name fields are capped at 100 runes and an over-long value is truncated
// rather than refused, so the response code is 200 either way and says nothing
// about what was kept. The five functions this replaces all stopped at that 200
// -- two of them captured the ciphertext and then only checked it was non-nil --
// so a truncate() that returned "" or that cut on bytes would have passed every
// one of them. Each row here reads the profile back through the service that
// wrote it and asserts the stored rune count.
//
// The CJK row is why the count is in runes: 101 three-byte runes is 303 bytes,
// and a byte-wise cut at 100 leaves 33 characters and a fragment of a fourth.
func TestIdentityPut_NameTruncation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		field     string
		value     string
		wantRunes int
	}{
		{name: "given name at the cap is kept whole", field: "given_name", value: strings.Repeat("A", 100), wantRunes: 100},
		{name: "given name one over the cap is cut to it", field: "given_name", value: strings.Repeat("B", 101), wantRunes: 100},
		{name: "family name at the cap is kept whole", field: "family_name", value: strings.Repeat("C", 100), wantRunes: 100},
		{name: "family name one over the cap is cut to it", field: "family_name", value: strings.Repeat("D", 101), wantRunes: 100},
		{name: "multi-byte runes are counted as runes", field: "given_name", value: strings.Repeat("\u4e16", 101), wantRunes: 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stored *model.IdentityProfile
			h := newIdentityTestHandler(&mocks.MockIdentityRepo{
				UpsertFn: func(_ context.Context, p *model.IdentityProfile) error {
					stored = p
					return nil
				},
			})

			w := identityPut(t, h, `{"`+tc.field+`":"`+tc.value+`"}`)
			if w.Code != http.StatusOK {
				t.Fatalf("%s of %d runes answered %d, want 200: %s",
					tc.field, utf8.RuneCountInString(tc.value), w.Code, w.Body.String())
			}
			if stored == nil {
				t.Fatal("the handler answered 200 without writing a profile")
			}

			// A second service over the same key material decrypts what the
			// handler's own service wrote, which is the only way to see the
			// stored value: the profile is one encrypted blob.
			readBack := service.NewIdentityService(
				&mocks.MockIdentityRepo{
					GetByPseudonymFn: func(_ context.Context, _ string) (*model.IdentityProfile, error) {
						return stored, nil
					},
				}, identityTestMasterKey(), identityTestHMACSecret())
			data, _, err := readBack.Get(context.Background(), testUserID)
			if err != nil {
				t.Fatalf("read the stored profile back: %v", err)
			}
			if data == nil {
				t.Fatal("the stored profile decrypted to nothing")
			}

			got := data.GivenName
			if tc.field == "family_name" {
				got = data.FamilyName
			}
			if n := utf8.RuneCountInString(got); n != tc.wantRunes {
				t.Fatalf("%s was stored as %d runes, want %d (sent %d)",
					tc.field, n, tc.wantRunes, utf8.RuneCountInString(tc.value))
			}
			if !strings.HasPrefix(tc.value, got) {
				t.Fatalf("%s was stored as %q, which is not a prefix of what was sent; "+
					"truncation must keep the leading characters", tc.field, got)
			}
		})
	}
}

// Sex is a legacy-platform parity enum {male,female,""} (maps to UserProfile.Gender 0/1),
// not free text — a valid value is accepted, anything else is rejected.
func TestIdentityPut_SexFieldValidEnum(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	for _, sex := range []string{"male", "female", ""} {
		body := `{"sex":"` + sex + `"}`
		w := identityPut(t, h, body)
		if w.Code != http.StatusOK {
			t.Fatalf("sex=%q should be accepted, got %d: %s", sex, w.Code, w.Body.String())
		}
	}
}

func TestIdentityPut_SexFieldInvalidRejected(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	h := newIdentityTestHandler(repo)

	body := `{"sex":"` + strings.Repeat("X", 51) + `"}`
	w := identityPut(t, h, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid sex should be 400 invalid_profile, got %d: %s", w.Code, w.Body.String())
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

// validateIdentity refuses a date_of_birth for three separate reasons -- a
// shape the regex does not match, a shape it does match that names no real day,
// and a real day that has not happened yet -- and answers all three with the
// same "invalid_date_of_birth", so an assertion on the error string cannot tell
// them apart. Each row therefore records its reason in its name and its input,
// and the rows must not be collapsed into "some bad dates are refused": a
// future date that stopped being refused would still satisfy every other row.
func TestIdentityPut_DateOfBirthValidation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dob      string
		wantCode int
	}{
		{name: "Feb 29 in a leap year is a real day", dob: "2000-02-29", wantCode: http.StatusOK},
		{name: "the earliest date the platform carries", dob: "1900-01-01", wantCode: http.StatusOK},
		{name: "Feb 29 outside a leap year names no day", dob: "2001-02-29", wantCode: http.StatusBadRequest},
		{name: "month 13 names no month", dob: "1990-13-01", wantCode: http.StatusBadRequest},
		{name: "April has no 31st", dob: "1990-04-31", wantCode: http.StatusBadRequest},
		{name: "a well-formed date that has not happened yet", dob: "2099-12-31", wantCode: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newIdentityTestHandler(&mocks.MockIdentityRepo{
				UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
			})

			w := identityPut(t, h, `{"date_of_birth":"`+tc.dob+`"}`)
			if w.Code != tc.wantCode {
				t.Fatalf("date_of_birth %q (%s) answered %d, want %d: %s",
					tc.dob, tc.name, w.Code, tc.wantCode, w.Body.String())
			}
			if tc.wantCode == http.StatusOK {
				return
			}

			var resp map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode the rejection of %q: %v", tc.dob, err)
			}
			if resp["error"] != "invalid_date_of_birth" {
				t.Fatalf("date_of_birth %q was refused as %v, want invalid_date_of_birth",
					tc.dob, resp["error"])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Country code validation
// ---------------------------------------------------------------------------

// The country code is ^[A-Z]{2}$: uppercase, exactly two, letters only. The
// rejected rows below are one broken constraint each, so a regex that loses one
// of the three fails a named row rather than the whole set at once. Empty is
// accepted because the field is optional -- an absent country and a malformed
// one are different answers.
//
// The billing address carries a country of its own under a separate error code,
// so the field the code arrived in is a column rather than a second table: an
// address error reported as a profile error sends the caller to the wrong form.
func TestIdentityPut_CountryCodeValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		code      string
		billing   bool
		wantCode  int
		wantError string
	}{
		{name: "US", code: "US", wantCode: http.StatusOK},
		{name: "SK", code: "SK", wantCode: http.StatusOK},
		{name: "HU", code: "HU", wantCode: http.StatusOK},
		{name: "DE", code: "DE", wantCode: http.StatusOK},
		{name: "JP", code: "JP", wantCode: http.StatusOK},
		{name: "empty is the optional field being omitted", code: "", wantCode: http.StatusOK},
		{name: "lowercase", code: "us", wantCode: http.StatusBadRequest, wantError: "invalid_country"},
		{name: "mixed case", code: "Us", wantCode: http.StatusBadRequest, wantError: "invalid_country"},
		{name: "alpha-3 rather than alpha-2", code: "USA", wantCode: http.StatusBadRequest, wantError: "invalid_country"},
		{name: "one letter", code: "U", wantCode: http.StatusBadRequest, wantError: "invalid_country"},
		{name: "digits", code: "12", wantCode: http.StatusBadRequest, wantError: "invalid_country"},
		{name: "billing lowercase", code: "sk", billing: true, wantCode: http.StatusBadRequest, wantError: "invalid_billing_country"},
		{name: "billing valid", code: "SK", billing: true, wantCode: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newIdentityTestHandler(&mocks.MockIdentityRepo{
				UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
			})

			body := `{"country":"` + tc.code + `"}`
			where := "country"
			if tc.billing {
				body = `{"billing":{"country":"` + tc.code + `"}}`
				where = "billing.country"
			}

			w := identityPut(t, h, body)
			if w.Code != tc.wantCode {
				t.Fatalf("%s=%q answered %d, want %d: %s", where, tc.code, w.Code, tc.wantCode, w.Body.String())
			}
			if tc.wantError == "" {
				return
			}

			var resp map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode the rejection of %s=%q: %v", where, tc.code, err)
			}
			if resp["error"] != tc.wantError {
				t.Fatalf("%s=%q was refused as %v, want %s", where, tc.code, resp["error"], tc.wantError)
			}
		})
	}
}
