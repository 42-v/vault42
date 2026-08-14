package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// EU GDPR 2016/679 -- register-audit hardening.
// https://eur-lex.europa.eu/eli/reg/2016/679/oj
//
// Each of these seven rows was flagged "weak-met": the register pinned it to a
// source/doc grep (does data_export.go contain "WriteJSON"? does PRIVACY.md
// contain the word "processor"?) rather than to behaviour. These tests drive the
// SHIPPED code paths -- the real DataExportHandler, IdentityService, AuthService --
// or assert the substantive content of the real shipped policy, so a green here
// means the clause is actually honoured, not that a token appears in a file.
// =============================================================================

// auditGDPRMasterKey / auditGDPRHMAC mirror the keys gdprIdentityService uses, so
// a profile written through one service decrypts through another built the same
// way. The all-zero master key is a valid 32-byte AES-256 key; it only has to
// round-trip within the test.
func auditGDPRMasterKey() []byte { return make([]byte, 32) }
func auditGDPRHMAC() []byte      { return []byte("gdpr-compliance-hmac-secret") }

// auditGDPRPrivacyDoc reads the real shipped privacy policy. The register's weak
// rows greped this file for a single word; these tests assert its substantive
// clauses instead, so gutting a section fails the test.
func auditGDPRPrivacyDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../docs/PRIVACY.md")
	if err != nil {
		t.Fatalf("read shipped privacy policy: %v", err)
	}
	// Collapse every run of whitespace (including the markdown line wraps) to a
	// single space, so a substantive phrase is matched by its words, not by the
	// column the author happened to wrap it at.
	return strings.Join(strings.Fields(string(b)), " ")
}

// auditGDPRPutIdentity builds an authenticated PUT /user/identity request whose
// body is the given JSON. gdprAuthedRequest (in gdpr_consent_test.go) only builds
// bodiless requests, so the rectification/consent-write paths need this variant.
func auditGDPRPutIdentity(subject, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPut, "/user/identity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: subject},
	}
	return req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
}

// auditGDPRRunExport wires the REAL DataExportHandler over a stateful identity
// store (so the profile is genuinely encrypted on write and decrypted back out of
// the export) plus a real BlobService, and returns the recorded response. This is
// the end-to-end export the register never invoked.
func auditGDPRRunExport(
	t *testing.T,
	userID string,
	seed *service.IdentityData,
	users *mocks.MockUserRepo,
	devices *mocks.MockDeviceRepo,
	social *mocks.MockSocialAccountRepo,
	blobs *mocks.MockBlobRepo,
	auditEvents *mocks.MockAuditRepo,
) *httptest.ResponseRecorder {
	t.Helper()

	idRepo := gdprIdentityRepo()
	idSvc := gdprIdentityService(idRepo)
	if seed != nil {
		if err := idSvc.Upsert(context.Background(), userID, seed); err != nil {
			t.Fatalf("seed identity profile: %v", err)
		}
	}
	blobSvc := service.NewBlobService(blobs, auditGDPRMasterKey(), auditGDPRHMAC(), service.BlobConfig{
		MaxBlobSize:     1 << 20,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 << 20,
	})

	h := handler.NewDataExportHandler(users, devices, social, auditEvents, idSvc, blobSvc, nil, nil)
	rec := httptest.NewRecorder()
	h.Export(rec, gdprAuthedRequest(http.MethodGet, "/user/data-export", userID))
	return rec
}

// -----------------------------------------------------------------------------
// Art. 20 -- Right to data portability: a structured, commonly used,
// machine-readable format.
//
// Register weakness: TestGDPR_Art20_ExportIsStructuredAndMachineReadable only
// grepped data_export.go for "WriteJSON". It never invoked the export, never
// decoded the output, never checked the subject's own data was in it. This drives
// the shipped Export handler, proves the body is machine-readable (parses as
// JSON), structured (named category objects), and carries the subject's actual
// personal data across every category.
// -----------------------------------------------------------------------------

func TestGDPR_Art20_ExportShapeIsPortableJSON(t *testing.T) {
	const userID = "portability-subject-0001"
	now := time.Now().UTC().Truncate(time.Second)

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{
				ID: id, Email: "port@example.com", EmailVerified: true,
				DisplayName: "Port Subject", Locale: "sk", Roles: []string{"user"},
				CreatedAt: now, UpdatedAt: now,
			}, nil
		},
	}
	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.Device, error) {
			return []*model.Device{{ID: "device-1", UserID: userID, FriendlyName: "Laptop", FirstSeenAt: now}}, nil
		},
	}
	social := &mocks.MockSocialAccountRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.SocialAccount, error) {
			return []*model.SocialAccount{{Provider: "github", ProviderUserID: "gh-77", Email: "port@example.com", CreatedAt: now}}, nil
		},
	}
	blobs := &mocks.MockBlobRepo{
		ListByPseudonymFn: func(_ context.Context, _ string) ([]*model.Blob, error) {
			return []*model.Blob{{ID: "blob-1", SizeBytes: 42, Checksum: "sha256:abc", CreatedAt: now}}, nil
		},
	}
	auditEvents := &mocks.MockAuditRepo{
		CountByUserFn: func(_ context.Context, _ string) (int, error) { return 1, nil },
		QueryFn: func(_ context.Context, f repository.AuditFilter) ([]*model.AuditEntry, error) {
			return []*model.AuditEntry{{EventType: "login_success", UserID: userID, IP: "203.0.113.7", Timestamp: now}}, nil
		},
	}

	seed := &service.IdentityData{GivenName: "Jane", FamilyName: "Doe", Country: "SK"}

	rec := auditGDPRRunExport(t, userID, seed, users, devices, social, blobs, auditEvents)

	if rec.Code != http.StatusOK {
		t.Fatalf("Art. 20: export status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Art. 20: Content-Type = %q, want application/json (machine-readable)", ct)
	}

	// Machine-readable: the body must parse as JSON with no bespoke framing.
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &generic); err != nil {
		t.Fatalf("Art. 20: export body is not machine-readable JSON: %v", err)
	}
	// Structured: personal data is grouped under named category objects, not a
	// flat dump. Portability requires the receiving controller can find the parts.
	for _, cat := range []string{"account", "identity", "devices", "blobs", "social_accounts", "audit_events"} {
		if _, ok := generic[cat]; !ok {
			t.Errorf("Art. 20: export missing structured category %q", cat)
		}
	}

	// The subject's ACTUAL data must be present, decoded into the typed shape.
	var resp handler.DataExportResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Art. 20: typed decode: %v", err)
	}
	if resp.Account.Email != "port@example.com" {
		t.Errorf("Art. 20: account email = %q, export did not carry the subject's data", resp.Account.Email)
	}
	if resp.Identity == nil || resp.Identity.GivenName != "Jane" || resp.Identity.FamilyName != "Doe" || resp.Identity.Country != "SK" {
		t.Errorf("Art. 20: identity PII not portable: %+v", resp.Identity)
	}
	if len(resp.Devices) != 1 || resp.Devices[0].FriendlyName != "Laptop" {
		t.Errorf("Art. 20: devices not exported: %+v", resp.Devices)
	}
	if len(resp.Blobs) != 1 || resp.Blobs[0].SizeBytes != 42 {
		t.Errorf("Art. 20: blob metadata not exported: %+v", resp.Blobs)
	}
	if len(resp.SocialAccounts) != 1 || resp.SocialAccounts[0].Provider != "github" {
		t.Errorf("Art. 20: linked social accounts not exported: %+v", resp.SocialAccounts)
	}
	if len(resp.AuditEvents) != 1 || resp.AuditEvents[0].EventType != "login_success" {
		t.Errorf("Art. 20: audit events not exported: %+v", resp.AuditEvents)
	}
}

// -----------------------------------------------------------------------------
// Art. 15 -- Right of access: a copy of ALL categories of personal data, and an
// export that never masquerades as complete when it is capped.
//
// Register weakness: TestGDPR_Art15_Art20_ExportDeclaresItsOwnTruncation only
// grepped for the constant name maxExportAuditEvents and the field
// AuditEventsTruncated. It proved nothing about the subject actually receiving
// every category, and nothing about the cap firing correctly. This exercises the
// real handler twice: a capped export must report the true total and flag itself
// truncated; a complete export must not; and every category must be present.
// -----------------------------------------------------------------------------

func TestGDPR_Art15_RightOfAccessCategoriesAndTruncation(t *testing.T) {
	const userID = "access-subject-0002"
	now := time.Now().UTC().Truncate(time.Second)

	// maxExportAuditEvents is unexported (1000); the handler caps the Query slice
	// at it and reports the true held total separately. Model a store holding more
	// than the cap so the truncation path is genuinely taken, not asserted about.
	const capLimit = 1000

	buildAudit := func(held int) *mocks.MockAuditRepo {
		returned := held
		if returned > capLimit {
			returned = capLimit
		}
		entries := make([]*model.AuditEntry, returned)
		for i := range entries {
			entries[i] = &model.AuditEntry{EventType: "login_success", UserID: userID, Timestamp: now}
		}
		return &mocks.MockAuditRepo{
			CountByUserFn: func(_ context.Context, _ string) (int, error) { return held, nil },
			QueryFn: func(_ context.Context, f repository.AuditFilter) ([]*model.AuditEntry, error) {
				// Honour the cap the handler asks for, like the real repo does.
				if f.Limit > 0 && len(entries) > f.Limit {
					return entries[:f.Limit], nil
				}
				return entries, nil
			},
		}
	}

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "access@example.com", CreatedAt: now, UpdatedAt: now}, nil
		},
	}
	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.Device, error) {
			return []*model.Device{{ID: "d-1", UserID: userID, FriendlyName: "Phone", FirstSeenAt: now}}, nil
		},
	}
	social := &mocks.MockSocialAccountRepo{}
	blobs := &mocks.MockBlobRepo{}
	seed := &service.IdentityData{GivenName: "Ann", Country: "SK"}

	t.Run("capped export declares the true total and flags itself truncated", func(t *testing.T) {
		rec := auditGDPRRunExport(t, userID, seed, users, devices, social, blobs, buildAudit(capLimit+7))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		var resp handler.DataExportResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}

		// Right of access: every category present (a copy of ALL their data).
		if resp.Identity == nil || resp.Identity.GivenName != "Ann" {
			t.Errorf("Art. 15: identity category missing from the copy of the subject's data: %+v", resp.Identity)
		}
		if len(resp.Devices) != 1 {
			t.Errorf("Art. 15: devices category missing: %+v", resp.Devices)
		}

		// Truncation is real, not a claim: total held is reported and it exceeds
		// the returned page, so the subject can tell there is more to ask for.
		if resp.AuditEventsLimit != capLimit {
			t.Errorf("Art. 15: audit_events_limit = %d, want %d", resp.AuditEventsLimit, capLimit)
		}
		if len(resp.AuditEvents) != capLimit {
			t.Errorf("Art. 15: returned %d events, want the cap of %d", len(resp.AuditEvents), capLimit)
		}
		if resp.AuditEventsTotal != capLimit+7 {
			t.Errorf("Art. 15: audit_events_total = %d, want %d -- without the true total the subject cannot know what is missing", resp.AuditEventsTotal, capLimit+7)
		}
		if !resp.AuditEventsTruncated {
			t.Error("Art. 15: a capped export reported itself complete; the subject would never ask for the remainder")
		}
	})

	t.Run("complete export is not falsely flagged truncated", func(t *testing.T) {
		rec := auditGDPRRunExport(t, userID, seed, users, devices, social, blobs, buildAudit(3))
		var resp handler.DataExportResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.AuditEventsTruncated {
			t.Error("Art. 15: a complete export was flagged truncated, sending the subject chasing data already in front of them")
		}
		if resp.AuditEventsTotal != 3 || len(resp.AuditEvents) != 3 {
			t.Errorf("Art. 15: total=%d returned=%d, want 3 and 3", resp.AuditEventsTotal, len(resp.AuditEvents))
		}
	})
}

// -----------------------------------------------------------------------------
// Art. 28 -- Processor / sub-processor disclosure.
//
// Register weakness: TestGDPR_Art28_ProcessorsAreDocumented passed if the word
// "processor" appeared anywhere in PRIVACY.md. This asserts the shipped policy
// actually ENUMERATES the processors vault42 engages, in a table with a role and
// a data-shared column, and states the Art. 28 data-processing-agreement duty --
// the substance the clause requires, not the token.
// -----------------------------------------------------------------------------

func TestGDPR_Art28_ProcessorsEnumeratedInRegister(t *testing.T) {
	doc := auditGDPRPrivacyDoc(t)

	if !strings.Contains(doc, "Third-Party Processors") {
		t.Error("Art. 28: no dedicated processors section in the shipped policy")
	}
	// A real register: a table with a role column and a data-shared column, not a
	// sentence mentioning the word.
	for _, header := range []string{"Recipient / processor", "Role", "Data shared"} {
		if !strings.Contains(doc, header) {
			t.Errorf("Art. 28: processor register is missing the %q column; it is not an enumeration", header)
		}
	}
	// The concrete processors that actually receive personal data must be named,
	// each with its role, so a sub-processor cannot hide behind a generic clause.
	namedProcessors := []string{
		"PostgreSQL",            // primary datastore
		"Email delivery",        // transactional + marketing mail
		"Have I Been Pwned",     // breach-password screening (k-anonymity)
		"OAuth / OIDC identity", // federated login providers
	}
	for _, p := range namedProcessors {
		if !strings.Contains(doc, p) {
			t.Errorf("Art. 28: processor %q not enumerated in the register", p)
		}
	}
	// The Art. 28(3) contractual guarantee: a data-processing agreement is required
	// with each processor.
	if !strings.Contains(doc, "data-processing agreement (Art. 28)") {
		t.Error("Art. 28: the register does not state the Art. 28 data-processing-agreement obligation")
	}
}

// -----------------------------------------------------------------------------
// Art. 44 -- Transfers to third countries: general principle / safeguards.
//
// Register weakness: Art. 44 was pinned to the SAME "PRIVACY.md contains the word
// processor" grep as Art. 28 -- mismatched and tautological. Art. 44 governs the
// safeguards for cross-border transfer. vault42 is self-hosted middleware that
// performs no transfer of its own (hosting region is the Operator's choice), so
// the appropriate control is documenting the safeguard the Operator must put in
// place; this asserts that documentation is SUBSTANTIVE -- it names the concrete
// transfer mechanisms and ties them to processors outside the EEA -- rather than
// reusing the Art. 28 grep.
// -----------------------------------------------------------------------------

func TestGDPR_Art44_CrossBorderTransferSafeguards(t *testing.T) {
	doc := auditGDPRPrivacyDoc(t)

	// Distinct from Art. 28: the transfer clause must name the actual Chapter V
	// mechanisms, not merely mention "processor".
	for _, needle := range []string{
		"adequacy decision",            // Art. 45
		"Standard Contractual Clauses", // Art. 46
		"44",                           // the Chapter V article range (Arts. 44-49)
	} {
		if !strings.Contains(doc, needle) {
			t.Errorf("Art. 44: transfer safeguard clause does not name %q", needle)
		}
	}
	// The safeguard must be bound to the trigger condition: a processor located
	// outside the EEA. A transfer-mechanism sentence with no location trigger is
	// decorative.
	if !strings.Contains(doc, "outside the EEA") {
		t.Error("Art. 44: the transfer safeguard is not tied to processors located outside the EEA")
	}
	if !strings.Contains(doc, "transfer mechanism") {
		t.Error("Art. 44: the policy does not require an appropriate transfer mechanism for extra-EEA processors")
	}
}

// -----------------------------------------------------------------------------
// Art. 6 -- Lawfulness of processing (the six bases).
//
// Register weakness: TestGDPR_Art7_1_ConsentRecordProvenance stamped consent on a
// bare IdentityData fixture and never established the lawful basis of the PRIMARY
// processing (authentication), which is contract, not consent. This does both:
//   1. Drives the REAL PUT /user/identity -> Get round trip so the consent record
//      for the one consent-based purpose (P10 marketing, Art. 6(1)(a)) is stamped
//      and read back through shipped handlers with genuine provenance.
//   2. Asserts the shipped lawful-basis register ties the primary purpose (P1
//      account creation + authentication) to Art. 6(1)(b) contract -- so
//      lawfulness of the core processing is actually established, and consent is
//      scoped to marketing rather than standing in for everything.
// -----------------------------------------------------------------------------

func TestGDPR_Art6_LawfulBasisPrimaryAndConsentRecord(t *testing.T) {
	const userID = "lawful-basis-subject-0003"

	// (1) The real consent record via the shipped handler, not a fixture.
	repo := gdprIdentityRepo()
	svc := gdprIdentityService(repo)
	h := handler.NewIdentityHandler(svc, nil)

	putRec := httptest.NewRecorder()
	h.Put(putRec, auditGDPRPutIdentity(userID, `{"given_name":"Consent","country":"SK","marketing_emails":true}`))
	if putRec.Code != http.StatusOK {
		t.Fatalf("Art. 6: PUT /user/identity status = %d, want 200; body: %s", putRec.Code, putRec.Body.String())
	}

	getRec := httptest.NewRecorder()
	h.Get(getRec, gdprAuthedRequest(http.MethodGet, "/user/identity", userID))
	if getRec.Code != http.StatusOK {
		t.Fatalf("Art. 6: GET /user/identity status = %d, want 200; body: %s", getRec.Code, getRec.Body.String())
	}
	var got handler.IdentityResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Art. 6: decode identity: %v", err)
	}
	if got.MarketingConsent == nil {
		t.Fatal("Art. 6(1)(a): no consent record was persisted through the real write path")
	}
	if got.MarketingConsent.Source != service.ConsentSourceProfile {
		t.Errorf("Art. 6(1)(a): consent source = %q, want %q -- a real affirmative act, recorded with provenance", got.MarketingConsent.Source, service.ConsentSourceProfile)
	}
	if !got.MarketingConsent.Granted || !got.MarketingConsent.Affirmative {
		t.Errorf("Art. 6(1)(a): consent record not affirmative: %+v", got.MarketingConsent)
	}
	if got.MarketingConsent.At == "" {
		t.Error("Art. 6(1)(a): consent record carries no timestamp; the controller cannot demonstrate when it was given")
	}

	// (2) The shipped register establishes the lawful basis of the PRIMARY
	// processing, which the old test never did.
	doc := auditGDPRPrivacyDoc(t)
	if !strings.Contains(doc, "Lawful Basis for Processing (Art. 6)") {
		t.Fatal("Art. 6: no lawful-basis register in the shipped policy")
	}
	if !strings.Contains(doc, "Account creation and authentication") {
		t.Error("Art. 6: the primary processing purpose (authentication) is not in the lawful-basis register")
	}
	// Authentication must rest on contract (6(1)(b)), NOT consent -- reusing the
	// marketing-consent test for it was the register's exact error.
	if !strings.Contains(doc, "Art. 6(1)(b)") {
		t.Error("Art. 6(1)(b): no contract basis declared for the primary processing")
	}
	// Marketing (the one consent purpose) must be 6(1)(a), scoped to that purpose.
	if !strings.Contains(doc, "Art. 6(1)(a) consent -- sent only when the user has opted in") {
		t.Error("Art. 6(1)(a): the marketing purpose is not correctly scoped to consent in the register")
	}
}

// -----------------------------------------------------------------------------
// Arts. 16, 18, 21 -- Rectification, restriction, objection.
//
// Register weakness: only the marketing objection (Art. 21) was exercised;
// rectification (Art. 16) and restriction (Art. 18) rested on a note. This drives
// all three shipped paths:
//   - Art. 16: PUT /user/identity actually changes stored data, read back via GET.
//   - Art. 18: a disabled account (the restriction control per PRIVACY.md 5.4) is
//     refused authentication by the real AuthService while its data is retained.
//   - Art. 21: POST /user/marketing/unsubscribe withdraws consent with the right
//     provenance, through the real handler+service.
// -----------------------------------------------------------------------------

func TestGDPR_Arts16_18_21_RectifyRestrictObject(t *testing.T) {
	t.Run("art16_rectification_persists_through_real_path", func(t *testing.T) {
		const userID = "rectify-subject-0004"
		repo := gdprIdentityRepo()
		svc := gdprIdentityService(repo)
		h := handler.NewIdentityHandler(svc, nil)

		// Establish a stored value.
		rec1 := httptest.NewRecorder()
		h.Put(rec1, auditGDPRPutIdentity(userID, `{"given_name":"Olde","country":"SK"}`))
		if rec1.Code != http.StatusOK {
			t.Fatalf("seed PUT status = %d; body: %s", rec1.Code, rec1.Body.String())
		}
		// Rectify it.
		rec2 := httptest.NewRecorder()
		h.Put(rec2, auditGDPRPutIdentity(userID, `{"given_name":"Corrected","country":"CZ"}`))
		if rec2.Code != http.StatusOK {
			t.Fatalf("rectify PUT status = %d; body: %s", rec2.Code, rec2.Body.String())
		}
		// Read it back through the shipped GET; the correction must have landed.
		rec3 := httptest.NewRecorder()
		h.Get(rec3, gdprAuthedRequest(http.MethodGet, "/user/identity", userID))
		var got handler.IdentityResponse
		if err := json.Unmarshal(rec3.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.GivenName != "Corrected" || got.Country != "CZ" {
			t.Errorf("Art. 16: rectification not persisted: given_name=%q country=%q", got.GivenName, got.Country)
		}
	})

	t.Run("art18_restriction_disabled_account_not_processed_but_retained", func(t *testing.T) {
		const email = "restricted@example.com"
		password := "correct-horse-battery-staple-42"
		hash, err := vaultcrypto.HashPassword(password)
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}

		// The account exists with valid credentials but the restriction flag
		// (Disabled) is set -- PRIVACY.md 5.4's restriction control.
		disabledUser := &model.User{
			ID: "restricted-0005", Email: email, EmailVerified: true,
			PasswordHash: hash, Disabled: true, Roles: []string{"user"},
		}
		userRepo := &mocks.MockUserRepo{
			GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) { return disabledUser, nil },
			GetByIDFn:    func(_ context.Context, _ string) (*model.User, error) { return disabledUser, nil },
		}

		svc, mem := auditGDPRAuthService(t, userRepo)
		defer mem.Close()

		// Restriction is enforced: a correct password does NOT authenticate a
		// restricted account. This is the real gate, after password proof.
		_, err = svc.Login(context.Background(), service.LoginInput{Email: email, Password: password},
			"203.0.113.9", "TestAgent")
		if !errors.Is(err, service.ErrAccountDisabled) {
			t.Fatalf("Art. 18: restricted account login err = %v, want ErrAccountDisabled (processing must stop)", err)
		}

		// Retained, not erased: the account data still exists after the refusal.
		still, _ := userRepo.GetByEmail(context.Background(), email)
		if still == nil || still.Email != email {
			t.Error("Art. 18: restriction must retain the data, not delete it")
		}
		if !still.Disabled {
			t.Error("Art. 18: the restriction flag was cleared by the refused login")
		}
	})

	t.Run("art21_objection_unsubscribe_withdraws_through_real_path", func(t *testing.T) {
		const userID = "object-subject-0006"
		repo := gdprIdentityRepo()
		svc := gdprIdentityService(repo)
		ctx := context.Background()

		// Start from an affirmative opt-in so the withdrawal is a real change.
		if err := svc.Upsert(ctx, userID, gdprStamped(true, service.ConsentSourceProfile, "")); err != nil {
			t.Fatalf("seed opt-in: %v", err)
		}

		h := handler.NewIdentityHandler(svc, nil)
		rec := httptest.NewRecorder()
		h.Unsubscribe(rec, gdprAuthedRequest(http.MethodPost, "/user/marketing/unsubscribe", userID))
		if rec.Code != http.StatusOK {
			t.Fatalf("Art. 21: unsubscribe status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}

		data, _, err := svc.Get(ctx, userID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if data == nil || data.MarketingConsent == nil {
			t.Fatal("Art. 21: objection was not recorded")
		}
		if data.MarketingConsent.Granted {
			t.Error("Art. 21: consent still granted after objection")
		}
		if data.MarketingConsent.Source != service.ConsentSourceUnsubscribe {
			t.Errorf("Art. 21: withdrawal source = %q, want %q", data.MarketingConsent.Source, service.ConsentSourceUnsubscribe)
		}
		// The purpose is now closed: nothing may be sent.
		allowed, err := svc.MarketingAllowed(ctx, userID)
		if err != nil {
			t.Fatalf("MarketingAllowed: %v", err)
		}
		if allowed {
			t.Error("Art. 21: marketing still authorised after the objection landed")
		}
	})
}

// auditGDPRAuthService builds a real AuthService reaching only as far as the
// administrative-denial gate (no MFA, no email path needed): enough to prove the
// Art. 18 restriction control refuses a disabled account after password proof.
func auditGDPRAuthService(t *testing.T, users *mocks.MockUserRepo) (*service.AuthService, *cache.MemoryCache) {
	t.Helper()
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := service.NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	mfaSvc := service.NewMFAService(&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, false)
	auditLog := audit.NewLogger(&mocks.MockAuditRepo{}, 0)
	mem := cache.NewMemoryCache()

	svc := service.NewAuthService(
		users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, mfaSvc, auditLog, service.NewHIBPClient(),
		mem, &mocks.MockEmailSender{}, "https://vault.test", "TestVault",
		"", 15, false, auditGDPRHMAC(),
	)
	return svc, mem
}

// -----------------------------------------------------------------------------
// Art. 5(1)(b) -- Purpose limitation.
//
// Register weakness: TestASVS_V14_1_1_TheDataInventoryExistsAndIsEnforced greped
// PRIVACY.md for the headings "Data Inventory"/"Retention" and audit.go for
// sensitiveKeys -- an inventory-existence check (an Art. 30 concern), not purpose
// limitation. The real Art. 5(1)(b) enforcement is the marketing gate:
// MarketingAllowed fails closed, so data collected under any other basis cannot be
// repurposed to send marketing; only data affirmatively consented FOR the
// marketing purpose authorises it. This drives that real gate, plus confirms the
// register binds the marketing purpose to its own basis (purpose specification).
// -----------------------------------------------------------------------------

func TestGDPR_Art5_1b_PurposeLimitationEnforced(t *testing.T) {
	const userID = "purpose-subject-0007"
	yes := true

	// Each row is data that PHYSICALLY EXISTS but was not collected/consented for
	// the marketing purpose; purpose limitation forbids reusing it to send mail.
	cases := []struct {
		name string
		seed *service.IdentityData
		want bool
	}{
		{"imported opt-in was collected for another system's purpose", gdprStamped(true, service.ConsentSourceImport, "beon3"), false},
		{"legacy bare bool has no marketing-purpose provenance", &service.IdentityData{MarketingEmails: &yes}, false},
		{"no profile at all", nil, false},
		{"affirmative consent FOR the marketing purpose authorises it", gdprStamped(true, service.ConsentSourceProfile, ""), true},
		{"a recorded withdrawal closes the purpose", gdprStamped(false, service.ConsentSourceUnsubscribe, ""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := gdprIdentityRepo()
			svc := gdprIdentityService(repo)
			if tc.seed != nil {
				if err := svc.Upsert(context.Background(), userID, tc.seed); err != nil {
					t.Fatalf("seed: %v", err)
				}
			}
			allowed, err := svc.MarketingAllowed(context.Background(), userID)
			if err != nil {
				t.Fatalf("MarketingAllowed: %v", err)
			}
			if allowed != tc.want {
				t.Errorf("Art. 5(1)(b): MarketingAllowed = %v, want %v -- data may only serve the purpose it was collected for", allowed, tc.want)
			}
		})
	}

	// Purpose specification is the precondition of purpose limitation: the register
	// must bind the marketing purpose to its own (consent) basis, distinct from the
	// contract basis of the primary processing, so the two purposes cannot be
	// conflated. The code gate above enforces exactly that separation at runtime.
	doc := auditGDPRPrivacyDoc(t)
	if !strings.Contains(doc, "Marketing email") {
		t.Error("Art. 5(1)(b): the marketing purpose is not specified as its own purpose in the register")
	}
}
