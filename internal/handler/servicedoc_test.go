package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

const (
	svcDocHandlerClientA = "aaaaaaaa-0000-4000-8000-000000000001"
	svcDocHandlerClientB = "bbbbbbbb-0000-4000-8000-000000000002"
	svcDocHandlerClientC = "cccccccc-0000-4000-8000-000000000003"
)

// ---------------------------------------------------------------------------
// In-memory document repository
// ---------------------------------------------------------------------------

type memDocKey struct{ client, subject, key string }

type memDocRepo struct {
	rows map[memDocKey]*repository.ServiceDocument
	// getErr stands in for a store that is down. Set it to drive the failure a
	// dead database produces on the read path.
	getErr error
}

func newMemDocRepo() *memDocRepo {
	return &memDocRepo{rows: map[memDocKey]*repository.ServiceDocument{}}
}

func (m *memDocRepo) Get(_ context.Context, clientID, subjectHash, docKey string) (*repository.ServiceDocument, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	d, ok := m.rows[memDocKey{clientID, subjectHash, docKey}]
	if !ok {
		return nil, nil
	}
	cp := *d
	return &cp, nil
}

func (m *memDocRepo) ListSharedByKey(_ context.Context, subjectHash, docKey, exclude string) ([]*repository.ServiceDocument, error) {
	var out []*repository.ServiceDocument
	for k, d := range m.rows {
		if k.subject == subjectHash && k.key == docKey && k.client != exclude && d.Visibility == repository.VisibilityShared {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *memDocRepo) Upsert(_ context.Context, doc *repository.ServiceDocument) (bool, error) {
	k := memDocKey{doc.ClientID, doc.SubjectHash, doc.DocKey}
	_, existed := m.rows[k]
	cp := *doc
	m.rows[k] = &cp
	return !existed, nil
}

func (m *memDocRepo) Delete(_ context.Context, clientID, subjectHash, docKey string) (bool, error) {
	k := memDocKey{clientID, subjectHash, docKey}
	if _, ok := m.rows[k]; !ok {
		return false, nil
	}
	delete(m.rows, k)
	return true, nil
}

func (m *memDocRepo) ListByOwner(_ context.Context, clientID, subjectHash string) ([]*repository.ServiceDocument, error) {
	var out []*repository.ServiceDocument
	for k, d := range m.rows {
		if k.client == clientID && k.subject == subjectHash {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *memDocRepo) ListSharedForSubject(_ context.Context, subjectHash, exclude string) ([]*repository.ServiceDocument, error) {
	var out []*repository.ServiceDocument
	for k, d := range m.rows {
		if k.subject == subjectHash && k.client != exclude && d.Visibility == repository.VisibilityShared {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *memDocRepo) ListAllForSubject(_ context.Context, subjectHash string) ([]*repository.ServiceDocument, error) {
	var out []*repository.ServiceDocument
	for k, d := range m.rows {
		if k.subject == subjectHash {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *memDocRepo) CountForOwner(_ context.Context, clientID, subjectHash string) (int, error) {
	n := 0
	for k := range m.rows {
		if k.client == clientID && k.subject == subjectHash {
			n++
		}
	}
	return n, nil
}

func (m *memDocRepo) SumBytesForSubject(_ context.Context, subjectHash string) (int, error) {
	total := 0
	for k, d := range m.rows {
		if k.subject == subjectHash {
			total += d.StoredBytes
		}
	}
	return total, nil
}

func (m *memDocRepo) DeleteAllForSubject(_ context.Context, subjectHash string) error {
	for k := range m.rows {
		if k.subject == subjectHash {
			delete(m.rows, k)
		}
	}
	return nil
}

type memClientRepo struct{ byID, byName map[string]*model.Client }

func newMemClientRepo() *memClientRepo {
	r := &memClientRepo{byID: map[string]*model.Client{}, byName: map[string]*model.Client{}}
	for _, c := range []*model.Client{
		{ID: svcDocHandlerClientA, Name: "service-a"},
		{ID: svcDocHandlerClientB, Name: "service-b"},
	} {
		r.byID[c.ID] = c
		r.byName[c.Name] = c
	}
	return r
}

func (r *memClientRepo) Create(context.Context, *model.Client) error { return nil }
func (r *memClientRepo) GetByID(_ context.Context, id string) (*model.Client, error) {
	return r.byID[id], nil
}

func (r *memClientRepo) GetByName(_ context.Context, n string) (*model.Client, error) {
	return r.byName[n], nil
}
func (r *memClientRepo) List(context.Context) ([]*model.Client, error) { return nil, nil }
func (r *memClientRepo) Update(context.Context, *model.Client) error   { return nil }
func (r *memClientRepo) Deactivate(context.Context, string) error      { return nil }

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

func newDocHandler(t *testing.T, auditLog *audit.Logger, mutate func(*service.ServiceDocumentConfig)) (*ServiceDocumentHandler, *memDocRepo) {
	t.Helper()
	cfg := service.ServiceDocumentConfig{
		MaxDocumentBytes:     64 * 1024,
		MaxDocsPerSubject:    32,
		QuotaBytesPerSubject: 1024 * 1024,
		SharedEnabled:        true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	repo := newMemDocRepo()
	master := make([]byte, 32)
	hmacSecret := make([]byte, 32)
	for i := range master {
		master[i] = byte(i * 3)
		hmacSecret[i] = byte(i * 7)
	}
	svc := service.NewServiceDocumentService(repo, newMemClientRepo(), master, hmacSecret, cfg, nil)
	return NewServiceDocumentHandler(svc, auditLog), repo
}

// docRequest builds a request with the path values Go's ServeMux would set.
func docRequest(method, subject, key, query, body string) *http.Request {
	target := "/service/documents/" + subject
	if key != "" {
		target += "/" + key
	}
	if query != "" {
		target += "?" + query
	}
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	req.RemoteAddr = "127.0.0.1:9999"
	req.SetPathValue("subject", subject)
	if key != "" {
		req.SetPathValue("key", key)
	}
	return req
}

func asClient(req *http.Request, clientID string, scopes []string) *http.Request {
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: clientID},
		ClientID:         clientID,
		Scopes:           scopes,
		TokenType:        "Bearer",
	}
	return req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
}

// ---------------------------------------------------------------------------
// Access control
// ---------------------------------------------------------------------------

// RequireScope alone is only accidentally sufficient: user tokens cannot carry
// a svcdoc scope today only because the user issuance sites hardcode their
// scopes. The handler asserts the client claim itself.
func TestServiceDocumentHandler_RejectsTokensWithoutAClientClaim(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), nil)
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: "an-end-user"},
		Scopes:           []string{"svcdoc:read", "svcdoc:write"},
		TokenType:        "Bearer",
	}

	for _, tc := range []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
		req  *http.Request
	}{
		{"put", h.Put, docRequest(http.MethodPut, "user-1", "prefs", "", `{"a":1}`)},
		{"get", h.Get, docRequest(http.MethodGet, "user-1", "prefs", "", "")},
		{"delete", h.Delete, docRequest(http.MethodDelete, "user-1", "prefs", "", "")},
		{"list", h.List, docRequest(http.MethodGet, "user-1", "", "", "")},
	} {
		req := tc.req.WithContext(context.WithValue(tc.req.Context(), middleware.ClaimsKey, claims))
		rec := httptest.NewRecorder()
		tc.fn(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 (%s)", tc.name, rec.Code, rec.Body.String())
		}
	}
}

func TestServiceDocumentHandler_RejectsUnauthenticated(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), nil)
	rec := httptest.NewRecorder()
	h.Get(rec, docRequest(http.MethodGet, "user-1", "prefs", "", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

func TestServiceDocumentHandler_PutGetDeleteRoundTrip(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), nil)

	rec := httptest.NewRecorder()
	h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "beon3.profile_prefs", "", `{"show_real_name":false}`), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("first write: %d %s", rec.Code, rec.Body.String())
	}
	var created ServiceDocumentResponse
	decodeResponse(t, rec, &created)
	if created.Visibility != "private" {
		t.Errorf("default visibility = %q, want private", created.Visibility)
	}

	rec = httptest.NewRecorder()
	h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "beon3.profile_prefs", "", `{"show_real_name":true}`), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("replacement: %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.Get(rec, asClient(docRequest(http.MethodGet, "user-1", "beon3.profile_prefs", "", ""), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("read: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type = %q", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, rec.Body.String())
	}
	if body["show_real_name"] != true {
		t.Fatalf("body = %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.Delete(rec, asClient(docRequest(http.MethodDelete, "user-1", "beon3.profile_prefs", "", ""), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.Get(rec, asClient(docRequest(http.MethodGet, "user-1", "beon3.profile_prefs", "", ""), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("read after delete: %d, want 404", rec.Code)
	}
}

// User-independent configuration is a first-class case, addressed by a sentinel
// subject rather than a nullable column.
func TestServiceDocumentHandler_GlobalSubject(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), nil)
	rec := httptest.NewRecorder()
	h.Put(rec, asClient(docRequest(http.MethodPut, service.GlobalSubject, "flags", "", `{"beta":true}`), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("global write: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.Get(rec, asClient(docRequest(http.MethodGet, service.GlobalSubject, "flags", "", ""), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("global read: %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

func TestServiceDocumentHandler_ErrorMapping(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), nil)

	cases := []struct {
		name    string
		subject string
		key     string
		query   string
		body    string
		status  int
		code    string
	}{
		{"bad key", "user-1", "BadKey", "", `{"a":1}`, http.StatusBadRequest, "invalid_key"},
		{"path traversal key", "user-1", "..", "", `{"a":1}`, http.StatusBadRequest, "invalid_key"},
		{"bad subject", "_secret", "prefs", "", `{"a":1}`, http.StatusBadRequest, "invalid_subject"},
		{"array body", "user-1", "prefs", "", `[1,2]`, http.StatusBadRequest, "invalid_document"},
		{"duplicate keys", "user-1", "prefs", "", `{"a":1,"a":2}`, http.StatusBadRequest, "invalid_document"},
		{"empty body", "user-1", "prefs", "", ``, http.StatusBadRequest, "invalid_document"},
		{"bad visibility", "user-1", "prefs", "visibility=restricted", `{"a":1}`, http.StatusBadRequest, "invalid_visibility"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.Put(rec, asClient(docRequest(http.MethodPut, tc.subject, tc.key, tc.query, tc.body), svcDocHandlerClientA, nil))
		if rec.Code != tc.status {
			t.Errorf("%s: status %d, want %d (%s)", tc.name, rec.Code, tc.status, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s: body %s, want %s", tc.name, rec.Body.String(), tc.code)
		}
	}
}

// The route prefix is exempt from the global 8 KiB body cap, so the handler has
// to bound the body itself or the exemption is an unbounded-body hole.
func TestServiceDocumentHandler_EnforcesItsOwnBodyLimit(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), func(cfg *service.ServiceDocumentConfig) {
		cfg.MaxDocumentBytes = 2048
	})
	oversize := `{"pad":"` + strings.Repeat("x", 8192) + `"}`
	rec := httptest.NewRecorder()
	h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "prefs", "", oversize), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413 (%s)", rec.Code, rec.Body.String())
	}
}

// A document larger than the cap but inside the reader's slack must still be
// refused by the service, so the two limits cannot disagree.
func TestServiceDocumentHandler_RefusesDocumentsInsideTheReaderSlack(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), func(cfg *service.ServiceDocumentConfig) {
		cfg.MaxDocumentBytes = 2048
	})
	oversize := `{"pad":"` + strings.Repeat("x", 2200) + `"}`
	rec := httptest.NewRecorder()
	h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "prefs", "", oversize), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413 (%s)", rec.Code, rec.Body.String())
	}
}

func TestServiceDocumentHandler_SharedTierGate(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), func(cfg *service.ServiceDocumentConfig) {
		cfg.SharedEnabled = false
	})
	rec := httptest.NewRecorder()
	h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "flags", "visibility=shared", `{"a":1}`), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "shared_visibility_disabled") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Cross-service isolation
// ---------------------------------------------------------------------------

func TestServiceDocumentHandler_PrivateDocumentIsInvisibleToOtherClients(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), nil)

	rec := httptest.NewRecorder()
	h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "prefs", "", `{"a":1}`), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("write: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.Get(rec, asClient(docRequest(http.MethodGet, "user-1", "prefs", "", ""), svcDocHandlerClientB, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-client read: %d, want 404 (%s)", rec.Code, rec.Body.String())
	}
	// Reported as absent, never as forbidden: the difference would answer
	// "does service A hold a record about user 1".
	if strings.Contains(rec.Body.String(), "not_document_owner") {
		t.Fatalf("existence leaked: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.Delete(rec, asClient(docRequest(http.MethodDelete, "user-1", "prefs", "", ""), svcDocHandlerClientB, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-client delete: %d, want 404", rec.Code)
	}
}

func TestServiceDocumentHandler_ListSeparatesOwnFromShared(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), nil)

	for _, tc := range []struct {
		client, key, query string
	}{
		{svcDocHandlerClientA, "mine", ""},
		{svcDocHandlerClientB, "theirs", "visibility=shared"},
		{svcDocHandlerClientB, "hidden", ""},
	} {
		rec := httptest.NewRecorder()
		h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", tc.key, tc.query, `{"a":1}`), tc.client, nil))
		if rec.Code != http.StatusCreated {
			t.Fatalf("seed %s: %d %s", tc.key, rec.Code, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	h.List(rec, asClient(docRequest(http.MethodGet, "user-1", "", "", ""), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var resp ServiceDocumentListResponse
	decodeResponse(t, rec, &resp)
	if resp.Count != 2 {
		t.Fatalf("count = %d, want 2 (%s)", resp.Count, rec.Body.String())
	}
	for _, d := range resp.Documents {
		if d.Key == "hidden" {
			t.Fatal("listing exposed another client's private document")
		}
		if d.Key == "theirs" && (d.Mine || d.Owner != "service-b") {
			t.Fatalf("shared document mis-attributed: %+v", d)
		}
	}
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// The document body is personal data and audit rows survive account erasure, so
// nothing that could carry a body may reach the log.
func TestServiceDocumentHandler_AuditNeverCarriesTheDocumentBody(t *testing.T) {
	var captured []*model.AuditEntry
	auditRepo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, entry *model.AuditEntry) error {
			captured = append(captured, entry)
			return nil
		},
	}
	h, _ := newDocHandler(t, audit.NewLogger(auditRepo, 0), nil)

	const marker = "qzx-secret-marker-3141"
	rec := httptest.NewRecorder()
	h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "prefs", "", `{"note":"`+marker+`"}`), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("write: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.Get(rec, asClient(docRequest(http.MethodGet, "user-1", "prefs", "", ""), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("read: %d", rec.Code)
	}

	if len(captured) != 2 {
		t.Fatalf("recorded %d audit entries, want 2", len(captured))
	}
	for _, e := range captured {
		if !strings.HasPrefix(e.EventType, "svcdoc_") {
			t.Errorf("event type %q is outside the scrubbed prefix", e.EventType)
		}
		if e.ClientID != svcDocHandlerClientA {
			t.Errorf("client id = %q", e.ClientID)
		}
		if e.UserID != "user-1" {
			t.Errorf("user id = %q, want the subject so the event lands in that user's export", e.UserID)
		}
		raw, err := json.Marshal(e.Metadata)
		if err != nil {
			t.Fatalf("marshal metadata: %v", err)
		}
		if strings.Contains(string(raw), marker) {
			t.Fatalf("audit metadata carried the document body: %s", raw)
		}
	}
}

// A global document belongs to a service, not a user, so it must not be filed
// under a user id where the data export would pick it up.
func TestServiceDocumentHandler_GlobalWriteIsNotFiledUnderAUser(t *testing.T) {
	var captured []*model.AuditEntry
	auditRepo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, entry *model.AuditEntry) error {
			captured = append(captured, entry)
			return nil
		},
	}
	h, _ := newDocHandler(t, audit.NewLogger(auditRepo, 0), nil)

	rec := httptest.NewRecorder()
	h.Put(rec, asClient(docRequest(http.MethodPut, service.GlobalSubject, "flags", "", `{"a":1}`), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("write: %d", rec.Code)
	}
	if len(captured) != 1 {
		t.Fatalf("recorded %d entries", len(captured))
	}
	if captured[0].UserID != "" {
		t.Fatalf("global document filed under user %q", captured[0].UserID)
	}
}

// ---------------------------------------------------------------------------
// Path segments
// ---------------------------------------------------------------------------

// The four methods read their subject and key from path wildcards, and a
// wildcard that did not bind arrives as an empty string rather than as an
// error. Neither may be treated as a value: an empty key would reach the store
// as a document whose identity is the empty string, and an empty subject would
// address a pseudonym nobody owns.
func TestServiceDocumentHandler_RefusesUnboundPathWildcards(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), nil)

	bind := func(method, target string, values map[string]string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(`{"a":1}`))
		req.RemoteAddr = "127.0.0.1:9999"
		for name, v := range values {
			req.SetPathValue(name, v)
		}
		return asClient(req, svcDocHandlerClientA, nil)
	}
	onlyKey := map[string]string{"key": "prefs"}
	onlySubject := map[string]string{"subject": "user-1"}

	for _, tc := range []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
		req  *http.Request
		code string
	}{
		{"put without subject", h.Put, bind(http.MethodPut, "/service/documents/x/prefs", onlyKey), "missing_subject"},
		{"put without key", h.Put, bind(http.MethodPut, "/service/documents/user-1/x", onlySubject), "missing_key"},
		{"get without subject", h.Get, bind(http.MethodGet, "/service/documents/x/prefs", onlyKey), "missing_subject"},
		{"get without key", h.Get, bind(http.MethodGet, "/service/documents/user-1/x", onlySubject), "missing_key"},
		{"delete without subject", h.Delete, bind(http.MethodDelete, "/service/documents/x/prefs", onlyKey), "missing_subject"},
		{"delete without key", h.Delete, bind(http.MethodDelete, "/service/documents/user-1/x", onlySubject), "missing_key"},
		{"list without subject", h.List, bind(http.MethodGet, "/service/documents/x", nil), "missing_subject"},
	} {
		rec := httptest.NewRecorder()
		tc.fn(rec, tc.req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (%s)", tc.name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s: body %s, want %s", tc.name, rec.Body.String(), tc.code)
		}
	}
}

// The listing validates its subject through the service like every other route,
// so a subject the store would refuse is a 400 here too rather than an empty
// listing that reads as "this user has nothing".
func TestServiceDocumentHandler_ListRejectsAnInvalidSubject(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), nil)
	rec := httptest.NewRecorder()
	h.List(rec, asClient(docRequest(http.MethodGet, "_secret", "", "", ""), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_subject") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Quota
// ---------------------------------------------------------------------------

func TestServiceDocumentHandler_QuotaBreachIsAConflict(t *testing.T) {
	t.Run("document count per owner", func(t *testing.T) {
		h, _ := newDocHandler(t, newTestAuditLogger(), func(cfg *service.ServiceDocumentConfig) {
			cfg.MaxDocsPerSubject = 1
		})

		rec := httptest.NewRecorder()
		h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "first", "", `{"a":1}`), svcDocHandlerClientA, nil))
		if rec.Code != http.StatusCreated {
			t.Fatalf("first write: %d %s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "second", "", `{"a":1}`), svcDocHandlerClientA, nil))
		if rec.Code != http.StatusConflict {
			t.Fatalf("status %d, want 409 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "quota_exceeded") {
			t.Fatalf("body = %s", rec.Body.String())
		}

		// A replacement is not a new document and must not be charged a slot it
		// already holds, or a client at its limit could never correct a value.
		rec = httptest.NewRecorder()
		h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "first", "", `{"a":2}`), svcDocHandlerClientA, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("replacement: %d %s", rec.Code, rec.Body.String())
		}
	})

	// The byte budget is per subject across every owning client, so one user's
	// footprint stays bounded however many services write about them.
	t.Run("byte budget spans every owning client", func(t *testing.T) {
		h, _ := newDocHandler(t, newTestAuditLogger(), func(cfg *service.ServiceDocumentConfig) {
			cfg.QuotaBytesPerSubject = 200
		})
		body := `{"pad":"` + strings.Repeat("x", 100) + `"}`

		rec := httptest.NewRecorder()
		h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "first", "", body), svcDocHandlerClientA, nil))
		if rec.Code != http.StatusCreated {
			t.Fatalf("first write: %d %s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "second", "", body), svcDocHandlerClientB, nil))
		if rec.Code != http.StatusConflict {
			t.Fatalf("status %d, want 409 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "quota_exceeded") {
			t.Fatalf("body = %s", rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// Shared resolution
// ---------------------------------------------------------------------------

// Two services publishing the same shared key for the same subject is a legal
// state. Picking one arbitrarily would hand the reader another service's
// document under a name it did not ask for, so the read is refused until the
// caller names the publisher it meant.
func TestServiceDocumentHandler_AmbiguousSharedKeyIsRefused(t *testing.T) {
	h, _ := newDocHandler(t, newTestAuditLogger(), nil)

	for _, owner := range []string{svcDocHandlerClientA, svcDocHandlerClientB} {
		rec := httptest.NewRecorder()
		h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "prefs", "visibility=shared", `{"a":1}`), owner, nil))
		if rec.Code != http.StatusCreated {
			t.Fatalf("seed %s: %d %s", owner, rec.Code, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	h.Get(rec, asClient(docRequest(http.MethodGet, "user-1", "prefs", "", ""), svcDocHandlerClientC, nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ambiguous_document") {
		t.Fatalf("body = %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.Get(rec, asClient(docRequest(http.MethodGet, "user-1", "prefs", "owner=service-a", ""), svcDocHandlerClientC, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("named owner: %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Document-Owner"); got != svcDocHandlerClientA {
		t.Fatalf("X-Document-Owner = %q, want the named publisher", got)
	}
}

// ---------------------------------------------------------------------------
// Store failure
// ---------------------------------------------------------------------------

// A store that is down is an internal error, not a 404: reporting the document
// absent would tell a caller its data had been deleted. The underlying failure
// stays out of the response, since a service caller has no use for the
// database's address.
func TestServiceDocumentHandler_StoreFailureIsAnInternalError(t *testing.T) {
	h, repo := newDocHandler(t, newTestAuditLogger(), nil)
	repo.getErr = errors.New("dial tcp 10.9.9.9:5432: connection refused")

	rec := httptest.NewRecorder()
	h.Get(rec, asClient(docRequest(http.MethodGet, "user-1", "prefs", "", ""), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "internal_error") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "10.9.9.9") {
		t.Fatalf("the store failure leaked into the response: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Audit is best effort
// ---------------------------------------------------------------------------

// Auditing must never block the document path, which includes the case where
// there is no audit logger wired at all.
func TestServiceDocumentHandler_ServesDocumentsWithoutAnAuditLogger(t *testing.T) {
	h, _ := newDocHandler(t, nil, nil)

	rec := httptest.NewRecorder()
	h.Put(rec, asClient(docRequest(http.MethodPut, "user-1", "prefs", "", `{"a":1}`), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("write: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.Get(rec, asClient(docRequest(http.MethodGet, "user-1", "prefs", "", ""), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("read: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.Delete(rec, asClient(docRequest(http.MethodDelete, "user-1", "prefs", "", ""), svcDocHandlerClientA, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Rate limit keying
// ---------------------------------------------------------------------------

// A caller behind a single in-cluster pod presents one source address for its
// whole fleet, so an IP bucket would throttle every service as one.
func TestClientRateLimitKey(t *testing.T) {
	req := asClient(httptest.NewRequest(http.MethodGet, "/service/documents/user-1", nil), svcDocHandlerClientA, nil)
	if got := ClientRateLimitKey(req); got != "client:"+svcDocHandlerClientA {
		t.Fatalf("key = %q", got)
	}

	anon := httptest.NewRequest(http.MethodGet, "/service/documents/user-1", nil)
	anon.RemoteAddr = "203.0.113.9:1234"
	if got := ClientRateLimitKey(anon); !strings.HasPrefix(got, "ip:") {
		t.Fatalf("unauthenticated key = %q, want an IP bucket", got)
	}
}
