package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// ---------------------------------------------------------------------------
// In-memory fakes
// ---------------------------------------------------------------------------

type svcDocKey struct{ client, subject, key string }

type fakeSvcDocRepo struct {
	rows   map[svcDocKey]*repository.ServiceDocument
	failOn string
}

func newFakeSvcDocRepo() *fakeSvcDocRepo {
	return &fakeSvcDocRepo{rows: map[svcDocKey]*repository.ServiceDocument{}}
}

func (f *fakeSvcDocRepo) fail(op string) error {
	if f.failOn == op {
		return errors.New("db unavailable")
	}
	return nil
}

func (f *fakeSvcDocRepo) Get(_ context.Context, clientID, subjectHash, docKey string) (*repository.ServiceDocument, error) {
	if err := f.fail("get"); err != nil {
		return nil, err
	}
	d, ok := f.rows[svcDocKey{clientID, subjectHash, docKey}]
	if !ok {
		return nil, nil
	}
	cp := *d
	return &cp, nil
}

func (f *fakeSvcDocRepo) ListSharedByKey(_ context.Context, subjectHash, docKey, exclude string) ([]*repository.ServiceDocument, error) {
	if err := f.fail("shared"); err != nil {
		return nil, err
	}
	var out []*repository.ServiceDocument
	for k, d := range f.rows {
		if k.subject == subjectHash && k.key == docKey && k.client != exclude && d.Visibility == repository.VisibilityShared {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeSvcDocRepo) Upsert(_ context.Context, doc *repository.ServiceDocument) (bool, error) {
	if err := f.fail("upsert"); err != nil {
		return false, err
	}
	k := svcDocKey{doc.ClientID, doc.SubjectHash, doc.DocKey}
	_, existed := f.rows[k]
	cp := *doc
	f.rows[k] = &cp
	return !existed, nil
}

func (f *fakeSvcDocRepo) Delete(_ context.Context, clientID, subjectHash, docKey string) (bool, error) {
	if err := f.fail("delete"); err != nil {
		return false, err
	}
	k := svcDocKey{clientID, subjectHash, docKey}
	if _, ok := f.rows[k]; !ok {
		return false, nil
	}
	delete(f.rows, k)
	return true, nil
}

func (f *fakeSvcDocRepo) ListByOwner(_ context.Context, clientID, subjectHash string) ([]*repository.ServiceDocument, error) {
	if err := f.fail("listOwner"); err != nil {
		return nil, err
	}
	var out []*repository.ServiceDocument
	for k, d := range f.rows {
		if k.client == clientID && k.subject == subjectHash {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeSvcDocRepo) ListSharedForSubject(_ context.Context, subjectHash, exclude string) ([]*repository.ServiceDocument, error) {
	if err := f.fail("listShared"); err != nil {
		return nil, err
	}
	var out []*repository.ServiceDocument
	for k, d := range f.rows {
		if k.subject == subjectHash && k.client != exclude && d.Visibility == repository.VisibilityShared {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeSvcDocRepo) ListAllForSubject(_ context.Context, subjectHash string) ([]*repository.ServiceDocument, error) {
	if err := f.fail("listAll"); err != nil {
		return nil, err
	}
	var out []*repository.ServiceDocument
	for k, d := range f.rows {
		if k.subject == subjectHash {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeSvcDocRepo) CountForOwner(_ context.Context, clientID, subjectHash string) (int, error) {
	if err := f.fail("count"); err != nil {
		return 0, err
	}
	n := 0
	for k := range f.rows {
		if k.client == clientID && k.subject == subjectHash {
			n++
		}
	}
	return n, nil
}

func (f *fakeSvcDocRepo) SumBytesForSubjectAndClient(_ context.Context, subjectHash, clientID string) (int, error) {
	if err := f.fail("sum"); err != nil {
		return 0, err
	}
	total := 0
	for k, d := range f.rows {
		if k.subject == subjectHash && k.client == clientID {
			total += d.StoredBytes
		}
	}
	return total, nil
}

func (f *fakeSvcDocRepo) DeleteAllForSubject(_ context.Context, subjectHash string) error {
	if err := f.fail("deleteAll"); err != nil {
		return err
	}
	for k := range f.rows {
		if k.subject == subjectHash {
			delete(f.rows, k)
		}
	}
	return nil
}

type fakeSvcDocClients struct {
	byID   map[string]*model.Client
	byName map[string]*model.Client
}

func newFakeSvcDocClients(clients ...*model.Client) *fakeSvcDocClients {
	f := &fakeSvcDocClients{byID: map[string]*model.Client{}, byName: map[string]*model.Client{}}
	for _, c := range clients {
		f.byID[c.ID] = c
		f.byName[c.Name] = c
	}
	return f
}

func (f *fakeSvcDocClients) Create(context.Context, *model.Client) error { return nil }
func (f *fakeSvcDocClients) GetByID(_ context.Context, id string) (*model.Client, error) {
	return f.byID[id], nil
}

func (f *fakeSvcDocClients) GetByName(_ context.Context, name string) (*model.Client, error) {
	return f.byName[name], nil
}
func (f *fakeSvcDocClients) List(context.Context) ([]*model.Client, error) { return nil, nil }
func (f *fakeSvcDocClients) Update(context.Context, *model.Client) error   { return nil }
func (f *fakeSvcDocClients) Deactivate(context.Context, string) error      { return nil }

// unreachableSvcDocClients answers every lookup with a database failure, which
// is the case the service has to tell apart from "no such client": one is a
// 404 the caller can act on, the other is an outage.
type unreachableSvcDocClients struct{}

func (unreachableSvcDocClients) Create(context.Context, *model.Client) error { return nil }
func (unreachableSvcDocClients) GetByID(context.Context, string) (*model.Client, error) {
	return nil, errors.New("client directory unavailable")
}

func (unreachableSvcDocClients) GetByName(context.Context, string) (*model.Client, error) {
	return nil, errors.New("client directory unavailable")
}
func (unreachableSvcDocClients) List(context.Context) ([]*model.Client, error) { return nil, nil }
func (unreachableSvcDocClients) Update(context.Context, *model.Client) error   { return nil }
func (unreachableSvcDocClients) Deactivate(context.Context, string) error      { return nil }

// fakeSvcDocMetrics counts what the service reports. Metrics are optional, so
// the collector is an interface and every recording site is behind a nil check.
type fakeSvcDocMetrics struct{ writes, reads, rejected int }

func (m *fakeSvcDocMetrics) RecordSvcDocWrite()    { m.writes++ }
func (m *fakeSvcDocMetrics) RecordSvcDocRead()     { m.reads++ }
func (m *fakeSvcDocMetrics) RecordSvcDocRejected() { m.rejected++ }

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const (
	svcDocClientA = "11111111-1111-1111-1111-111111111111"
	svcDocClientB = "22222222-2222-2222-2222-222222222222"
)

func svcDocMasterKey(n int) []byte {
	k := make([]byte, n)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func svcDocHMACSecret() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(255 - i)
	}
	return s
}

func svcDocRegisteredClients() *fakeSvcDocClients {
	return newFakeSvcDocClients(
		&model.Client{ID: svcDocClientA, Name: "service-a"},
		&model.Client{ID: svcDocClientB, Name: "service-b"},
	)
}

func newSvcDocService(t *testing.T, repo *fakeSvcDocRepo, cfg DocumentConfig) *DocumentService {
	t.Helper()
	return NewDocumentService(repo, svcDocRegisteredClients(),
		svcDocMasterKey(32), svcDocHMACSecret(), cfg, nil)
}

// newSvcDocServiceWith builds a service over collaborators the default harness
// cannot express: a deployment with no client directory, a directory that is
// down, a metrics collector, or a master key the AES layer refuses.
func newSvcDocServiceWith(
	repo *fakeSvcDocRepo, clients repository.ClientRepository,
	cfg DocumentConfig, metrics DocumentMetrics, masterKey []byte,
) *DocumentService {
	return NewDocumentService(repo, clients, masterKey, svcDocHMACSecret(), cfg, metrics)
}

func defaultSvcDocConfig() DocumentConfig {
	return DocumentConfig{
		MaxDocumentBytes:     64 * 1024,
		MaxDocsPerSubject:    32,
		QuotaBytesPerSubject: 1024 * 1024,
		SharedEnabled:        true,
	}
}

// ---------------------------------------------------------------------------
// Document validation
// ---------------------------------------------------------------------------

// A 64 KiB body of array openers is tens of thousands of nesting levels. It has
// to be refused on the token stream: unmarshalling it recurses to the same depth
// and takes the process down, so a validator that only runs after a successful
// decode never gets to run at all.
func TestValidateDocumentStructure_RejectsDepthBomb(t *testing.T) {
	bomb := `{"a":` + strings.Repeat("[", 40000) + strings.Repeat("]", 40000) + `}`
	if err := ValidateDocumentStructure([]byte(bomb)); !errors.Is(err, ErrSvcDocInvalidDocument) {
		t.Fatalf("depth bomb accepted: %v", err)
	}
}

func TestValidateDocumentStructure_DepthBoundary(t *testing.T) {
	// The top-level object is level 1, so svcDocMaxDepth nested objects sit
	// exactly on the limit and one more is over it.
	atLimit := strings.Repeat(`{"a":`, svcDocMaxDepth) + `1` + strings.Repeat(`}`, svcDocMaxDepth)
	if err := ValidateDocumentStructure([]byte(atLimit)); err != nil {
		t.Fatalf("document at the depth limit rejected: %v", err)
	}
	overLimit := strings.Repeat(`{"a":`, svcDocMaxDepth+1) + `1` + strings.Repeat(`}`, svcDocMaxDepth+1)
	if err := ValidateDocumentStructure([]byte(overLimit)); !errors.Is(err, ErrSvcDocInvalidDocument) {
		t.Fatalf("document past the depth limit accepted: %v", err)
	}
}

// encoding/json silently accepts duplicate keys last-wins, so a document would
// round-trip differently than it was submitted.
func TestValidateDocumentStructure_RejectsDuplicateKeys(t *testing.T) {
	for _, doc := range []string{
		`{"a":1,"a":2}`,
		`{"outer":{"b":1,"b":2}}`,
		`{"list":[{"c":1,"c":2}]}`,
	} {
		if err := ValidateDocumentStructure([]byte(doc)); !errors.Is(err, ErrSvcDocInvalidDocument) {
			t.Errorf("duplicate key accepted in %s: %v", doc, err)
		}
	}
}

func TestValidateDocumentStructure_RejectsNonObjectTopLevel(t *testing.T) {
	for _, doc := range []string{`[1,2,3]`, `"scalar"`, `42`, `true`, `null`, ``, `{`, `{}{}`} {
		if err := ValidateDocumentStructure([]byte(doc)); !errors.Is(err, ErrSvcDocInvalidDocument) {
			t.Errorf("non-object top level accepted: %q (%v)", doc, err)
		}
	}
}

func TestValidateDocumentStructure_RejectsTooManyKeys(t *testing.T) {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i <= svcDocMaxKeys; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"k`)
		b.WriteString(strings.Repeat("0", 1))
		b.WriteString(itoa(i))
		b.WriteString(`":1`)
	}
	b.WriteString("}")
	if err := ValidateDocumentStructure([]byte(b.String())); !errors.Is(err, ErrSvcDocInvalidDocument) {
		t.Fatalf("document past the key limit accepted: %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}

func TestValidateDocumentStructure_AcceptsNestedDocument(t *testing.T) {
	doc := `{"prefs":{"show_real_name":false,"tags":["a","b"],"n":null},"count":3}`
	if err := ValidateDocumentStructure([]byte(doc)); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Canonicalisation
// ---------------------------------------------------------------------------

func TestPut_RejectsInvalidUTF8(t *testing.T) {
	svc := newSvcDocService(t, newFakeSvcDocRepo(), defaultSvcDocConfig())
	raw := []byte("{\"a\":\"\xff\xfe\"}")
	_, _, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs", raw, repository.VisibilityPrivate)
	if !errors.Is(err, ErrSvcDocInvalidDocument) {
		t.Fatalf("invalid UTF-8 accepted: %v", err)
	}
}

func TestPut_RejectsOversizeDocument(t *testing.T) {
	cfg := defaultSvcDocConfig()
	cfg.MaxDocumentBytes = 128
	svc := newSvcDocService(t, newFakeSvcDocRepo(), cfg)
	raw := []byte(`{"a":"` + strings.Repeat("x", 200) + `"}`)
	_, _, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs", raw, repository.VisibilityPrivate)
	if !errors.Is(err, ErrSvcDocTooLarge) {
		t.Fatalf("oversize document accepted: %v", err)
	}
}

// A stored document must be byte-faithful to what the service submitted. Go's
// default encoder escapes '<', '>' and '&', which would silently rewrite any
// value carrying markup or a query string.
func TestPut_PreservesMarkupAndNumberPrecision(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	raw := []byte(`{"html":"<b>&amp;</b>","big":123456789012345678901234567890,"exact":0.1000000000000000055511151231257827}`)

	if _, _, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs", raw, repository.VisibilityPrivate); err != nil {
		t.Fatalf("put: %v", err)
	}
	body, _, err := svc.Get(context.Background(), svcDocClientA, "user-1", "prefs", "")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got := string(body)
	for _, want := range []string{`"<b>&amp;</b>"`, `123456789012345678901234567890`, `0.1000000000000000055511151231257827`} {
		if !strings.Contains(got, want) {
			t.Errorf("stored document lost %s: %s", want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Key / subject validation
// ---------------------------------------------------------------------------

func TestValidateDocKey(t *testing.T) {
	valid := []string{"prefs", "beon3.profile_prefs", "a-b.c_d", "x1"}
	for _, k := range valid {
		if err := ValidateDocKey(k); err != nil {
			t.Errorf("valid key %q rejected: %v", k, err)
		}
	}
	invalid := []string{"", "UPPER", ".leading", "trailing.", "a..b", "a/b", "../etc", strings.Repeat("a", 129)}
	for _, k := range invalid {
		if err := ValidateDocKey(k); !errors.Is(err, ErrSvcDocInvalidKey) {
			t.Errorf("invalid key %q accepted", k)
		}
	}
}

// The global sentinel must not be reachable as an ordinary subject, or a caller
// could write a service's global configuration by naming it as a user.
func TestValidateSubject_GlobalSentinelIsNotASubjectCharset(t *testing.T) {
	if err := ValidateSubject(GlobalSubject); err != nil {
		t.Fatalf("global sentinel rejected: %v", err)
	}
	for _, s := range []string{"", "_global2", "_other", "has space", "a\nb", strings.Repeat("a", 129)} {
		if err := ValidateSubject(s); !errors.Is(err, ErrSvcDocInvalidSubject) {
			t.Errorf("invalid subject %q accepted", s)
		}
	}
}

func TestSubjectHash_GlobalIsDistinctFromEveryUser(t *testing.T) {
	svc := newSvcDocService(t, newFakeSvcDocRepo(), defaultSvcDocConfig())
	if svc.subjectHash(GlobalSubject) == svc.SubjectPseudonym(GlobalSubject) {
		t.Fatal("global sentinel hashes to the same value as a user literally named _global")
	}
	if svc.subjectHash("user-1") != svc.SubjectPseudonym("user-1") {
		t.Fatal("subject hashing diverged from the pseudonym the erasure cascade derives")
	}
}

// ---------------------------------------------------------------------------
// Round trip, ownership, visibility
// ---------------------------------------------------------------------------

func TestPut_CreatedThenReplaced(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	ctx := context.Background()

	_, created, err := svc.Put(ctx, svcDocClientA, "user-1", "prefs", []byte(`{"a":1}`), repository.VisibilityPrivate)
	if err != nil || !created {
		t.Fatalf("first write: created=%v err=%v", created, err)
	}
	_, created, err = svc.Put(ctx, svcDocClientA, "user-1", "prefs", []byte(`{"a":2}`), repository.VisibilityPrivate)
	if err != nil || created {
		t.Fatalf("second write: created=%v err=%v", created, err)
	}
	if len(repo.rows) != 1 {
		t.Fatalf("replacement created a second row: %d rows", len(repo.rows))
	}
}

// A private document belonging to another service must be indistinguishable
// from one that does not exist. Returning a forbidden instead would turn the
// store into an oracle for "does service X hold a record about user U".
func TestGet_OtherClientsPrivateDocumentIsNotFound(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	ctx := context.Background()

	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "prefs", []byte(`{"a":1}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, _, err := svc.Get(ctx, svcDocClientB, "user-1", "prefs", ""); !errors.Is(err, ErrSvcDocNotFound) {
		t.Fatalf("private document leaked across clients: %v", err)
	}
	// Naming the owner explicitly must not change the answer.
	if _, _, err := svc.Get(ctx, svcDocClientB, "user-1", "prefs", "service-a"); !errors.Is(err, ErrSvcDocNotFound) {
		t.Fatalf("private document leaked when the owner was named: %v", err)
	}
}

func TestGet_SharedDocumentIsReadableByOtherClients(t *testing.T) {
	svc := newSvcDocService(t, newFakeSvcDocRepo(), defaultSvcDocConfig())
	ctx := context.Background()

	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "flags", []byte(`{"beta":true}`), repository.VisibilityShared); err != nil {
		t.Fatalf("put: %v", err)
	}
	body, meta, err := svc.Get(ctx, svcDocClientB, "user-1", "flags", "")
	if err != nil {
		t.Fatalf("shared read failed: %v", err)
	}
	if meta.Mine {
		t.Error("another client's shared document reported as mine")
	}
	if meta.Owner != "service-a" {
		t.Errorf("owner name = %q, want service-a", meta.Owner)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil || decoded["beta"] != true {
		t.Fatalf("shared body mismatch: %s (%v)", body, err)
	}
}

// Two services publishing the same key for the same subject is a real
// possibility, and picking one arbitrarily would make reads nondeterministic.
func TestGet_AmbiguousSharedKeyRequiresAnOwner(t *testing.T) {
	svc := newSvcDocService(t, newFakeSvcDocRepo(), defaultSvcDocConfig())
	ctx := context.Background()
	const thirdClient = "33333333-3333-3333-3333-333333333333"

	for _, c := range []string{svcDocClientA, svcDocClientB} {
		if _, _, err := svc.Put(ctx, c, "user-1", "flags", []byte(`{"x":1}`), repository.VisibilityShared); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	if _, _, err := svc.Get(ctx, thirdClient, "user-1", "flags", ""); !errors.Is(err, ErrSvcDocAmbiguous) {
		t.Fatalf("ambiguous key resolved silently: %v", err)
	}
	if _, meta, err := svc.Get(ctx, thirdClient, "user-1", "flags", "service-b"); err != nil {
		t.Fatalf("named owner read failed: %v", err)
	} else if meta.OwnerID != svcDocClientB {
		t.Fatalf("named owner resolved to %s", meta.OwnerID)
	}
	if _, _, err := svc.Get(ctx, thirdClient, "user-1", "flags", "nobody"); !errors.Is(err, ErrSvcDocUnknownOwner) {
		t.Fatalf("unknown owner accepted: %v", err)
	}
}

func TestPut_SharedRejectedWhenTierDisabled(t *testing.T) {
	cfg := defaultSvcDocConfig()
	cfg.SharedEnabled = false
	svc := newSvcDocService(t, newFakeSvcDocRepo(), cfg)
	_, _, err := svc.Put(context.Background(), svcDocClientA, "user-1", "flags", []byte(`{"x":1}`), repository.VisibilityShared)
	if !errors.Is(err, ErrSvcDocSharedDisabled) {
		t.Fatalf("shared write accepted with the tier disabled: %v", err)
	}
}

func TestParseVisibility(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want repository.ServiceDocumentVisibility
		ok   bool
	}{
		{"", repository.VisibilityPrivate, true},
		{"private", repository.VisibilityPrivate, true},
		{"shared", repository.VisibilityShared, true},
		{"restricted", repository.VisibilityPrivate, false},
		{"1", repository.VisibilityPrivate, false},
	} {
		got, ok := ParseVisibility(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ParseVisibility(%q) = (%v,%v), want (%v,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// The AAD binds a ciphertext to its owning client, its subject and its key, so
// a row moved between any of them must fail to decrypt rather than change owner.
func TestGet_CiphertextIsBoundToOwnerSubjectAndKey(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	ctx := context.Background()

	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "prefs", []byte(`{"a":1}`), repository.VisibilityShared); err != nil {
		t.Fatalf("put: %v", err)
	}
	row := repo.rows[svcDocKey{svcDocClientA, svc.subjectHash("user-1"), "prefs"}]

	moved := *row
	moved.ClientID = svcDocClientB
	repo.rows[svcDocKey{svcDocClientB, moved.SubjectHash, moved.DocKey}] = &moved
	if _, _, err := svc.Get(ctx, svcDocClientB, "user-1", "prefs", ""); err == nil {
		t.Fatal("a row copied to another client decrypted successfully")
	}

	rekeyed := *row
	rekeyed.DocKey = "other"
	repo.rows[svcDocKey{svcDocClientA, rekeyed.SubjectHash, "other"}] = &rekeyed
	if _, _, err := svc.Get(ctx, svcDocClientA, "user-1", "other", ""); err == nil {
		t.Fatal("a row copied to another key decrypted successfully")
	}
}

// ---------------------------------------------------------------------------
// Quotas
// ---------------------------------------------------------------------------

func TestPut_DocumentCountQuota(t *testing.T) {
	cfg := defaultSvcDocConfig()
	cfg.MaxDocsPerSubject = 2
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, cfg)
	ctx := context.Background()

	for _, k := range []string{"one", "two"} {
		if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", k, []byte(`{"a":1}`), repository.VisibilityPrivate); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
	}
	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "three", []byte(`{"a":1}`), repository.VisibilityPrivate); !errors.Is(err, ErrSvcDocQuotaExceeded) {
		t.Fatalf("count quota not enforced: %v", err)
	}
	// Replacing an existing document consumes no new slot.
	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "two", []byte(`{"a":2}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("replacement refused at the count quota: %v", err)
	}
}

// The byte quota is enforced per (client, subject): the caller is charged
// against its own footprint, never a cross-client total. Before the fix the sum
// spanned every owning client, so one svcdoc:write client could fill a subject's
// shared budget and every OTHER service's write for that subject then failed 409
// forever. The last assertion below is that write-DoS fix.
func TestPut_ByteQuotaIsPerClientAndDiscountsTheReplacedRow(t *testing.T) {
	ctx := context.Background()
	body := []byte(`{"pad":"` + strings.Repeat("x", 100) + `"}`)

	// One document's stored size, measured rather than hardcoding the AES-GCM
	// overhead, so the budget can be sized to admit two documents but not three.
	probeRepo := newFakeSvcDocRepo()
	probe := newSvcDocService(t, probeRepo, defaultSvcDocConfig())
	pm, _, err := probe.Put(ctx, svcDocClientA, "user-1", "probe", body, repository.VisibilityPrivate)
	if err != nil {
		t.Fatalf("probe write: %v", err)
	}
	one := pm.StoredBytes

	cfg := defaultSvcDocConfig()
	cfg.QuotaBytesPerSubject = 2*one + one/2
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, cfg)

	// Client A fills its own budget to two documents.
	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "a", body, repository.VisibilityPrivate); err != nil {
		t.Fatalf("A first write: %v", err)
	}
	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "b", body, repository.VisibilityPrivate); err != nil {
		t.Fatalf("A second write: %v", err)
	}
	// A third document by A breaches A's own budget.
	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "c", body, repository.VisibilityPrivate); !errors.Is(err, ErrSvcDocQuotaExceeded) {
		t.Fatalf("A's own byte budget not enforced: %v", err)
	}
	// Rewriting an existing document at the same size discounts the row it
	// replaces, so it stays inside the budget.
	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "a", body, repository.VisibilityPrivate); err != nil {
		t.Fatalf("replacement double-counted its own bytes: %v", err)
	}
	// Client B writing about the SAME subject is charged only against B's own
	// bytes, so it succeeds even though A has filled A's budget. Before the fix
	// the budget spanned clients and this was a permanent 409.
	if _, _, err := svc.Put(ctx, svcDocClientB, "user-1", "b", body, repository.VisibilityPrivate); err != nil {
		t.Fatalf("another client's write blocked by A's usage (cross-service write-DoS): %v", err)
	}
}

// A listing reports only the CALLER'S own used_bytes. A cross-client total would
// tell any svcdoc:read caller that another service holds data about the subject,
// and how much, which is the presence oracle the pseudonymised subject denies.
func TestList_UsedBytesIsCallerScopedNotCrossClient(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	ctx := context.Background()

	body := []byte(`{"pad":"` + strings.Repeat("x", 100) + `"}`)
	aMeta, _, err := svc.Put(ctx, svcDocClientA, "user-1", "a", body, repository.VisibilityPrivate)
	if err != nil {
		t.Fatalf("A write: %v", err)
	}

	// B holds nothing of its own for the subject, so its used_bytes is zero and
	// must not carry A's footprint.
	_, quotaB, err := svc.List(ctx, svcDocClientB, "user-1")
	if err != nil {
		t.Fatalf("B list: %v", err)
	}
	if quotaB.UsedBytes != 0 {
		t.Fatalf("used_bytes leaked another client's footprint: got %d, want 0", quotaB.UsedBytes)
	}

	// A's own listing still reports A's own footprint.
	_, quotaA, err := svc.List(ctx, svcDocClientA, "user-1")
	if err != nil {
		t.Fatalf("A list: %v", err)
	}
	if quotaA.UsedBytes != aMeta.StoredBytes {
		t.Fatalf("caller's own used_bytes = %d, want %d", quotaA.UsedBytes, aMeta.StoredBytes)
	}
}

// The shared kill switch gates reads as well as writes. A row shared while the
// tier was on must stop being readable or listable by other clients the moment
// an operator turns the tier off, rather than staying visible until it is
// rewritten. The owner keeps its own row throughout.
func TestSharedReadPathsAreGatedOnSharedEnabled(t *testing.T) {
	repo := newFakeSvcDocRepo()
	ctx := context.Background()

	on := newSvcDocService(t, repo, defaultSvcDocConfig())
	if _, _, err := on.Put(ctx, svcDocClientA, "user-1", "flags", []byte(`{"beta":true}`), repository.VisibilityShared); err != nil {
		t.Fatalf("share: %v", err)
	}
	// Sanity: with the tier on, another client can read the shared row.
	if _, _, err := on.Get(ctx, svcDocClientB, "user-1", "flags", ""); err != nil {
		t.Fatalf("shared read with the tier on: %v", err)
	}

	offCfg := defaultSvcDocConfig()
	offCfg.SharedEnabled = false
	off := newSvcDocService(t, repo, offCfg)

	if _, _, err := off.Get(ctx, svcDocClientB, "user-1", "flags", ""); !errors.Is(err, ErrSvcDocNotFound) {
		t.Fatalf("shared row readable after the tier was disabled: %v", err)
	}
	if _, _, err := off.Get(ctx, svcDocClientB, "user-1", "flags", "service-a"); !errors.Is(err, ErrSvcDocNotFound) {
		t.Fatalf("shared row readable by named owner after the tier was disabled: %v", err)
	}
	metas, _, err := off.List(ctx, svcDocClientB, "user-1")
	if err != nil {
		t.Fatalf("B list: %v", err)
	}
	for _, m := range metas {
		if m.OwnerID == svcDocClientA {
			t.Fatalf("another client's shared row listed after the tier was disabled: %+v", m)
		}
	}

	// The owner still reads and lists its own row regardless of the tier.
	if _, _, err := off.Get(ctx, svcDocClientA, "user-1", "flags", ""); err != nil {
		t.Fatalf("owner lost its own row when the tier was disabled: %v", err)
	}
	ownMetas, _, err := off.List(ctx, svcDocClientA, "user-1")
	if err != nil {
		t.Fatalf("A list: %v", err)
	}
	if len(ownMetas) != 1 {
		t.Fatalf("owner's own listing = %d rows, want 1", len(ownMetas))
	}
}

// ---------------------------------------------------------------------------
// Delete, list
// ---------------------------------------------------------------------------

func TestDelete_OwnerOnly(t *testing.T) {
	svc := newSvcDocService(t, newFakeSvcDocRepo(), defaultSvcDocConfig())
	ctx := context.Background()

	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "prefs", []byte(`{"a":1}`), repository.VisibilityShared); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := svc.Delete(ctx, svcDocClientB, "user-1", "prefs"); !errors.Is(err, ErrSvcDocNotFound) {
		t.Fatalf("a non-owner deleted a shared document: %v", err)
	}
	if err := svc.Delete(ctx, svcDocClientA, "user-1", "prefs"); err != nil {
		t.Fatalf("owner delete failed: %v", err)
	}
	if err := svc.Delete(ctx, svcDocClientA, "user-1", "prefs"); !errors.Is(err, ErrSvcDocNotFound) {
		t.Fatalf("second delete did not report absence: %v", err)
	}
}

func TestList_OwnPlusSharedWithQuota(t *testing.T) {
	cfg := defaultSvcDocConfig()
	svc := newSvcDocService(t, newFakeSvcDocRepo(), cfg)
	ctx := context.Background()

	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "mine", []byte(`{"a":1}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, _, err := svc.Put(ctx, svcDocClientB, "user-1", "theirs", []byte(`{"a":1}`), repository.VisibilityShared); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, _, err := svc.Put(ctx, svcDocClientB, "user-1", "hidden", []byte(`{"a":1}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("put: %v", err)
	}

	metas, quota, err := svc.List(ctx, svcDocClientA, "user-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	seen := map[string]bool{}
	for _, m := range metas {
		seen[m.Key] = true
	}
	if !seen["mine"] || !seen["theirs"] {
		t.Fatalf("listing missed a readable document: %v", seen)
	}
	if seen["hidden"] {
		t.Fatal("listing exposed another client's private document")
	}
	if quota.MaxCount != cfg.MaxDocsPerSubject || quota.MaxBytes != cfg.QuotaBytesPerSubject {
		t.Fatalf("quota reported as %+v", quota)
	}
	if quota.UsedCount != 1 {
		t.Fatalf("used count counts other clients' documents: %d", quota.UsedCount)
	}
}

// ---------------------------------------------------------------------------
// GDPR
// ---------------------------------------------------------------------------

// The export must carry bodies, must include documents the subject cannot see
// through any request path, and must not leak a service's global configuration.
func TestExportForSubject_IncludesPrivateBodiesAndExcludesGlobal(t *testing.T) {
	svc := newSvcDocService(t, newFakeSvcDocRepo(), defaultSvcDocConfig())
	ctx := context.Background()

	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "prefs", []byte(`{"show_real_name":false}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, _, err := svc.Put(ctx, svcDocClientB, GlobalSubject, "flags", []byte(`{"beta":true}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("put global: %v", err)
	}
	if _, _, err := svc.Put(ctx, svcDocClientA, "user-2", "prefs", []byte(`{"other":true}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("put other user: %v", err)
	}

	out, err := svc.ExportForSubject(ctx, "user-1")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("export returned %d documents, want 1", len(out))
	}
	if out[0].Owner != "service-a" || out[0].Key != "prefs" {
		t.Fatalf("export metadata wrong: %+v", out[0])
	}
	if !strings.Contains(string(out[0].Document), `"show_real_name":false`) {
		t.Fatalf("export omitted the document body: %s", out[0].Document)
	}
}

// A row that cannot be decrypted must not deny the subject the rest of the
// export.
func TestExportForSubject_SkipsUndecryptableRows(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	ctx := context.Background()

	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "good", []byte(`{"a":1}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("put: %v", err)
	}
	subj := svc.SubjectPseudonym("user-1")
	repo.rows[svcDocKey{svcDocClientB, subj, "corrupt"}] = &repository.ServiceDocument{
		ID: "x", ClientID: svcDocClientB, SubjectHash: subj, DocKey: "corrupt",
		DataEnc: []byte("not a ciphertext"), SizeBytes: 16, StoredBytes: 16,
	}

	out, err := svc.ExportForSubject(ctx, "user-1")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(out) != 1 || out[0].Key != "good" {
		t.Fatalf("export = %d rows, want only the readable one", len(out))
	}
}

// Erasure must clear every document held about a user across every owning
// service, must leave other subjects alone, must leave global documents alone,
// and must be safe to re-run after an interrupted cascade.
func TestDeleteAllForSubject_SpansClientsAndIsIdempotent(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	ctx := context.Background()

	for _, c := range []string{svcDocClientA, svcDocClientB} {
		if _, _, err := svc.Put(ctx, c, "user-1", "prefs", []byte(`{"a":1}`), repository.VisibilityPrivate); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	if _, _, err := svc.Put(ctx, svcDocClientA, "user-2", "prefs", []byte(`{"a":1}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, _, err := svc.Put(ctx, svcDocClientA, GlobalSubject, "flags", []byte(`{"a":1}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("put global: %v", err)
	}

	if err := svc.DeleteAllForSubject(ctx, "user-1"); err != nil {
		t.Fatalf("erasure: %v", err)
	}
	if err := svc.DeleteAllForSubject(ctx, "user-1"); err != nil {
		t.Fatalf("erasure re-run failed: %v", err)
	}
	if len(repo.rows) != 2 {
		t.Fatalf("erasure removed %d rows too many or too few: %d remain", 4-len(repo.rows), len(repo.rows))
	}
	for k := range repo.rows {
		if k.subject == svc.SubjectPseudonym("user-1") {
			t.Fatal("a document survived the erasure of its subject")
		}
	}
}

// ---------------------------------------------------------------------------
// Failure propagation
// ---------------------------------------------------------------------------

// A quota lookup that failed open would let a caller write past the limit.
func TestPut_SurfacesQuotaLookupFailure(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "sum"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	_, _, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs", []byte(`{"a":1}`), repository.VisibilityPrivate)
	if err == nil {
		t.Fatal("quota lookup failure reported as success")
	}
	if errors.Is(err, ErrSvcDocQuotaExceeded) {
		t.Fatal("a database failure was reported as a quota rejection")
	}
}

func TestGet_SurfacesRepositoryFailure(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "get"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	if _, _, err := svc.Get(context.Background(), svcDocClientA, "user-1", "prefs", ""); err == nil {
		t.Fatal("repository failure reported as success")
	}
}

// A quota lookup that failed open would let a caller write past the document
// count, so the count failure has to reach the caller as a failure and not as
// the quota rejection an operator would read as working-as-intended.
func TestPut_SurfacesTheDocumentCountLookupFailure(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "count"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())

	_, _, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs",
		[]byte(`{"a":1}`), repository.VisibilityPrivate)
	if err == nil {
		t.Fatal("document count lookup failure reported as success")
	}
	if errors.Is(err, ErrSvcDocQuotaExceeded) {
		t.Fatal("a database failure was reported as a quota rejection")
	}
	if len(repo.rows) != 0 {
		t.Fatalf("a document was stored although its quota was never established: %d rows", len(repo.rows))
	}
}

// The quota is checked against the state the write would produce, so the read of
// the row being replaced is part of the quota decision. Failing it open would
// charge a replacement as a new document, or skip the check entirely.
func TestPut_SurfacesTheExistingDocumentLoadFailure(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "get"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())

	_, _, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs",
		[]byte(`{"a":1}`), repository.VisibilityPrivate)
	if err == nil {
		t.Fatal("existing document load failure reported as success")
	}
	if len(repo.rows) != 0 {
		t.Fatalf("a document was stored although the row it replaces could not be read: %d rows", len(repo.rows))
	}
}

// Every at-rest store in vault42 is encrypted. A write whose encryption fails
// must fail the request, never fall through to a row holding a shorter or empty
// body: a plaintext document here would be the product's first plaintext
// personal-data column.
func TestPut_StoresNothingWhenEncryptionFails(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocServiceWith(repo, svcDocRegisteredClients(), defaultSvcDocConfig(), nil,
		svcDocMasterKey(16))

	_, _, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs",
		[]byte(`{"a":1}`), repository.VisibilityPrivate)
	if err == nil {
		t.Fatal("a master key AES-256 cannot use produced a stored document")
	}
	if len(repo.rows) != 0 {
		t.Fatalf("a document was stored although it could not be encrypted: %d rows", len(repo.rows))
	}
}

// An upsert that failed silently would report a stored document to a caller that
// then stops holding the only copy.
func TestPut_SurfacesTheStoreFailure(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "upsert"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())

	meta, created, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs",
		[]byte(`{"a":1}`), repository.VisibilityPrivate)
	if err == nil {
		t.Fatal("store failure reported as success")
	}
	if meta != nil || created {
		t.Fatalf("a failed store returned meta=%v created=%v", meta, created)
	}
}

func TestSharedEnabled_ReportsTheConfiguredTier(t *testing.T) {
	cfg := defaultSvcDocConfig()
	if !newSvcDocService(t, newFakeSvcDocRepo(), cfg).SharedEnabled() {
		t.Error("shared tier reported off while configured on")
	}
	cfg.SharedEnabled = false
	if newSvcDocService(t, newFakeSvcDocRepo(), cfg).SharedEnabled() {
		t.Error("shared tier reported on while configured off")
	}
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

// Writes, reads and rejections are counted separately: a rejection counted as a
// write would hide a client hammering the store with documents it never stores.
func TestMetrics_CountWritesReadsAndRejectionsSeparately(t *testing.T) {
	m := &fakeSvcDocMetrics{}
	repo := newFakeSvcDocRepo()
	svc := newSvcDocServiceWith(repo, svcDocRegisteredClients(), defaultSvcDocConfig(), m,
		svcDocMasterKey(32))
	ctx := context.Background()

	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "prefs", []byte(`{"a":1}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, _, err := svc.Get(ctx, svcDocClientA, "user-1", "prefs", ""); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "NOT A KEY", []byte(`{"a":1}`), repository.VisibilityPrivate); err == nil {
		t.Fatal("invalid key accepted")
	}

	if m.writes != 1 {
		t.Errorf("writes = %d, want 1", m.writes)
	}
	if m.reads != 1 {
		t.Errorf("reads = %d, want 1", m.reads)
	}
	if m.rejected != 1 {
		t.Errorf("rejections = %d, want 1", m.rejected)
	}
}

// ---------------------------------------------------------------------------
// Validation runs before the repository
// ---------------------------------------------------------------------------

// A malformed key or subject is a 400. Reaching the repository with one would
// turn it into a constraint violation surfacing as a 500, and would let an
// unvalidated value into the HMAC input and the query.
func TestGet_ValidatesKeyAndSubjectBeforeTouchingTheRepository(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "get"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	ctx := context.Background()

	if _, _, err := svc.Get(ctx, svcDocClientA, "user-1", "NOT A KEY", ""); !errors.Is(err, ErrSvcDocInvalidKey) {
		t.Fatalf("invalid key reached the repository: %v", err)
	}
	if _, _, err := svc.Get(ctx, svcDocClientA, "not a subject", "prefs", ""); !errors.Is(err, ErrSvcDocInvalidSubject) {
		t.Fatalf("invalid subject reached the repository: %v", err)
	}
}

func TestDelete_ValidatesKeyAndSubjectBeforeTouchingTheRepository(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "delete"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	ctx := context.Background()

	if err := svc.Delete(ctx, svcDocClientA, "user-1", "NOT A KEY"); !errors.Is(err, ErrSvcDocInvalidKey) {
		t.Fatalf("invalid key reached the repository: %v", err)
	}
	if err := svc.Delete(ctx, svcDocClientA, "not a subject", "prefs"); !errors.Is(err, ErrSvcDocInvalidSubject) {
		t.Fatalf("invalid subject reached the repository: %v", err)
	}
}

// A delete that failed must not be reported as ErrSvcDocNotFound: the caller
// reads absence as "already gone" and stops retrying while the row is still
// there.
func TestDelete_SurfacesTheRepositoryFailureRatherThanReportingAbsence(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "delete"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())

	err := svc.Delete(context.Background(), svcDocClientA, "user-1", "prefs")
	if err == nil {
		t.Fatal("delete failure reported as success")
	}
	if errors.Is(err, ErrSvcDocNotFound) {
		t.Fatal("a database failure was reported as an absent document")
	}
}

func TestList_ValidatesTheSubjectBeforeTouchingTheRepository(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "listOwner"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())

	if _, _, err := svc.List(context.Background(), svcDocClientA, "not a subject"); !errors.Is(err, ErrSvcDocInvalidSubject) {
		t.Fatalf("invalid subject reached the repository: %v", err)
	}
}

// A listing is assembled from three independent lookups. Any one of them failing
// open would return a listing the caller reads as complete: a missing document,
// or a quota position that understates what the subject already holds.
func TestList_SurfacesEveryLookupFailureRatherThanReturningAPartialListing(t *testing.T) {
	for _, op := range []string{"listOwner", "listShared", "sum"} {
		repo := newFakeSvcDocRepo()
		repo.failOn = op
		svc := newSvcDocService(t, repo, defaultSvcDocConfig())

		metas, quota, err := svc.List(context.Background(), svcDocClientA, "user-1")
		if err == nil {
			t.Errorf("%s failure reported as a complete listing", op)
		}
		if metas != nil || quota != nil {
			t.Errorf("%s failure returned metas=%v quota=%v", op, metas, quota)
		}
	}
}

// An export that reported "no documents held" because the query failed is an
// Art. 15 answer the subject cannot tell from a truthful empty one.
func TestExportForSubject_SurfacesTheLookupFailure(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "listAll"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())

	out, err := svc.ExportForSubject(context.Background(), "user-1")
	if err == nil {
		t.Fatal("export lookup failure reported as an empty export")
	}
	if out != nil {
		t.Fatalf("a failed export returned %d documents", len(out))
	}
}

// ---------------------------------------------------------------------------
// Owner resolution
// ---------------------------------------------------------------------------

// Naming an owner takes a different path through resolve than the default one,
// and it must not turn a database failure into "no such document".
func TestGet_SurfacesTheRepositoryFailureOnTheNamedOwnerPath(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "get"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())

	_, _, err := svc.Get(context.Background(), svcDocClientB, "user-1", "prefs", "service-a")
	if err == nil {
		t.Fatal("repository failure on the named owner path reported as success")
	}
	if errors.Is(err, ErrSvcDocNotFound) {
		t.Fatal("a database failure was reported as an absent document")
	}
}

// The shared lookup is the last resort when a caller holds no document of its
// own. Failing it open would report a shared document as absent, which is the
// same answer the store gives for a private one it may not read.
func TestGet_SurfacesTheSharedLookupFailure(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "shared"
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())

	_, _, err := svc.Get(context.Background(), svcDocClientA, "user-1", "prefs", "")
	if err == nil {
		t.Fatal("shared lookup failure reported as success")
	}
	if errors.Is(err, ErrSvcDocNotFound) {
		t.Fatal("a database failure was reported as an absent document")
	}
}

// A deployment can run without a client directory. Owner names are then a
// convenience the service does without: a named owner resolves to nothing, and
// a listing carries the owner id but no name. Neither may fail the request.
func TestGet_WithoutAClientDirectoryDropsOwnerNamesRatherThanFailing(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocServiceWith(repo, nil, defaultSvcDocConfig(), nil, svcDocMasterKey(32))
	ctx := context.Background()

	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "flags", []byte(`{"beta":true}`), repository.VisibilityShared); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, _, err := svc.Get(ctx, svcDocClientB, "user-1", "flags", "service-a"); !errors.Is(err, ErrSvcDocUnknownOwner) {
		t.Fatalf("a named owner resolved without a client directory: %v", err)
	}

	_, meta, err := svc.Get(ctx, svcDocClientA, "user-1", "flags", "")
	if err != nil {
		t.Fatalf("own read failed without a client directory: %v", err)
	}
	if meta.Owner != "" {
		t.Errorf("owner name = %q without a client directory", meta.Owner)
	}
	if meta.OwnerID != svcDocClientA {
		t.Errorf("owner id = %q, want %q", meta.OwnerID, svcDocClientA)
	}
}

// The name is a convenience and the id is already in the response, so a
// directory outage degrades the name to empty. Resolving a caller-supplied owner
// name is a different matter: that one decides which document is read, so it has
// to fail rather than silently fall through to the shared lookup.
func TestGet_ADirectoryOutageDropsTheOwnerNameButFailsOwnerResolution(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocServiceWith(repo, unreachableSvcDocClients{}, defaultSvcDocConfig(), nil,
		svcDocMasterKey(32))
	ctx := context.Background()

	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "flags", []byte(`{"beta":true}`), repository.VisibilityShared); err != nil {
		t.Fatalf("put: %v", err)
	}

	_, _, err := svc.Get(ctx, svcDocClientB, "user-1", "flags", "service-a")
	if err == nil {
		t.Fatal("owner resolution reported success against an unreachable directory")
	}
	if errors.Is(err, ErrSvcDocUnknownOwner) {
		t.Fatal("a directory outage was reported as an unregistered owner")
	}

	_, meta, err := svc.Get(ctx, svcDocClientA, "user-1", "flags", "")
	if err != nil {
		t.Fatalf("own read failed because the owner name could not be resolved: %v", err)
	}
	if meta.Owner != "" {
		t.Errorf("owner name = %q against an unreachable directory", meta.Owner)
	}
}

// A row owned by a client that is no longer registered still belongs in a
// listing: the caller's own documents do not vanish because the directory lost
// the publisher's name.
func TestList_KeepsARowWhoseOwnerIsNoLongerRegistered(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	ctx := context.Background()
	const retiredClient = "44444444-4444-4444-4444-444444444444"

	if _, _, err := svc.Put(ctx, retiredClient, "user-1", "flags", []byte(`{"beta":true}`), repository.VisibilityShared); err != nil {
		t.Fatalf("put: %v", err)
	}

	metas, _, err := svc.List(ctx, svcDocClientA, "user-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("listing returned %d documents, want 1", len(metas))
	}
	if metas[0].Owner != "" {
		t.Errorf("owner name = %q for an unregistered client", metas[0].Owner)
	}
	if metas[0].OwnerID != retiredClient {
		t.Errorf("owner id = %q, want %q", metas[0].OwnerID, retiredClient)
	}
	if metas[0].Mine {
		t.Error("another client's shared document reported as mine")
	}
}

// ---------------------------------------------------------------------------
// Canonicalisation size
// ---------------------------------------------------------------------------

// U+2028 and U+2029 are three bytes on the wire and six in the canonical
// encoding, which Go escapes whether or not HTML escaping is on. So a body that
// fits the cap as submitted can exceed it once canonicalised, and the cap has to
// be re-checked on the bytes actually stored.
func TestPut_RejectsADocumentThatOnlyExceedsTheCapOnceCanonicalised(t *testing.T) {
	cfg := defaultSvcDocConfig()
	cfg.MaxDocumentBytes = 64
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, cfg)

	raw := []byte("{\"a\":\"" + strings.Repeat("\u2028", 16) + "\"}")
	if len(raw) > cfg.MaxDocumentBytes {
		t.Fatalf("the fixture is already over the cap as submitted (%d bytes), so it proves nothing", len(raw))
	}

	_, _, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs", raw, repository.VisibilityPrivate)
	if !errors.Is(err, ErrSvcDocTooLarge) {
		t.Fatalf("a document that trebles its escapes past the cap was accepted: %v", err)
	}
	if len(repo.rows) != 0 {
		t.Fatalf("an oversize canonical document was stored: %d rows", len(repo.rows))
	}
}

// The canonical encoding is what the store holds and what a read hands back, so
// it has to be byte-identical to the submitted body wherever the encoder has a
// choice. U+2028 is the one place it does not: it escapes, and the stored size
// grows accordingly.
func TestPut_CanonicalSizeIsTheEscapedSizeNotTheSubmittedSize(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())

	raw := []byte("{\"a\":\"" + strings.Repeat("\u2028", 4) + "\"}")
	meta, _, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs", raw, repository.VisibilityPrivate)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if meta.SizeBytes != len(raw)+4*3 {
		t.Fatalf("reported size %d, want the escaped size %d", meta.SizeBytes, len(raw)+4*3)
	}
}

// ---------------------------------------------------------------------------
// Token stream walk
// ---------------------------------------------------------------------------

// The walk reads the token stream itself rather than leaning on a successful
// decode, so every place it pulls a token is a place a truncated or malformed
// body arrives. None of them may fall through to the decoder.
func TestValidateDocumentStructure_RejectsAMalformedTokenStream(t *testing.T) {
	for name, doc := range map[string]string{
		"trailing comma where a key belongs": `{"a":1,}`,
		"repeated comma in an object":        `{"a":1,,"b":2}`,
		"key with no value":                  `{"a":}`,
		"truncated after a key":              `{"a"`,
		"truncated inside an array":          `{"a":[1,2`,
		"truncated inside a nested object":   `{"a":{"b":1`,
		"array closed by an object brace":    `{"a":[1}`,
		"object closed by an array bracket":  `{"a":{"b":1]`,
	} {
		if err := ValidateDocumentStructure([]byte(doc)); !errors.Is(err, ErrSvcDocInvalidDocument) {
			t.Errorf("%s accepted: %q (%v)", name, doc, err)
		}
	}
}

// The handler sizes its own body reader from this number, so a value that did
// not match the one the service validates against would either truncate a legal
// document or let an oversize one reach the validator.
func TestMaxDocumentBytes_ReportsTheConfiguredCap(t *testing.T) {
	cfg := defaultSvcDocConfig()
	cfg.MaxDocumentBytes = 4096
	if got := newSvcDocService(t, newFakeSvcDocRepo(), cfg).MaxDocumentBytes(); got != 4096 {
		t.Fatalf("MaxDocumentBytes = %d, want %d", got, cfg.MaxDocumentBytes)
	}
}

// The subject goes into an HMAC input and the key into a column with a CHECK
// constraint, so both are validated before any of the work a write does: a bad
// value must be a rejection, not a constraint violation surfacing as a 500.
func TestPut_ValidatesKeyAndSubjectBeforeStoringAnything(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	ctx := context.Background()

	if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "NOT A KEY", []byte(`{"a":1}`), repository.VisibilityPrivate); !errors.Is(err, ErrSvcDocInvalidKey) {
		t.Errorf("invalid key: err = %v, want ErrSvcDocInvalidKey", err)
	}
	if _, _, err := svc.Put(ctx, svcDocClientA, "not a subject", "prefs", []byte(`{"a":1}`), repository.VisibilityPrivate); !errors.Is(err, ErrSvcDocInvalidSubject) {
		t.Errorf("invalid subject: err = %v, want ErrSvcDocInvalidSubject", err)
	}
	if len(repo.rows) != 0 {
		t.Fatalf("a rejected write reached the store: %d rows", len(repo.rows))
	}
}

// A write path has to refuse the same bodies the validator refuses. An empty
// body is not an empty object, and a body that fails the token walk must never
// reach the decoder that the walk exists to protect.
func TestPut_RejectsAnEmptyOrStructurallyInvalidBody(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())
	ctx := context.Background()

	for name, body := range map[string]string{
		"empty body":           ``,
		"whitespace only":      "  \n\t ",
		"array at the top":     `[1,2,3]`,
		"scalar at the top":    `"prefs"`,
		"duplicate key":        `{"a":1,"a":2}`,
		"trailing second body": `{"a":1}{"b":2}`,
	} {
		if _, _, err := svc.Put(ctx, svcDocClientA, "user-1", "prefs", []byte(body), repository.VisibilityPrivate); !errors.Is(err, ErrSvcDocInvalidDocument) {
			t.Errorf("%s accepted: %q (%v)", name, body, err)
		}
	}
	if len(repo.rows) != 0 {
		t.Fatalf("a rejected body reached the store: %d rows", len(repo.rows))
	}
}
