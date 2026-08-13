package attack

// Attack surface: the service-document store's per-owner document count quota
// and per-subject byte quota (internal/service/servicedoc.go).
//
// WHY these tests exist. checkQuota reads the current state with CountForOwner
// and SumBytesForSubject, decides, and then the caller writes with Upsert. The
// read and the write are separate statements with nothing between them: no
// transaction, no SELECT ... FOR UPDATE, no advisory lock, and no compensating
// delete if the decision turns out to have raced. The only database-level guard
// on this table (migration 014) is a UNIQUE index on
// (client_id, subject_hash, doc_key); it collapses two writes of the SAME key
// but does nothing for two writes of DIFFERENT keys, which is exactly what a
// count or byte quota bounds. So two writes that arrive together each observe
// the pre-write total, each pass, and each land, and the quota the docs promise
// (32 docs per subject, 1 MiB per subject) is advisory under concurrency.
//
// Both tests below assert the SECURE invariant (the stored total never exceeds
// the configured cap). They FAIL against the current code because the exploit
// works, and they turn green the day the check and the write are made atomic.
//
// The interleaving is forced deterministically with a barrier inside the
// repository's Upsert, so the finding does not depend on race timing and the
// tests are stable under -race. The barrier releases only once every concurrent
// writer has arrived at Upsert, which is to say once every writer has already
// finished its quota check against the pre-write state. That is precisely the
// window READ COMMITTED leaves open for the real Postgres repository.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

const (
	atkClientA = "aaaaaaaa-0000-4000-8000-000000000001"
	atkClientB = "bbbbbbbb-0000-4000-8000-000000000002"
)

// atkBarrier releases all of its arrivals at once, and only once target of them
// have arrived. A writer that never arrives (a fixed implementation that rejects
// the second write before it reaches Upsert) must not hang the test, so the wait
// has an upper bound after which a lone arrival proceeds on its own.
type atkBarrier struct {
	mu     sync.Mutex
	target int
	count  int
	ready  chan struct{}
}

func newAtkBarrier(target int) *atkBarrier {
	return &atkBarrier{target: target, ready: make(chan struct{})}
}

func (b *atkBarrier) wait() {
	b.mu.Lock()
	b.count++
	if b.count == b.target {
		close(b.ready)
	}
	b.mu.Unlock()
	select {
	case <-b.ready:
	case <-time.After(2 * time.Second):
		// A fixed store rejects the second writer before Upsert, so the target is
		// never reached; let the single arrival through rather than deadlock.
	}
}

type atkDocKey struct{ client, subject, key string }

// atkSvcDocRepo is a faithful in-memory stand-in for the Postgres service
// document repository: every method is individually atomic (map guarded by a
// mutex, like a single SQL statement), but nothing spans two methods, which is
// the property the real repository also lacks. gate, when set, blocks each
// Upsert until every concurrent writer has reached it.
type atkSvcDocRepo struct {
	mu   sync.Mutex
	rows map[atkDocKey]*repository.ServiceDocument
	gate *atkBarrier
}

var _ repository.ServiceDocumentRepository = (*atkSvcDocRepo)(nil)

func newAtkSvcDocRepo(gate *atkBarrier) *atkSvcDocRepo {
	return &atkSvcDocRepo{rows: map[atkDocKey]*repository.ServiceDocument{}, gate: gate}
}

func (m *atkSvcDocRepo) Get(_ context.Context, clientID, subjectHash, docKey string) (*repository.ServiceDocument, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.rows[atkDocKey{clientID, subjectHash, docKey}]
	if !ok {
		return nil, nil
	}
	cp := *d
	return &cp, nil
}

func (m *atkSvcDocRepo) ListSharedByKey(_ context.Context, subjectHash, docKey, exclude string) ([]*repository.ServiceDocument, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*repository.ServiceDocument
	for k, d := range m.rows {
		if k.subject == subjectHash && k.key == docKey && k.client != exclude && d.Visibility == repository.VisibilityShared {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *atkSvcDocRepo) Upsert(_ context.Context, doc *repository.ServiceDocument) (bool, error) {
	// The check-then-write window. Every concurrent writer has already run its
	// quota check by the time it reaches here; the barrier holds them so they all
	// commit together, reproducing the TOCTOU without depending on scheduler luck.
	if m.gate != nil {
		m.gate.wait()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := atkDocKey{doc.ClientID, doc.SubjectHash, doc.DocKey}
	_, existed := m.rows[k]
	cp := *doc
	m.rows[k] = &cp
	return !existed, nil
}

func (m *atkSvcDocRepo) Delete(_ context.Context, clientID, subjectHash, docKey string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := atkDocKey{clientID, subjectHash, docKey}
	if _, ok := m.rows[k]; !ok {
		return false, nil
	}
	delete(m.rows, k)
	return true, nil
}

func (m *atkSvcDocRepo) ListByOwner(_ context.Context, clientID, subjectHash string) ([]*repository.ServiceDocument, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*repository.ServiceDocument
	for k, d := range m.rows {
		if k.client == clientID && k.subject == subjectHash {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *atkSvcDocRepo) ListSharedForSubject(_ context.Context, subjectHash, exclude string) ([]*repository.ServiceDocument, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*repository.ServiceDocument
	for k, d := range m.rows {
		if k.subject == subjectHash && k.client != exclude && d.Visibility == repository.VisibilityShared {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *atkSvcDocRepo) ListAllForSubject(_ context.Context, subjectHash string) ([]*repository.ServiceDocument, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*repository.ServiceDocument
	for k, d := range m.rows {
		if k.subject == subjectHash {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *atkSvcDocRepo) CountForOwner(_ context.Context, clientID, subjectHash string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k := range m.rows {
		if k.client == clientID && k.subject == subjectHash {
			n++
		}
	}
	return n, nil
}

func (m *atkSvcDocRepo) SumBytesForSubject(_ context.Context, subjectHash string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for k, d := range m.rows {
		if k.subject == subjectHash {
			total += d.StoredBytes
		}
	}
	return total, nil
}

func (m *atkSvcDocRepo) DeleteAllForSubject(_ context.Context, subjectHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.rows {
		if k.subject == subjectHash {
			delete(m.rows, k)
		}
	}
	return nil
}

// rowCount returns how many documents are stored, across every owner and key.
// Every test here uses a single subject, so this is the subject's document total.
func (m *atkSvcDocRepo) rowCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

// storedBytes returns the total stored bytes across every row, which for a
// single-subject test is the subject's whole footprint.
func (m *atkSvcDocRepo) storedBytes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, d := range m.rows {
		total += d.StoredBytes
	}
	return total
}

// atkDocHandler builds a real DocumentService and handler over repo. The
// clients repository is nil, which the service tolerates and the write path never
// consults. A nil audit logger is a supported no-op.
func atkDocHandler(repo repository.ServiceDocumentRepository, mutate func(*service.DocumentConfig)) *handler.ServiceDocumentHandler {
	cfg := service.DocumentConfig{
		MaxDocumentBytes:     64 * 1024,
		MaxDocsPerSubject:    32,
		QuotaBytesPerSubject: 1 << 20,
		SharedEnabled:        true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	master := make([]byte, 32)
	hmacSecret := make([]byte, 32)
	for i := range master {
		master[i] = byte(i * 3)
		hmacSecret[i] = byte(i * 7)
	}
	svc := service.NewDocumentService(repo, nil, master, hmacSecret, cfg, nil)
	return handler.NewServiceDocumentHandler(svc, nil)
}

// atkDocPutReq builds a PUT request with the path values Go's ServeMux would set,
// carrying an authenticated client-credentials claim so the handler's requireClient
// gate is satisfied and the request reaches the quota path.
func atkDocPutReq(clientID, subject, key, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPut, "/service/documents/"+subject+"/"+key, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	req.SetPathValue("subject", subject)
	req.SetPathValue("key", key)
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: clientID},
		ClientID:         clientID,
		Scopes:           []string{"svcdoc:read", "svcdoc:write"},
		TokenType:        "Bearer",
	}
	return req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
}

// TestAtkSvcDocCountQuotaConcurrentBypass drives two concurrent writes of two
// distinct keys, by one client, about one subject, under a per-owner cap of one
// document. Sequentially the second is a 409; concurrently both land, because
// each reads a count of zero before either writes and the unique index does not
// fire for distinct keys.
//
// FAILS against current code: two documents are stored under a cap of one.
func TestAtkSvcDocCountQuotaConcurrentBypass(t *testing.T) {
	const subject = "user-toctou-count"
	const writers = 2

	repo := newAtkSvcDocRepo(newAtkBarrier(writers))
	h := atkDocHandler(repo, func(c *service.DocumentConfig) {
		c.MaxDocsPerSubject = 1 // one document per (client, subject)
	})

	keys := []string{"doc-a", "doc-b"}
	codes := make([]int, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.Put(rec, atkDocPutReq(atkClientA, subject, keys[i], `{"v":1}`))
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()

	if got := repo.rowCount(); got > 1 {
		t.Errorf("count quota bypassed: stored %d documents under a per-owner cap of 1 "+
			"(responses %v); checkQuota+Upsert is a non-atomic check-then-write in "+
			"internal/service/servicedoc.go", got, codes)
	}
}

// TestAtkSvcDocByteQuotaConcurrentBypass drives two concurrent writes by two
// DIFFERENT clients about one subject, under a per-subject byte budget sized to
// hold exactly one such document. The byte quota is the control that bounds a
// user's storage footprint across every service that writes about them, so a
// concurrent breach lets two tenants together exceed the very cap that is meant
// to span them.
//
// The document size is measured first with a throwaway write, so the budget can
// be set to admit one and refuse two without hardcoding the AES-GCM overhead.
//
// FAILS against current code: the subject's stored bytes exceed the budget.
func TestAtkSvcDocByteQuotaConcurrentBypass(t *testing.T) {
	const subject = "user-toctou-bytes"
	body := `{"pad":"` + strings.Repeat("x", 512) + `"}`

	// Measure one document's stored size under a generous budget.
	probe := newAtkSvcDocRepo(nil)
	ph := atkDocHandler(probe, nil)
	rec := httptest.NewRecorder()
	ph.Put(rec, atkDocPutReq(atkClientA, subject, "probe", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("probe write: status %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
	one := probe.storedBytes()
	if one <= 0 {
		t.Fatalf("probe recorded no stored bytes")
	}

	// A budget that fits one document but not two: one <= budget < 2*one.
	budget := one + one/2

	repo := newAtkSvcDocRepo(newAtkBarrier(2))
	h := atkDocHandler(repo, func(c *service.DocumentConfig) {
		c.QuotaBytesPerSubject = budget
	})

	type write struct {
		client, key string
	}
	writes := []write{{atkClientA, "from-a"}, {atkClientB, "from-b"}}
	codes := make([]int, len(writes))
	var wg sync.WaitGroup
	for i, wr := range writes {
		wg.Add(1)
		go func(i int, wr write) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.Put(rec, atkDocPutReq(wr.client, subject, wr.key, body))
			codes[i] = rec.Code
		}(i, wr)
	}
	wg.Wait()

	if got := repo.storedBytes(); got > budget {
		t.Errorf("byte quota bypassed: subject holds %d stored bytes under a per-subject "+
			"budget of %d (one document is %d bytes, responses %v); the per-subject byte "+
			"cap is enforced by a non-atomic read-then-write and two tenants breached it "+
			"together", got, budget, one, codes)
	}
}
