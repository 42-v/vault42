package attack

// The other half of the quota fix: what a caller SEES.
//
// atk_api_svcdoc_quota_test.go proves the store no longer overruns its caps
// under concurrency. That property is easy to obtain and ruin the contract in
// the process, because the fix moves the decision into a serialized section and
// a serialized section has failure modes of its own: a lock error, a rolled-back
// transaction, a wrapped sentinel. Any of those reaching the handler turns a
// 409 quota_exceeded into a 500 internal_error, and a service whose retry logic
// keys on 409 would then hammer a store that is simply full.
//
// So these tests pin the response, not the storage. A write refused because the
// subject is at its cap must produce exactly one status and exactly one error
// code, and it must produce them whether the caller arrived alone or lost a
// race. Two writers hitting the cap together and one writer hitting it later are
// the same event as far as the API is concerned, and a caller must not be able
// to tell them apart: a distinguishable refusal is a side channel that reports
// how many other services are writing about this user right now.
//
// The single-writer path is the one the fix must not have moved. Everything
// below the concurrency test is the sequential contract as it stood before, with
// the replacement case included, because the most tempting way to serialize a
// check-then-write is to make every write take a slot, and that would refuse a
// caller rewriting a document it already owns.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/42-v/vault42/internal/service"
)

// atkQuotaResponse is what a caller can observe about a refusal: the status line
// and the error code in the body. Nothing else about a rejected write is
// visible, so nothing else needs comparing.
type atkQuotaResponse struct {
	status int
	body   string
}

func atkPut(h interface {
	Put(http.ResponseWriter, *http.Request)
}, clientID, subject, key, body string,
) atkQuotaResponse {
	rec := httptest.NewRecorder()
	h.Put(rec, atkDocPutReq(clientID, subject, key, body))
	return atkQuotaResponse{status: rec.Code, body: strings.TrimSpace(rec.Body.String())}
}

// TestSvcDocQuotaSequentialRefusalIsUnchanged holds the single-writer contract
// still: over the count cap is a 409 quota_exceeded, over the byte cap is a 409
// quota_exceeded, and a replacement of a document the caller already owns is
// still allowed at a cap it would breach if it were a new document.
func TestSvcDocQuotaSequentialRefusalIsUnchanged(t *testing.T) {
	t.Run("count cap", func(t *testing.T) {
		repo := newAtkSvcDocRepo(nil)
		h := atkDocHandler(repo, func(c *service.DocumentConfig) {
			c.MaxDocsPerSubject = 1
		})

		if got := atkPut(h, atkClientA, "user-seq-count", "doc-a", `{"v":1}`); got.status != http.StatusCreated {
			t.Fatalf("first write: status %d, want 201 (%s)", got.status, got.body)
		}

		got := atkPut(h, atkClientA, "user-seq-count", "doc-b", `{"v":1}`)
		if got.status != http.StatusConflict {
			t.Errorf("over the count cap: status %d, want 409 (%s)", got.status, got.body)
		}
		if !strings.Contains(got.body, "quota_exceeded") {
			t.Errorf("over the count cap: body %s, want quota_exceeded", got.body)
		}

		// A rewrite of a document that already exists consumes no slot, so it must
		// still be admitted at a cap that is already full. Serializing the write
		// must not have turned "you own this row" into "you are at your limit".
		if got := atkPut(h, atkClientA, "user-seq-count", "doc-a", `{"v":2}`); got.status != http.StatusOK {
			t.Errorf("replacement at a full count cap: status %d, want 200 (%s)", got.status, got.body)
		}
		if n := repo.rowCount(); n != 1 {
			t.Errorf("a replacement stored %d rows, want 1", n)
		}
	})

	t.Run("byte cap", func(t *testing.T) {
		body := `{"pad":"` + strings.Repeat("x", 256) + `"}`

		probe := newAtkSvcDocRepo(nil)
		if got := atkPut(atkDocHandler(probe, nil), atkClientA, "user-seq-bytes", "probe", body); got.status != http.StatusCreated {
			t.Fatalf("probe write: status %d, want 201 (%s)", got.status, got.body)
		}
		one := probe.storedBytes()

		repo := newAtkSvcDocRepo(nil)
		h := atkDocHandler(repo, func(c *service.DocumentConfig) {
			c.QuotaBytesPerSubject = one + one/2
		})

		if got := atkPut(h, atkClientA, "user-seq-bytes", "doc-a", body); got.status != http.StatusCreated {
			t.Fatalf("first write: status %d, want 201 (%s)", got.status, got.body)
		}

		// A different client, because the byte budget spans owners. The refusal a
		// second tenant sees has to be the same refusal the first tenant would see.
		got := atkPut(h, atkClientB, "user-seq-bytes", "doc-b", body)
		if got.status != http.StatusConflict {
			t.Errorf("over the byte cap: status %d, want 409 (%s)", got.status, got.body)
		}
		if !strings.Contains(got.body, "quota_exceeded") {
			t.Errorf("over the byte cap: body %s, want quota_exceeded", got.body)
		}
	})
}

// TestSvcDocQuotaRefusalIsIdenticalUnderConcurrency drives the sequential
// refusal and the concurrent one through the same handler configuration and
// compares them byte for byte.
//
// The concurrent half is the same shape as the bypass test: two writers, two
// distinct keys, one cap, released together by the barrier. What it asserts is
// different. The bypass test asserts the store held the line; this one asserts
// the loser was told the same thing a late arrival is told, so a caller cannot
// learn from its own error whether someone else is writing about this subject.
func TestSvcDocQuotaRefusalIsIdenticalUnderConcurrency(t *testing.T) {
	cap1 := func(c *service.DocumentConfig) { c.MaxDocsPerSubject = 1 }

	sequential := func() atkQuotaResponse {
		h := atkDocHandler(newAtkSvcDocRepo(nil), cap1)
		if got := atkPut(h, atkClientA, "user-cmp-seq", "doc-a", `{"v":1}`); got.status != http.StatusCreated {
			t.Fatalf("first sequential write: status %d (%s)", got.status, got.body)
		}
		return atkPut(h, atkClientA, "user-cmp-seq", "doc-b", `{"v":1}`)
	}()

	repo := newAtkSvcDocRepo(newAtkBarrier(2))
	h := atkDocHandler(repo, cap1)
	keys := []string{"doc-a", "doc-b"}
	results := make([]atkQuotaResponse, len(keys))
	var wg sync.WaitGroup
	for i, k := range keys {
		wg.Add(1)
		go func(i int, k string) {
			defer wg.Done()
			results[i] = atkPut(h, atkClientA, "user-cmp-conc", k, `{"v":1}`)
		}(i, k)
	}
	wg.Wait()

	// Exactly one writer wins. Which one is timing, and the test must not care;
	// that there is exactly one winner and exactly one refusal is the invariant.
	accepted := make([]atkQuotaResponse, 0, len(results))
	refused := make([]atkQuotaResponse, 0, len(results))
	for _, r := range results {
		if r.status == http.StatusCreated {
			accepted = append(accepted, r)
			continue
		}
		refused = append(refused, r)
	}
	if len(accepted) != 1 || len(refused) != 1 {
		t.Fatalf("two concurrent writers at a cap of 1 produced %v, want one 201 and one refusal", results)
	}

	if refused[0] != sequential {
		t.Errorf("the writer that lost the race saw %+v, the writer that arrived late saw %+v; "+
			"a refusal that differs by arrival order tells a caller about traffic it cannot see",
			refused[0], sequential)
	}
	if sequential.status != http.StatusConflict || !strings.Contains(sequential.body, "quota_exceeded") {
		t.Errorf("quota refusal is %d %s, want 409 quota_exceeded", sequential.status, sequential.body)
	}
}
