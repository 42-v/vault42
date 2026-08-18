package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/repository"
)

// legacySvcDocHash is the pseudonym the store derived before subjects were
// canonicalised: HMAC over the caller's raw string. Tests use it to plant a row
// exactly as a pre-1.0.0 write would have left it.
func legacySvcDocHash(subject string) string {
	return vaultcrypto.HMACSign([]byte(subject+":svcdoc"), svcDocHMACSecret())
}

// The accepted subject charset admits mixed case and '@', so an email or a
// differently-cased identifier is a legal subject, and the pseudonym was an HMAC
// over the raw string with no folding anywhere. "Alice@example.com" and
// "alice@example.com" were therefore two disjoint namespaces for one human, each
// with its own quota and its own documents.
//
// It matters most on the erasure path. The cascade derives its pseudonym from
// the account's user id; a document a service filed under a different spelling of
// that same id matched no rows, and DeleteAllForSubject reports no error for a
// subject it never held, so the audit log recorded an erasure while the documents
// survived.
func TestSubjectPseudonymFoldsCase(t *testing.T) {
	svc := newSvcDocService(t, newFakeSvcDocRepo(), defaultSvcDocConfig())

	for _, pair := range [][2]string{
		{"Alice", "alice"},
		{"Alice@Example.com", "alice@example.com"},
		{"USER-1", "user-1"},
		{"11111111-AAAA-3333-4444-555555555555", "11111111-aaaa-3333-4444-555555555555"},
	} {
		if got, want := svc.SubjectPseudonym(pair[0]), svc.SubjectPseudonym(pair[1]); got != want {
			t.Errorf("SubjectPseudonym(%q) = %q, SubjectPseudonym(%q) = %q; one subject must have one pseudonym",
				pair[0], got, pair[1], want)
		}
	}

	// Folding must not collapse subjects that are genuinely different.
	if svc.SubjectPseudonym("alice") == svc.SubjectPseudonym("alice2") {
		t.Error("distinct subjects must keep distinct pseudonyms")
	}
}

// The cascade and the store derive the pseudonym independently, so the folding
// has to land on both sides or the fix creates the very divergence
// erasure_svcdoc_test.go exists to catch.
func TestErasurePseudonymFoldsCaseTheSameWay(t *testing.T) {
	docs := newErasureSvcDocService(t, newFakeSvcDocRepo())
	svc := newErasureService(t, nil, newErasureMocks())

	for _, userID := range []string{"UPPER.case_id@example", "Alice", "USER-1"} {
		if cascade, store := svc.svcDocPseudonym(userID), docs.SubjectPseudonym(strings.ToLower(userID)); cascade != store {
			t.Errorf("subject %q: the cascade deletes under %q, the store writes the folded subject under %q",
				userID, cascade, store)
		}
	}
}

// The end-to-end statement of the Article 17 defect: a service files a document
// about a user under a differently-cased spelling of that user's id, the account
// is erased, and the document has to be gone.
func TestErasureReachesADocumentFiledUnderAMixedCaseSubject(t *testing.T) {
	ctx := context.Background()
	repo := newFakeSvcDocRepo()
	docs := newErasureSvcDocService(t, repo)

	const userID = "11111111-aaaa-3333-4444-555555555555"
	mixed := strings.ToUpper(userID)

	if _, _, err := docs.Put(ctx, svcDocClientA, mixed, "profile",
		[]byte(`{"tier":"gold"}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("put under %q: %v", mixed, err)
	}
	if len(repo.rows) != 1 {
		t.Fatalf("setup stored %d rows, want 1", len(repo.rows))
	}

	if err := docs.DeleteAllForSubject(ctx, userID); err != nil {
		t.Fatalf("erase: %v", err)
	}
	if len(repo.rows) != 0 {
		t.Fatalf("erasure left %d document(s) filed under a differently-cased spelling of the same user id; "+
			"the cascade would have reported success", len(repo.rows))
	}
}

// Rows written before this change are keyed on the HMAC of the raw spelling, and
// no migration can re-key them: objects.service_documents stores subject_hash and
// never the subject, so the plaintext the old hash was taken over does not exist
// anywhere in the database. The read, list and delete paths therefore cover both
// forms, so a client that filed a document under "Alice" still finds it.
func TestLegacyNonCanonicalRowsStayReachable(t *testing.T) {
	ctx := context.Background()
	const subject = "Alice@Example.com"

	seed := func(t *testing.T) (*fakeSvcDocRepo, *DocumentService) {
		t.Helper()
		repo := newFakeSvcDocRepo()
		svc := newSvcDocService(t, repo, defaultSvcDocConfig())
		legacy := legacySvcDocHash(subject)
		body := []byte(`{"tier":"gold"}`)
		enc, err := vaultcrypto.Encrypt(body, svcDocMasterKey(32), docAAD(svcDocClientA, legacy, "profile"))
		if err != nil {
			t.Fatalf("seed encrypt: %v", err)
		}
		repo.rows[svcDocKey{svcDocClientA, legacy, "profile"}] = &repository.ServiceDocument{
			ID: "legacy-row", ClientID: svcDocClientA, SubjectHash: legacy, DocKey: "profile",
			Visibility: repository.VisibilityPrivate, DataEnc: enc,
			SizeBytes: len(body), StoredBytes: len(enc), Version: 1,
		}
		return repo, svc
	}

	t.Run("get finds it", func(t *testing.T) {
		_, svc := seed(t)
		body, _, err := svc.Get(ctx, svcDocClientA, subject, "profile", "")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		var doc map[string]string
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if doc["tier"] != "gold" {
			t.Errorf("body = %s, want the seeded document", body)
		}
	})

	t.Run("list reports it and charges its bytes", func(t *testing.T) {
		_, svc := seed(t)
		metas, quota, err := svc.List(ctx, svcDocClientA, subject)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(metas) != 1 {
			t.Fatalf("list returned %d documents, want 1", len(metas))
		}
		if quota.UsedBytes == 0 {
			t.Error("a legacy row's bytes must count against the subject's quota, or the budget is understated")
		}
		if quota.UsedCount != 1 {
			t.Errorf("UsedCount = %d, want 1", quota.UsedCount)
		}
	})

	t.Run("delete removes it", func(t *testing.T) {
		repo, svc := seed(t)
		if err := svc.Delete(ctx, svcDocClientA, subject, "profile"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if len(repo.rows) != 0 {
			t.Fatalf("legacy row survived delete: %d rows left", len(repo.rows))
		}
	})

	t.Run("a write replaces it instead of shadowing it", func(t *testing.T) {
		repo, svc := seed(t)
		if _, _, err := svc.Put(ctx, svcDocClientA, subject, "profile",
			[]byte(`{"tier":"silver"}`), repository.VisibilityPrivate); err != nil {
			t.Fatalf("put: %v", err)
		}
		if len(repo.rows) != 1 {
			t.Fatalf("store holds %d rows after replacing a legacy document, want 1; "+
				"a shadowed row is invisible, uncounted and never erased", len(repo.rows))
		}
		for k := range repo.rows {
			if k.subject != svc.subjectHash(subject) {
				t.Errorf("surviving row is keyed on %q, want the canonical pseudonym", k.subject)
			}
		}
	})
}

// A delete that matches neither form is still a 404 rather than a success.
func TestDeleteOfAnAbsentDocumentStillReportsNotFound(t *testing.T) {
	svc := newSvcDocService(t, newFakeSvcDocRepo(), defaultSvcDocConfig())
	err := svc.Delete(context.Background(), svcDocClientA, "Alice", "profile")
	if !errors.Is(err, ErrSvcDocNotFound) {
		t.Fatalf("delete of an absent document = %v, want ErrSvcDocNotFound", err)
	}
}

// A subject that is already canonical must not cost a second lookup under a
// "legacy" spelling that is the same string.
// A subject that is already canonical must not cost a second lookup under a
// "legacy" spelling that is the same string.
func TestCanonicalSubjectsAreLookedUpOnce(t *testing.T) {
	svc := newSvcDocService(t, newFakeSvcDocRepo(), defaultSvcDocConfig())
	if h := svc.legacySubjectHash("alice"); h != "" {
		t.Errorf("legacySubjectHash(%q) = %q, want empty: the subject is already canonical", "alice", h)
	}
	if h := svc.legacySubjectHash(GlobalSubject); h != "" {
		t.Errorf("the global sentinel has no legacy form, got %q", h)
	}
	if h := svc.legacySubjectHash("Alice"); h == "" {
		t.Error("a non-canonical subject must yield its pre-folding pseudonym")
	}
}

// The global sentinel is matched verbatim and must not be folded into some other
// namespace by the canonicalisation.
func TestGlobalSubjectSurvivesCanonicalisation(t *testing.T) {
	svc := newSvcDocService(t, newFakeSvcDocRepo(), defaultSvcDocConfig())
	global := svc.subjectHash(GlobalSubject)
	if global == svc.SubjectPseudonym(GlobalSubject) {
		t.Error("the global sentinel must keep its own domain-separated pseudonym")
	}
	if global != svc.subjectHash(GlobalSubject) {
		t.Error("the global pseudonym must be stable")
	}
}

// Case folding alone is the whole canonicalisation, and that is only sufficient
// because every subject the store accepts is ASCII. A Unicode subject would need
// NFC normalisation before folding, because two byte sequences can spell one
// character; this pins the premise so widening the charset fails here rather than
// silently reintroducing two namespaces for one subject.
func TestSubjectCharsetIsASCIIOnly(t *testing.T) {
	for r := rune(0x80); r < 0x300; r++ {
		if svcDocSubjectCharset.MatchString("a" + string(r)) {
			t.Fatalf("subject charset accepts non-ASCII %q; canonicalSubject folds case only and would leave "+
				"two spellings of one character in two namespaces", r)
		}
	}
}
