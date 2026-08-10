package service

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/repository"
)

// Service documents are the one store in the cascade whose row key the erasure
// service derives on its own instead of asking the owning service for it.
// ErasureService.svcDocPseudonym and ServiceDocumentService.SubjectPseudonym are
// two independent copies of the same HMAC, and nothing in the type system ties
// them together.
//
// A divergence between them is silent in the worst possible way. The delete is
// keyed by subject hash, so a wrong hash matches zero rows; DeleteAllForSubject
// is idempotent by design and reports no error for a subject it never held, the
// cascade continues, the audit log records an erasure and DeleteAccount returns
// nil. Every observable signal says the account was erased while every document
// another service wrote about that user is still in the table, which is exactly
// what docs/PRIVACY.md §5.3 promises does not happen under Art. 17.

func newErasureSvcDocService(t *testing.T, repo *fakeSvcDocRepo) *ServiceDocumentService {
	t.Helper()
	// testHMAC is the same secret newErasureService hands the cascade, which is
	// the production arrangement: one VAULT_HMAC_SECRET, two derivations of it.
	return NewServiceDocumentService(repo, nil, bytes.Repeat([]byte{0x42}, 32), testHMAC, defaultSvcDocConfig(), nil)
}

// The derivations must agree byte for byte, on any subject the store accepts.
// This is the assertion that fails first if either side gains a separator, a
// domain tag or a different input ordering.
func TestErasure_ServiceDocumentPseudonymMatchesTheDocumentStore(t *testing.T) {
	docs := newErasureSvcDocService(t, newFakeSvcDocRepo())
	svc := newErasureService(t, nil, newErasureMocks())

	for _, userID := range []string{
		"user-1",
		"11111111-2222-3333-4444-555555555555",
		"UPPER.case_id@example",
		"",
	} {
		cascade := svc.svcDocPseudonym(userID)
		store := docs.SubjectPseudonym(userID)
		if cascade != store {
			t.Errorf("subject %q: the cascade deletes under %q but the store writes under %q; "+
				"erasure would match zero rows and still report success", userID, cascade, store)
		}
	}

	// The other three cascade pseudonyms share the same secret, so a missing or
	// reused domain tag would let one store's delete hit another's rows.
	const userID = "user-1"
	svcDoc := svc.svcDocPseudonym(userID)
	for name, other := range map[string]string{
		"identity": svc.identityPseudonym(userID),
		"blobs":    svc.blobPseudonym(userID),
		"recovery": svc.recoveryPseudonym(userID),
	} {
		if svcDoc == other {
			t.Errorf("the service-document pseudonym collides with the %s pseudonym for the same user", name)
		}
	}
}

// The end-to-end version of the same invariant: documents written through the
// document store must be gone after the cascade runs, without either side being
// told what the other hashed. If the two derivations ever drift apart this fails
// where the equality check above would have to be updated to keep passing.
func TestDeleteAccount_ErasesDocumentsOtherServicesWroteAboutTheUser(t *testing.T) {
	ctx := context.Background()
	repo := newFakeSvcDocRepo()
	docs := newErasureSvcDocService(t, repo)

	for _, d := range []struct {
		client     string
		subject    string
		key        string
		body       string
		visibility repository.ServiceDocumentVisibility
	}{
		{svcDocClientA, "user-1", "profile", `{"tier":"gold"}`, repository.VisibilityPrivate},
		{svcDocClientB, "user-1", "flags", `{"beta":true}`, repository.VisibilityShared},
		// Another user's record, to prove the delete is keyed rather than global.
		{svcDocClientA, "user-2", "profile", `{"tier":"silver"}`, repository.VisibilityPrivate},
		// The global sentinel belongs to the service, not to any user. Erasing an
		// account must not take a service's own configuration with it.
		{svcDocClientA, GlobalSubject, "settings", `{"region":"eu"}`, repository.VisibilityPrivate},
	} {
		if _, _, err := docs.Put(ctx, d.client, d.subject, d.key, []byte(d.body), d.visibility); err != nil {
			t.Fatalf("seed %s/%s/%s: %v", d.client, d.subject, d.key, err)
		}
	}

	m := newErasureMocks()
	svc := newErasureService(t, nil, m)
	svc.SetServiceDocs(repo)

	if err := svc.DeleteAccount(ctx, "user-1", "self", "user request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	erased, err := docs.ExportForSubject(ctx, "user-1")
	if err != nil {
		t.Fatalf("ExportForSubject after erasure: %v", err)
	}
	if len(erased) != 0 {
		keys := make([]string, 0, len(erased))
		for _, d := range erased {
			keys = append(keys, d.OwnerID+"/"+d.Key)
		}
		t.Errorf("DeleteAccount reported success but %d document(s) survived: %v; "+
			"the cascade and the store are not deriving the same subject pseudonym",
			len(erased), strings.Join(keys, ", "))
	}

	survivors, err := docs.ExportForSubject(ctx, "user-2")
	if err != nil {
		t.Fatalf("ExportForSubject for the untouched user: %v", err)
	}
	if len(survivors) != 1 {
		t.Errorf("erasing user-1 left %d documents for user-2, want 1", len(survivors))
	}

	global, _, err := docs.Get(ctx, svcDocClientA, GlobalSubject, "settings", "")
	if err != nil {
		t.Fatalf("the service's own global document was erased with the user account: %v", err)
	}
	if string(global) != `{"region":"eu"}` {
		t.Errorf("global document = %s, want it untouched", global)
	}
}

// The store is optional, so the cascade skips it when it is not wired. That skip
// must not be reachable when it IS wired: a failed document delete has to abort
// the erasure like every other step, or the account is reported erased with the
// documents still in place.
func TestDeleteAccount_FailsClosedWhenServiceDocumentsCannotBeErased(t *testing.T) {
	repo := newFakeSvcDocRepo()
	repo.failOn = "deleteAll"

	m := newErasureMocks()
	var reachedEnd bool
	m.tokens.DeleteAllForUserFn = func(context.Context, string) error {
		reachedEnd = true
		return nil
	}

	svc := newErasureService(t, nil, m)
	svc.SetServiceDocs(repo)

	err := svc.DeleteAccount(context.Background(), "user-1", "self", "user request")
	if err == nil {
		t.Fatal("the document store failed, but DeleteAccount reported the account erased")
	}
	if !strings.Contains(err.Error(), "delete service documents") {
		t.Errorf("error %q does not name the step that failed", err)
	}
	if reachedEnd {
		t.Error("the cascade ran to completion despite a failed document delete")
	}
}

// A deployment with the document store disabled leaves svcDocs nil, and erasure
// still has to work: the nil check is the difference between an optional store
// and a panic on every account deletion.
func TestDeleteAccount_SucceedsWithoutAServiceDocumentStore(t *testing.T) {
	m := newErasureMocks()
	svc := newErasureService(t, nil, m)

	if err := svc.DeleteAccount(context.Background(), "user-1", "self", "user request"); err != nil {
		t.Fatalf("erasure must not depend on the optional document store: %v", err)
	}
}

// ExportForSubject is the read side of the same pseudonym. Erasure and export
// have to agree on it too, or a subject access request answers "we hold nothing
// about you" for documents an erasure would happily find and delete.
func TestExportForSubject_ReadsWhatTheErasureCascadeWouldDelete(t *testing.T) {
	ctx := context.Background()
	repo := newFakeSvcDocRepo()
	docs := newErasureSvcDocService(t, repo)

	if _, _, err := docs.Put(ctx, svcDocClientA, "user-1", "profile", []byte(`{"tier":"gold"}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("Put: %v", err)
	}

	svc := newErasureService(t, nil, newErasureMocks())
	stored, err := repo.ListAllForSubject(ctx, svc.svcDocPseudonym("user-1"))
	if err != nil {
		t.Fatalf("ListAllForSubject: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("the cascade's pseudonym found %d rows for a subject with one document", len(stored))
	}

	exported, err := docs.ExportForSubject(ctx, "user-1")
	if err != nil {
		t.Fatalf("ExportForSubject: %v", err)
	}
	if len(exported) != 1 {
		t.Fatalf("export returned %d documents, want 1", len(exported))
	}
	if string(exported[0].Document) != `{"tier":"gold"}` {
		t.Errorf("exported body = %s, want the stored document", exported[0].Document)
	}
}
