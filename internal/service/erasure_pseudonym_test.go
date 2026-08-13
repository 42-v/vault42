package service

import (
	"testing"

	"github.com/42-v/vault42/tests/mocks"
)

// The erasure cascade deletes the identity profile and the encrypted blobs by
// pseudonym, and it derives those pseudonyms itself instead of asking the service
// that wrote the rows. Each derivation therefore exists twice, in two files, tied
// together by nothing the compiler can see.
//
// A divergence is silent in the worst possible way, and it is the same failure
// mode erasure_svcdoc_test.go pins for the document store. The delete is keyed by
// pseudonym, a wrong pseudonym matches zero rows, DELETE ... WHERE reports no
// error for rows it never held, the cascade continues, the audit log records an
// erasure and DeleteAccount returns nil. Every signal says the account was erased
// while the profile and every blob the user uploaded are still in the database.
//
// The document store got this test because it was the store whose key the cascade
// derived on its own. It was not the only one.
func TestErasure_IdentityAndBlobPseudonymsMatchTheServicesThatWroteTheRows(t *testing.T) {
	svc := newErasureService(t, nil, newErasureMocks())
	identity := NewIdentityService(&mocks.MockIdentityRepo{}, testKey, testHMAC)
	blobs := NewBlobService(&mocks.MockBlobRepo{}, testKey, testHMAC, BlobConfig{})

	// Ids shaped the way real ones are, plus the awkward ones: erasure has to reach
	// a profile written under any id the user table accepted.
	for _, userID := range []string{
		"user-1",
		"11111111-2222-3333-4444-555555555555",
		"UPPER.case_id@example",
		"",
	} {
		if cascade, store := svc.identityPseudonym(userID), identity.Pseudonym(userID); cascade != store {
			t.Errorf("subject %q: the cascade deletes the identity profile under %q but IdentityService wrote it under %q; "+
				"erasure would match zero rows and still report success", userID, cascade, store)
		}
		if cascade, store := svc.blobPseudonym(userID), blobs.Pseudonym(userID); cascade != store {
			t.Errorf("subject %q: the cascade deletes blobs under %q but BlobService stored them under %q; "+
				"erasure would match zero rows and still report success", userID, cascade, store)
		}
	}
}
