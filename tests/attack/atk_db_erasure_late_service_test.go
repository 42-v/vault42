package attack

// Does erasure reach data written by a service that did not exist when the
// account was created?
//
// It is a fair thing to doubt. objects.service_documents is keyed by
// (client_id, subject_hash, doc_key) and the erasure cascade is handed only a
// user id, so if the delete were scoped per owning client — the way the quota
// check and the read path are — it would clear the documents of the services the
// erasure code happened to know about and leave the rest. The unique index is
// per owner, the shared-read index is per owner, and the natural way to write a
// per-user delete against that schema is to loop over clients.
//
// It is not written that way. ServiceDocumentRepo.DeleteAllForSubject deletes on
// subject_hash alone, across every owning client, and objects.blobs is likewise
// keyed by pseudonym with no client dimension at all. This test pins that: a
// client registered AFTER the user, writing a document AFTER the user's last
// login, still loses it. It is the property, not the implementation, that the
// GDPR position depends on — a service onboarded next year must not be able to
// accumulate documents about people erased last year.

import (
	"context"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestErasureReachesDocumentsFromLaterRegisteredServices(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	appDB := &postgres.DB{Pool: atkDBRolePool(t, owner, "vault_app")}
	svcDocs := postgres.NewServiceDocumentRepo(appDB)

	// Order matters and is the whole point: the account exists first.
	user := atkDBSeedUser(t, owner, "victim-late-service@test.com")
	subject := vaultcrypto.HMACSign([]byte(user.ID+":svcdoc"), atkDBHMACSecret)

	// Two services onboarded afterwards, each filing its own document about a
	// person who had already been using the product before either existed.
	early := atkDBSeedClient(t, owner)
	late := atkDBSeedClient(t, owner)
	seedServiceDoc(t, ctx, svcDocs, early, subject, "profile")
	seedServiceDoc(t, ctx, svcDocs, late, subject, "billing.status")

	// A document about somebody else, owned by the same late service. The delete
	// must be scoped to the subject, not to the client.
	bystander := atkDBSeedUser(t, owner, "bystander-late-service@test.com")
	bystanderSubject := vaultcrypto.HMACSign([]byte(bystander.ID+":svcdoc"), atkDBHMACSecret)
	seedServiceDoc(t, ctx, svcDocs, late, bystanderSubject, "billing.status")

	if n := countDocsForSubject(t, ctx, owner, subject); n != 2 {
		t.Fatalf("seeded %d documents, want 2: the test would prove nothing", n)
	}

	svc := atkDBNewErasureLikeSelfService(appDB)
	if err := svc.DeleteAccount(ctx, user.ID, "self", "user_request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if n := countDocsForSubject(t, ctx, owner, subject); n != 0 {
		t.Errorf("%d document(s) survived the erasure. The cascade is not reaching every "+
			"owning client, so a service registered after the account keeps its records "+
			"of a person who asked to be erased.", n)
	}
	if n := countDocsForSubject(t, ctx, owner, bystanderSubject); n != 1 {
		t.Errorf("a bystander's documents at the same service went from 1 to %d; the delete "+
			"is scoped to the owning client rather than to the subject", n)
	}
}
