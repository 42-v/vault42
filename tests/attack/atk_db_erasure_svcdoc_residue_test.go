package attack

// Finding: admin-initiated GDPR erasure leaves objects.service_documents behind.
//
// ErasureService only reaches the service-document store when SetServiceDocs has
// been called; otherwise s.svcDocs is nil and the cascade skips it
// (internal/service/erasure.go, DeleteAccount, the `if s.svcDocs != nil` guard).
// The store's own doc comment on SetServiceDocs states the consequence plainly:
// "without this the store would silently retain data across an erasure that
// reported success."
//
// The self-service path wires it: internal/server/server.go:397 calls
// erasureSvc.SetServiceDocs(d.ServiceDocs). The admin gateway does NOT:
// cmd/admin-gateway/main.go:201 constructs NewErasureService and never calls
// SetServiceDocs, and admin-gateway/main.go never even constructs a
// ServiceDocumentRepo, so DELETE /admin/users/{id} (handler.DeleteUser ->
// ErasureService.DeleteAccount) runs the cascade with svcDocs nil.
//
// That the omission is a bug and not a design choice is settled by migration 014
// itself, which grants vault_admin SELECT, DELETE on objects.service_documents
// "for the admin-gateway erasure cascade" (014 lines 79-82). The privilege was
// provisioned for a cascade that the wiring never connected. The grant is dead
// and the documents survive.
//
// Impact: a data subject whose account is erased BY AN ADMIN (the ordinary way a
// controller actions an Art. 17 request) keeps every document other services
// filed about them, keyed by their subject pseudonym, while the endpoint returns
// success and writes an AccountErased audit record. Personal data under Art. 4(1)
// outlives an erasure that every observable signal says completed. docs/PRIVACY.md
// §5.3 promises this does not happen.
//
// This test reproduces the admin-gateway wiring against a real PostgreSQL: it
// builds the ErasureService with exactly the arguments cmd/admin-gateway/main.go
// passes (no SetServiceDocs), seeds a service document about the user, runs the
// same DeleteAccount the admin endpoint runs, and then reads the store back. It
// FAILS today because the document is still there.

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/repository/postgres"
	"github.com/42-v/vault42/internal/service"

	"github.com/jackc/pgx/v5/pgxpool"
)

// atkDBHMACSecret is the shared VAULT_HMAC_SECRET both the erasure cascade and the
// document store derive their subject pseudonyms from. One secret, two
// derivations, exactly as in production.
var atkDBHMACSecret = []byte("attack-suite-hmac-secret-0123456789abcdef")

func TestAdminErasureLeavesServiceDocumentsBehind(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()
	db := &postgres.DB{Pool: owner}

	// A service client to own the document (client_id is a FK into auth.clients).
	clientID := atkDBSeedClient(t, owner)
	svcDocs := postgres.NewServiceDocumentRepo(db)

	// subjectHash is what ErasureService.svcDocPseudonym derives:
	// HMAC(userID+":svcdoc"). If this ever drifts from the cascade the delete
	// would miss for a different reason, so it is written the same way the code
	// under test computes it rather than hard-coded.
	subjectHashFor := func(userID string) string {
		return vaultcrypto.HMACSign([]byte(userID+":svcdoc"), atkDBHMACSecret)
	}

	t.Run("admin-gateway wiring: document is erased", func(t *testing.T) {
		user := atkDBSeedUser(t, owner, "victim-admin-erase@test.com")
		seedServiceDoc(t, ctx, svcDocs, clientID, subjectHashFor(user.ID), "profile")

		// Reconstruct the ErasureService exactly as cmd/admin-gateway/main.go
		// does, INCLUDING the SetServiceDocs call it was missing. recoveryPub nil
		// disables escrow (irrelevant to this cascade); auditLog nil is tolerated
		// by DeleteAccount's `if s.auditLog != nil` guard.
		//
		// That this test constructs the wiring rather than reading it is the
		// limit of what it can prove. It shows the cascade reaches the store when
		// the setter is called; tests/spec/erasure_cascade_test.go is what shows
		// every production call site actually calls it, by parsing them.
		svc := atkDBNewErasureLikeAdminGateway(db)
		svc.SetServiceDocs(svcDocs)

		if err := svc.DeleteAccount(ctx, user.ID, "admin:"+atkDBRandomID(t), "admin_request"); err != nil {
			t.Fatalf("DeleteAccount (admin path): %v", err)
		}

		remaining := countDocsForSubject(t, ctx, owner, subjectHashFor(user.ID))
		if remaining != 0 {
			t.Errorf("admin erasure reported success but %d service document(s) survived for the erased user; "+
				"objects.service_documents retains personal data across an Art. 17 erasure", remaining)
		}
	})

	// Control: the self-service wiring (server.go calls SetServiceDocs) does erase
	// the document. This passes today. It proves the residue above is the missing
	// wiring and not a pseudonym mismatch, and it is the shape the fix must make
	// the admin path match.
	t.Run("self-service wiring: document is erased", func(t *testing.T) {
		user := atkDBSeedUser(t, owner, "victim-self-erase@test.com")
		seedServiceDoc(t, ctx, svcDocs, clientID, subjectHashFor(user.ID), "profile")

		svc := atkDBNewErasureLikeAdminGateway(db)
		svc.SetServiceDocs(svcDocs) // the one call the admin path omits

		if err := svc.DeleteAccount(ctx, user.ID, "self", "user_request"); err != nil {
			t.Fatalf("DeleteAccount (self path): %v", err)
		}

		remaining := countDocsForSubject(t, ctx, owner, subjectHashFor(user.ID))
		if remaining != 0 {
			t.Fatalf("SetServiceDocs was wired yet %d document(s) survived: the cascade and the "+
				"store are not deriving the same subject pseudonym", remaining)
		}
	})
}

// atkDBNewErasureLikeAdminGateway builds the ErasureService with the same
// positional arguments cmd/admin-gateway/main.go:201 passes. Kept in one place so
// the parallel to the real wiring is auditable.
func atkDBNewErasureLikeAdminGateway(db *postgres.DB) *service.ErasureService {
	var recoveryPub *rsa.PublicKey // nil: escrow disabled, not exercised here
	var recovery repository.AccountRecoveryRepository
	return service.NewErasureService(
		postgres.NewUserRepo(db),
		postgres.NewIdentityRepo(db),
		postgres.NewBlobRepo(db),
		postgres.NewDeviceRepo(db),
		postgres.NewSocialAccountRepo(db),
		postgres.NewPasswordHistoryRepo(db),
		postgres.NewRefreshTokenRepo(db),
		postgres.NewTOTPRepo(db),
		postgres.NewWebAuthnRepo(db),
		postgres.NewBackupCodeRepo(db),
		recovery,
		nil, // auditLog: DeleteAccount tolerates nil
		recoveryPub,
		atkDBHMACSecret,
	)
}

// atkDBSeedUser inserts a minimal user as the owner. Creating the row is not what
// is under test; the erasure of a document about it is.
func atkDBSeedUser(t *testing.T, owner *pgxpool.Pool, email string) *model.User {
	t.Helper()
	now := time.Now().UTC()
	u := &model.User{
		ID:            atkDBRandomID(t),
		Email:         email,
		EmailVerified: true,
		PasswordHash:  "$argon2id$placeholder",
		Locale:        "en",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := postgres.NewUserRepo(&postgres.DB{Pool: owner}).Create(context.Background(), u); err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	return u
}

// atkDBSeedClient inserts one active service client and returns its id, satisfying
// the objects.service_documents.client_id foreign key.
func atkDBSeedClient(t *testing.T, owner *pgxpool.Pool) string {
	t.Helper()
	id := atkDBRandomID(t)
	_, err := owner.Exec(context.Background(),
		`INSERT INTO auth.clients (id, name, secret_hash, role, scopes) VALUES ($1, $2, $3, $4, $5)`,
		id, "atk-svcdoc-owner-"+id[:8], "$argon2id$placeholder", "service", []string{"svcdoc:write"})
	if err != nil {
		t.Fatalf("seed client: %v", err)
	}
	return id
}

// seedServiceDoc writes one encrypted-shaped document about a subject. The bytes
// are opaque to this test; only the row's presence and its subject key matter.
func seedServiceDoc(t *testing.T, ctx context.Context, repo *postgres.ServiceDocumentRepo, clientID, subjectHash, key string) {
	t.Helper()
	created, err := repo.Upsert(ctx, &repository.ServiceDocument{
		ID:          atkDBRandomID(t),
		ClientID:    clientID,
		SubjectHash: subjectHash,
		DocKey:      key,
		Visibility:  repository.VisibilityPrivate,
		DataEnc:     []byte("ciphertext-about-the-user"),
		SizeBytes:   24,
		StoredBytes: 24,
		Version:     1,
	})
	if err != nil {
		t.Fatalf("seed service document: %v", err)
	}
	if !created {
		t.Fatalf("seed service document: expected an insert, got an update")
	}
}

// countDocsForSubject reads the store directly, so the assertion does not depend
// on any repository method the erasure path might also be skipping.
func countDocsForSubject(t *testing.T, ctx context.Context, owner *pgxpool.Pool, subjectHash string) int {
	t.Helper()
	var n int
	if err := owner.QueryRow(ctx,
		`SELECT COUNT(*) FROM objects.service_documents WHERE subject_hash = $1`, subjectHash).Scan(&n); err != nil {
		t.Fatalf("count service documents: %v", err)
	}
	return n
}
