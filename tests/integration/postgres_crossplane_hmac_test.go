package integration_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/config"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/repository/postgres"
	"github.com/42-v/vault42/internal/service"
)

// Cross-plane HMAC_SECRET agreement.
//
// cmd/vault and cmd/admin-gateway hold their own copy of HMAC_SECRET and never
// see each other's configuration. Three of the stores an erasure clears —
// identity.profiles, objects.blobs, objects.service_documents — are addressed
// by a subject pseudonym HMAC'd under that secret, so two planes holding
// different secrets erase by strings no row ever carried.
//
// The first test below runs that configuration against a real database and
// measures what it does, because the failure is entirely invisible from inside
// the cascade: DeleteAccount returns nil, the audit log records AccountErased,
// and the data is still there. The rest hold the guard that now stops such a
// deployment from starting.

const (
	planeSecretA = "plane-a-hmac-secret-32-bytes!!!!"
	planeSecretB = "plane-b-hmac-secret-32-bytes!!!!"

	crossPlaneClientID = "c1055b1a-0000-4000-8000-000000000001"
)

// crossPlaneFixture seeds one user with a row in each of the three
// pseudonym-keyed stores, derived under secret. It returns the user id.
func crossPlaneFixture(t *testing.T, pool *pgxpool.Pool, secret string) string {
	t.Helper()
	ctx := context.Background()
	db := &postgres.DB{Pool: pool}
	now := time.Now().UTC().Truncate(time.Microsecond)

	userID, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("user id: %v", err)
	}
	users := postgres.NewUserRepo(db)
	if err := users.Create(ctx, &model.User{
		ID: userID, Email: userID + "@example.com", EmailVerified: true,
		PasswordHash: "$argon2id$v=19$m=47104,t=1,p=1$dGVzdHNhbHQ$testhash",
		DisplayName:  "Cross Plane Subject", Locale: "en", Roles: []string{"user"},
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// The three derivations ErasureService reproduces. Written here exactly as
	// the identity, blob and document services write them.
	if err := postgres.NewIdentityRepo(db).Upsert(ctx, &model.IdentityProfile{
		PseudonymID: vaultcrypto.HMACSign([]byte(userID+":identity"), []byte(secret)),
		DataEnc:     []byte("aes-gcm-ciphertext"), Version: 1, UpdatedAt: now, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed identity profile: %v", err)
	}

	blobID, _ := vaultcrypto.RandomUUID()
	refHash, _ := vaultcrypto.RandomUUID()
	if err := postgres.NewBlobRepo(db).Create(ctx, &model.Blob{
		ID:          blobID,
		PseudonymID: vaultcrypto.HMACSign([]byte(userID+":objects"), []byte(secret)),
		RefHash:     refHash, LabelEnc: []byte("label-ct"), DataEnc: []byte("blob-ct"),
		SizeBytes: 7, StoredBytes: 16, Checksum: "sha256:" + refHash, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed blob: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.clients (id, name, secret_hash, role)
		VALUES ($1, 'cross-plane-service', 'x', 'service')
		ON CONFLICT (id) DO NOTHING`, crossPlaneClientID); err != nil {
		t.Fatalf("register client: %v", err)
	}
	docID, _ := vaultcrypto.RandomUUID()
	if _, err := postgres.NewServiceDocumentRepo(db).Upsert(ctx, &repository.ServiceDocument{
		ID: docID, ClientID: crossPlaneClientID,
		SubjectHash: vaultcrypto.HMACSign([]byte(userID+":svcdoc"), []byte(secret)),
		DocKey:      "prefs", Visibility: repository.VisibilityPrivate,
		DataEnc: []byte("doc-ct"), SizeBytes: 6, StoredBytes: 34, Version: 1,
	}); err != nil {
		t.Fatalf("seed service document: %v", err)
	}
	return userID
}

// crossPlaneErasure builds the cascade the admin gateway builds, under secret.
func crossPlaneErasure(pool *pgxpool.Pool, secret string) *service.ErasureService {
	db := &postgres.DB{Pool: pool}
	svc := service.NewErasureService(
		postgres.NewUserRepo(db), postgres.NewIdentityRepo(db), postgres.NewBlobRepo(db),
		postgres.NewDeviceRepo(db), postgres.NewSocialAccountRepo(db),
		postgres.NewPasswordHistoryRepo(db), postgres.NewRefreshTokenRepo(db),
		postgres.NewTOTPRepo(db), postgres.NewWebAuthnRepo(db), postgres.NewBackupCodeRepo(db),
		postgres.NewAccountRecoveryRepo(db), audit.NewLogger(postgres.NewAuditRepo(db), 0),
		nil, []byte(secret),
	)
	svc.SetServiceDocs(postgres.NewServiceDocumentRepo(db))
	svc.SetLoginCountries(postgres.NewLoginCountryRepo(db))
	return svc
}

func crossPlaneCount(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

// crossPlaneSubjectRows counts the rows an erasure has to reach in the three
// pseudonym-keyed stores, addressed the way the user plane wrote them.
func crossPlaneSubjectRows(t *testing.T, pool *pgxpool.Pool, userID, secret string) int {
	t.Helper()
	return crossPlaneCount(t, pool, `SELECT count(*) FROM identity.profiles WHERE pseudonym_id = $1`,
		vaultcrypto.HMACSign([]byte(userID+":identity"), []byte(secret))) +
		crossPlaneCount(t, pool, `SELECT count(*) FROM objects.blobs WHERE pseudonym_id = $1`,
			vaultcrypto.HMACSign([]byte(userID+":objects"), []byte(secret))) +
		crossPlaneCount(t, pool, `SELECT count(*) FROM objects.service_documents WHERE subject_hash = $1`,
			vaultcrypto.HMACSign([]byte(userID+":svcdoc"), []byte(secret)))
}

// TestDivergentPlaneSecretsEraseNothingAndReportSuccess measures the defect.
//
// It is the control and the demonstration in one run: the same fixture, the
// same cascade, the same assertions, once with the planes agreeing and once
// with them diverging. Agreement clears all three stores. Divergence clears
// none of them, returns nil, and tombstones the account anyway — so the subject
// is locked out of an account whose personal data is still on disk, and every
// signal available to the caller says the erasure succeeded.
//
// Nothing inside the cascade can detect this: DELETE ... WHERE pseudonym = $1
// matching zero rows is also what erasing an account that held no profile looks
// like. That is why the guard has to sit in configuration, before either plane
// serves anything.
func TestDivergentPlaneSecretsEraseNothingAndReportSuccess(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("planes agreeing: the cascade clears every subject-keyed store", func(t *testing.T) {
		userID := crossPlaneFixture(t, pool, planeSecretA)
		if before := crossPlaneSubjectRows(t, pool, userID, planeSecretA); before != 3 {
			t.Fatalf("fixture seeded %d subject rows, want 3", before)
		}

		if err := crossPlaneErasure(pool, planeSecretA).DeleteAccount(ctx, userID, "admin:test", "user_request"); err != nil {
			t.Fatalf("erasure failed: %v", err)
		}

		if after := crossPlaneSubjectRows(t, pool, userID, planeSecretA); after != 0 {
			t.Fatalf("%d subject rows survived an erasure by the same secret", after)
		}
	})

	t.Run("planes diverging: the cascade clears nothing and still reports success", func(t *testing.T) {
		userID := crossPlaneFixture(t, pool, planeSecretA)

		err := crossPlaneErasure(pool, planeSecretB).DeleteAccount(ctx, userID, "admin:test", "user_request")

		if err != nil {
			t.Fatalf("this test measures the silent case; the cascade reported: %v", err)
		}
		survived := crossPlaneSubjectRows(t, pool, userID, planeSecretA)
		if survived != 3 {
			t.Fatalf("%d of 3 subject rows survived; the divergence no longer produces the silent failure "+
				"this guard exists for, so the guard's justification needs re-reading", survived)
		}
		// And the account is gone as far as its owner is concerned.
		var deleted bool
		if err := pool.QueryRow(ctx, `SELECT deleted FROM auth.users WHERE id = $1`, userID).Scan(&deleted); err != nil {
			t.Fatalf("read user row: %v", err)
		}
		if !deleted {
			t.Error("the user was not tombstoned, so this is not the half-erased state the guard describes")
		}

		// The guard, against the same two secrets and a real auth.admin_config:
		// the deployment that produced the state above cannot start.
		store := postgres.NewAdminConfigRepo(&postgres.DB{Pool: pool})
		if err := config.VerifyHMACPlaneAgreement(ctx, store, []byte(planeSecretA)); err != nil {
			t.Fatalf("the user plane was refused while recording its own fingerprint: %v", err)
		}
		err = config.VerifyHMACPlaneAgreement(ctx, store, []byte(planeSecretB))
		if !errors.Is(err, config.ErrHMACPlaneMismatch) {
			t.Fatalf("the admin plane with the divergent secret was allowed to start: %v", err)
		}
	})
}

// TestTheFingerprintClaimIsAtomicAcrossPlanes covers the case a read-then-write
// would get wrong: two planes booting at the same moment.
//
// With a SELECT followed by a Set, both would find the key empty and the second
// write would overwrite the first, so two processes holding different secrets
// would each conclude they had recorded theirs and neither would report a
// disagreement. Exactly one of the callers below may see its own value.
func TestTheFingerprintClaimIsAtomicAcrossPlanes(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	store := postgres.NewAdminConfigRepo(&postgres.DB{Pool: pool})
	const key = "crossplane-atomic-claim"
	const racers = 8

	var wg sync.WaitGroup
	results := make([]string, racers)
	errs := make([]error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = store.ClaimIfAbsent(context.Background(), key, string(rune('a'+i)))
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for i, got := range results {
		if errs[i] != nil {
			t.Fatalf("claim %d: %v", i, errs[i])
		}
		if got == string(rune('a'+i)) {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("%d of %d concurrent claims believed they recorded their own value, want exactly 1", winners, racers)
	}
	var stored string
	if err := pool.QueryRow(context.Background(),
		`SELECT value FROM auth.admin_config WHERE key = $1`, key).Scan(&stored); err != nil {
		t.Fatalf("read back the claimed row: %v", err)
	}
	for _, got := range results {
		if got != stored {
			t.Fatalf("a claim was answered %q while the row holds %q", got, stored)
		}
	}
}

// A claim must not overwrite an incumbent, and must hand it back instead. That
// is the whole comparison: a claim that overwrote would make every plane agree
// with itself.
func TestAClaimNeverOverwritesTheIncumbent(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	ctx := context.Background()
	store := postgres.NewAdminConfigRepo(&postgres.DB{Pool: pool})
	const key = "crossplane-incumbent"

	first, err := store.ClaimIfAbsent(ctx, key, "first")
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if first != "first" {
		t.Fatalf("first claim returned %q, want its own value", first)
	}

	second, err := store.ClaimIfAbsent(ctx, key, "second")
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if second != "first" {
		t.Fatalf("second claim returned %q, want the incumbent %q", second, "first")
	}

	var stored string
	if err := pool.QueryRow(ctx, `SELECT value FROM auth.admin_config WHERE key = $1`, key).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored != "first" {
		t.Fatalf("the row now holds %q; the second claim overwrote the incumbent", stored)
	}
}
