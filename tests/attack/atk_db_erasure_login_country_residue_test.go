package attack

// Finding: GDPR erasure leaves auth.login_countries behind.
//
// migrations/028_login_countries.sql declares
//
//     user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE
//
// and its header states the consequence it believed followed: "user_id-owned and
// cascade-deleted, so account erasure (Art. 17) removes a user's countries
// automatically with no bespoke cascade step."
//
// vault42 never deletes the parent row. Erasure is a tombstone: auth.users keeps
// the row and auth.erase_user_identity (migration 015) scrubs the identity
// columns and sets deleted = TRUE. No DELETE ever reaches auth.users, so the
// ON DELETE CASCADE never fires, and nothing in Go deletes the country rows
// either — internal/repository/postgres/login_country.go only counts and
// inserts. internal/service/erasure.go already names this exact trap for the MFA
// tables ("These hang off user_id with ON DELETE CASCADE, but the user row is
// scrubbed with an UPDATE and never deleted — the cascade never fires"); the
// login-country table was added later and did not get the same treatment.
//
// Impact: the set of countries a user has signed in from is location-revealing
// personal data, introduced in this release, and it outlives an Art. 17 erasure
// that reports success and writes an AccountErased audit record. It also outlives
// the account in a table the erased user can no longer see or control.
//
// This test runs the real cascade against a real PostgreSQL, through the
// least-privilege vault_app role rather than the container owner, because the
// grant model is half the problem: 028 gives vault_app SELECT + INSERT only, so a
// naive `DELETE FROM auth.login_countries` on the self-service path would fail
// with 42501 even once someone remembered to write it.

import (
	"context"
	"crypto/rsa"
	"testing"

	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/repository/postgres"
	"github.com/42-v/vault42/internal/service"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestErasureLeavesLoginCountriesBehind(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	// The self-service erasure path (DELETE /user/account) reaches PostgreSQL as
	// vault_app. Running the cascade as the container owner would hide any missing
	// privilege, which is exactly the failure mode migration 009 was written for.
	appDB := &postgres.DB{Pool: atkDBRolePool(t, owner, "vault_app")}

	user := atkDBSeedUser(t, owner, "victim-login-country@test.com")

	// Record two countries the way a successful login does.
	countries := postgres.NewLoginCountryRepo(appDB)
	for _, cc := range []string{"DE", "FR"} {
		if _, _, err := countries.UpsertAndWasNew(ctx, user.ID, cc); err != nil {
			t.Fatalf("seed login country %s: %v", cc, err)
		}
	}
	if n := countLoginCountries(t, ctx, owner, user.ID); n != 2 {
		t.Fatalf("seeded %d login countries, want 2: the test would prove nothing", n)
	}

	svc := atkDBNewErasureLikeSelfService(appDB)
	if err := svc.DeleteAccount(ctx, user.ID, "self", "user_request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if remaining := countLoginCountries(t, ctx, owner, user.ID); remaining != 0 {
		t.Errorf("erasure reported success but %d login-country row(s) survived; "+
			"auth.login_countries retains location-revealing personal data across an "+
			"Art. 17 erasure, because the ON DELETE CASCADE in migration 028 can never "+
			"fire against a soft-deleted user row", remaining)
	}
}

// TestLoginCountryErasureLeavesOtherUsersAlone pins the blast radius. An erasure
// that cleared the whole table, or that keyed the delete on something coarser
// than the subject, would satisfy the assertion above while destroying every
// other account's new-location baseline — a security regression dressed as a
// privacy fix.
func TestLoginCountryErasureLeavesOtherUsersAlone(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	appDB := &postgres.DB{Pool: atkDBRolePool(t, owner, "vault_app")}
	countries := postgres.NewLoginCountryRepo(appDB)

	erased := atkDBSeedUser(t, owner, "erased-login-country@test.com")
	bystander := atkDBSeedUser(t, owner, "bystander-login-country@test.com")
	for _, u := range []string{erased.ID, bystander.ID} {
		if _, _, err := countries.UpsertAndWasNew(ctx, u, "DE"); err != nil {
			t.Fatalf("seed login country: %v", err)
		}
	}

	svc := atkDBNewErasureLikeSelfService(appDB)
	if err := svc.DeleteAccount(ctx, erased.ID, "self", "user_request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if n := countLoginCountries(t, ctx, owner, bystander.ID); n != 1 {
		t.Errorf("a bystander's login countries went from 1 to %d across someone else's "+
			"erasure; the delete is not scoped to the subject", n)
	}
}

// atkDBNewErasureLikeSelfService builds the ErasureService with the same
// positional arguments internal/server/server.go passes on the self-service path,
// including every setter that completes the cascade. Kept in one place so the
// parallel to the real wiring is auditable; tests/spec/erasure_cascade_test.go is
// what proves the production call sites still look like this.
func atkDBNewErasureLikeSelfService(db *postgres.DB) *service.ErasureService {
	var recoveryPub *rsa.PublicKey // nil: escrow disabled, not exercised here
	var recovery repository.AccountRecoveryRepository
	svc := service.NewErasureService(
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
	svc.SetServiceDocs(postgres.NewServiceDocumentRepo(db))
	return svc
}

// countLoginCountries reads the table directly as the owner, so the assertion
// does not depend on any repository method the erasure path might also be
// skipping.
func countLoginCountries(t *testing.T, ctx context.Context, owner *pgxpool.Pool, userID string) int {
	t.Helper()
	var n int
	if err := owner.QueryRow(ctx,
		`SELECT COUNT(*) FROM auth.login_countries WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatalf("count login countries: %v", err)
	}
	return n
}
