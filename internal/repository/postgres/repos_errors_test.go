package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
)

// Refresh tokens are single-use: MarkUsed is the atomic compare-and-set that decides
// whether this token has already been spent. Its bool is the whole replay defense.
//
// A DB failure that returned (true, nil) would mean a replayed refresh token is
// accepted — the exact attack rotation exists to stop — and it would do so silently.
// Likewise CountActiveFamilies returning (0, nil) would read as "this user has no
// sessions", which is how the session-count limit is enforced: fail it open and a user
// can mint unlimited concurrent sessions.
func TestRefreshTokenRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewRefreshTokenRepo(deadPool(t))
	ctx := context.Background()

	if err := repo.Create(ctx, &model.RefreshToken{ID: "rt-1", UserID: "u-1"}); err == nil {
		t.Error("Create reported success against an unreachable database")
	}
	if _, err := repo.GetByTokenHash(ctx, "hash"); err == nil {
		t.Error("GetByTokenHash returned no error against an unreachable database")
	}

	used, err := repo.MarkUsed(ctx, "rt-1")
	if err == nil {
		t.Error("MarkUsed reported success against an unreachable database")
	}
	if used {
		t.Error("MarkUsed returned true on failure — a replayed refresh token would be accepted")
	}

	if err := repo.RevokeByID(ctx, "rt-1"); err == nil {
		t.Error("RevokeByID reported success — a token believed revoked would still work")
	}
	if err := repo.RevokeByDeviceID(ctx, "dev-1"); err == nil {
		t.Error("RevokeByDeviceID reported success — signing out a lost device would do nothing")
	}
	if err := repo.RevokeFamily(ctx, "fam-1"); err == nil {
		t.Error("RevokeFamily reported success — the reuse-detection response would silently not happen")
	}
	if err := repo.RevokeAllForUser(ctx, "u-1"); err == nil {
		t.Error("RevokeAllForUser reported success against an unreachable database")
	}
	if err := repo.DeleteAllForUser(ctx, "u-1"); err == nil {
		t.Error("DeleteAllForUser reported success — erasure would leave every token behind")
	}
	if err := repo.RevokeAll(ctx); err == nil {
		t.Error("RevokeAll reported success — the break-glass mass revoke would do nothing")
	}

	n, err := repo.CountActiveFamilies(ctx, "u-1")
	if err == nil {
		t.Error("CountActiveFamilies returned no error against an unreachable database")
	}
	if n > 0 {
		t.Errorf("a failed CountActiveFamilies returned %d", n)
	}

	if _, err := repo.DeleteExpired(ctx); err == nil {
		t.Error("DeleteExpired reported success against an unreachable database")
	}
	// The second sweep, over rows that expired without ever being used or
	// revoked. On an instance with churn those are the majority of the table, and
	// the retention loop logs whatever count it is handed: a (0, nil) on failure
	// is a job that reports a clean run forever while the table only grows.
	if _, err := repo.DeleteExpiredUnused(ctx); err == nil {
		t.Error("DeleteExpiredUnused reported success against an unreachable database — " +
			"the retention sweep would log a clean run while every expired-unused row stayed")
	}
}

// Devices carry the trust decision that lets a login skip a second factor. A Trust that
// silently did nothing is the safe direction; a revoke or delete that silently did
// nothing is not — a user removing a device they no longer control would be told it was
// gone while it kept its trust.
func TestDeviceRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewDeviceRepo(deadPool(t))
	ctx := context.Background()

	if err := repo.Create(ctx, &model.Device{ID: "d-1", UserID: "u-1"}); err == nil {
		t.Error("Create reported success against an unreachable database")
	}
	if _, err := repo.GetByID(ctx, "d-1"); err == nil {
		t.Error("GetByID returned no error against an unreachable database")
	}
	if _, err := repo.GetByFingerprint(ctx, "u-1", "fp"); err == nil {
		t.Error("GetByFingerprint returned no error — an unknown device would look like a known one")
	}
	if _, err := repo.ListByUser(ctx, "u-1"); err == nil {
		t.Error("ListByUser returned no error — the user would be shown an empty device list")
	}
	if err := repo.UpdateLastSeen(ctx, "d-1", "203.0.113.1"); err == nil {
		t.Error("UpdateLastSeen reported success against an unreachable database")
	}
	if err := repo.UpdateFriendlyName(ctx, "d-1", "laptop"); err == nil {
		t.Error("UpdateFriendlyName reported success against an unreachable database")
	}
	if err := repo.Trust(ctx, "d-1", time.Now().Add(30*24*time.Hour)); err == nil {
		t.Error("Trust reported success against an unreachable database")
	}
	if err := repo.Delete(ctx, "d-1", "u-1"); err == nil {
		t.Error("Delete reported success — a device the user believes they removed would keep its trust")
	}
	if err := repo.DeleteAllForUser(ctx, "u-1"); err == nil {
		t.Error("DeleteAllForUser reported success — erasure would leave the devices behind")
	}
}

// Backup codes are the last way into an account when the second factor is lost, and
// each is single-use. MarkUsed returning true on a failure means a code that was never
// marked can be redeemed again.
func TestBackupCodeRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewBackupCodeRepo(deadPool(t))
	ctx := context.Background()

	if err := repo.CreateBatch(ctx, []*model.BackupCode{{ID: "bc-1", UserID: "u-1", CodeHash: "h"}}); err == nil {
		t.Error("CreateBatch reported success — the user would be shown codes that were never stored")
	}
	if _, err := repo.ListUnusedByUser(ctx, "u-1"); err == nil {
		t.Error("ListUnusedByUser returned no error against an unreachable database")
	}

	used, err := repo.MarkUsed(ctx, "bc-1")
	if err == nil {
		t.Error("MarkUsed reported success against an unreachable database")
	}
	if used {
		t.Error("MarkUsed returned true on failure — a single-use backup code would be redeemable again")
	}

	if err := repo.DeleteAllForUser(ctx, "u-1"); err == nil {
		t.Error("DeleteAllForUser reported success against an unreachable database")
	}
	if err := repo.PurgeAllForUser(ctx, "u-1"); err == nil {
		t.Error("PurgeAllForUser reported success — erasure would leave the code hashes behind")
	}
}

// App roles are the authorisation source. A List that returned an empty slice on a
// database failure would read as "this app grants no roles", and every role check that
// consults it would quietly deny — or, worse, a caller that treats an empty list as
// "unrestricted" would quietly allow.
func TestAppRoleRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewAppRoleRepo(deadPool(t))
	ctx := context.Background()

	if _, err := repo.List(ctx); err == nil {
		t.Error("List returned no error against an unreachable database")
	}
	if _, err := repo.ListNames(ctx); err == nil {
		t.Error("ListNames returned no error against an unreachable database")
	}
	if _, err := repo.Get(ctx, "admin"); err == nil {
		t.Error("Get returned no error against an unreachable database")
	}
	if err := repo.Create(ctx, &model.AppRole{Name: "admin"}); err == nil {
		t.Error("Create reported success against an unreachable database")
	}
	if err := repo.Delete(ctx, "admin"); err == nil {
		t.Error("Delete reported success against an unreachable database")
	}
}

// Admin sessions are the break-glass surface. A Revoke that reported success while
// doing nothing leaves an operator believing they have cut off a compromised admin
// session when it is still live — and RevokeAll is the mass response to exactly that.
func TestAdminSessionRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewAdminSessionRepo(deadPool(t))
	ctx := context.Background()

	if err := repo.Create(ctx, &model.AdminSession{ID: "as-1", AdminID: "a-1"}); err == nil {
		t.Error("Create reported success against an unreachable database")
	}
	if _, err := repo.GetByTokenHash(ctx, "hash"); err == nil {
		t.Error("GetByTokenHash returned no error against an unreachable database")
	}
	if _, err := repo.ListByAdmin(ctx, "a-1"); err == nil {
		t.Error("ListByAdmin returned no error against an unreachable database")
	}
	if _, err := repo.ListActive(ctx); err == nil {
		t.Error("ListActive returned no error — an empty list reads as 'no admin sessions are live'")
	}
	if err := repo.Revoke(ctx, "as-1"); err == nil {
		t.Error("Revoke reported success — a compromised admin session would remain live")
	}
	if err := repo.RevokeAllForAdmin(ctx, "a-1"); err == nil {
		t.Error("RevokeAllForAdmin reported success against an unreachable database")
	}
	if err := repo.RevokeAll(ctx); err == nil {
		t.Error("RevokeAll reported success — the mass revoke would silently do nothing")
	}
	if _, err := repo.DeleteExpired(ctx); err == nil {
		t.Error("DeleteExpired reported success against an unreachable database")
	}
}

// WebAuthn credentials are the strongest second factor on offer. UpdateSignCount is the
// clone-detection counter: if it silently failed to persist, the counter would never
// advance and a cloned authenticator would go undetected forever.
func TestWebAuthnRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewWebAuthnRepo(deadPool(t))
	ctx := context.Background()

	if err := repo.Create(ctx, &model.WebAuthnCredential{ID: "w-1", UserID: "u-1"}); err == nil {
		t.Error("Create reported success — the user would believe their security key is enrolled")
	}
	if _, err := repo.GetByCredentialID(ctx, []byte("cred")); err == nil {
		t.Error("GetByCredentialID returned no error against an unreachable database")
	}
	if _, err := repo.ListByUser(ctx, "u-1"); err == nil {
		t.Error("ListByUser returned no error — an empty list reads as 'no security keys enrolled'")
	}
	if err := repo.UpdateSignCount(ctx, "w-1", 42); err == nil {
		t.Error("UpdateSignCount reported success — clone detection depends on this counter persisting")
	}
	if err := repo.UpdateFlags(ctx, "w-1", 0x1d); err == nil {
		t.Error("UpdateFlags reported success -- a stale BackupEligible flag rejects every later login")
	}
	if err := repo.Delete(ctx, "w-1", "u-1"); err == nil {
		t.Error("Delete reported success against an unreachable database")
	}
	if err := repo.DeleteAllForUser(ctx, "u-1"); err == nil {
		t.Error("DeleteAllForUser reported success — erasure would leave the public keys behind")
	}
}

// The identity profile is the encrypted PII blob. UpsertCAS is the compare-and-set that
// serializes concurrent writes: its bool means "I won the race and my write landed". A
// database failure that returned (true, nil) would report a write that never happened,
// and the caller would stop retrying — which is precisely how a withdrawn marketing
// consent gets silently reverted.
func TestIdentityRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewIdentityRepo(deadPool(t))
	ctx := context.Background()
	profile := &model.IdentityProfile{PseudonymID: "p-1", DataEnc: []byte("enc")}

	won, err := repo.UpsertCAS(ctx, profile, time.Now())
	if err == nil {
		t.Error("UpsertCAS reported success against an unreachable database")
	}
	if won {
		t.Error("UpsertCAS returned true on failure — the caller would believe its write landed and stop retrying")
	}

	won, err = repo.UpsertCAS(ctx, profile, time.Time{})
	if err == nil {
		t.Error("UpsertCAS insert reported success against an unreachable database")
	}
	if won {
		t.Error("UpsertCAS insert returned true on failure")
	}

	if err := repo.Upsert(ctx, profile); err == nil {
		t.Error("Upsert reported success against an unreachable database")
	}
	if _, err := repo.GetByPseudonym(ctx, "p-1"); err == nil {
		t.Error("GetByPseudonym returned no error against an unreachable database")
	}
	if err := repo.Delete(ctx, "p-1"); err == nil {
		t.Error("Delete reported success — erasure would leave the identity profile behind")
	}
}

// OAuth clients decide which redirect URIs are legitimate. A Deactivate that reported
// success without writing leaves a client the operator believes is disabled still able
// to complete an authorisation flow.
func TestClientRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewClientRepo(deadPool(t))
	ctx := context.Background()

	if err := repo.Create(ctx, &model.Client{ID: "c-1", Name: "app"}); err == nil {
		t.Error("Create reported success against an unreachable database")
	}
	if _, err := repo.GetByID(ctx, "c-1"); err == nil {
		t.Error("GetByID returned no error against an unreachable database")
	}
	if _, err := repo.GetByName(ctx, "app"); err == nil {
		t.Error("GetByName returned no error against an unreachable database")
	}
	if _, err := repo.List(ctx); err == nil {
		t.Error("List returned no error against an unreachable database")
	}
	if err := repo.Update(ctx, &model.Client{ID: "c-1", Name: "app"}); err == nil {
		t.Error("Update reported success against an unreachable database")
	}
	if err := repo.Deactivate(ctx, "c-1"); err == nil {
		t.Error("Deactivate reported success — a client believed disabled could still complete an OAuth flow")
	}
}

// Social links are how an OAuth identity maps to an account. A GetByProviderAndID that
// returned (nil, nil) on a database failure would look exactly like "this Google account
// has never signed in here" — and the OAuth callback would go on to create a *second*
// account for a user who already has one, silently splitting their data in two.
func TestSocialAccountRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewSocialAccountRepo(deadPool(t))
	ctx := context.Background()

	if err := repo.Create(ctx, &model.SocialAccount{ID: "sa-1", UserID: "u-1", Provider: "google"}); err == nil {
		t.Error("Create reported success against an unreachable database")
	}
	if _, err := repo.GetByProviderAndID(ctx, "google", "provider-user-1"); err == nil {
		t.Error("GetByProviderAndID returned no error — an existing link would read as absent and a duplicate account would be created")
	}
	if _, err := repo.ListByUser(ctx, "u-1"); err == nil {
		t.Error("ListByUser returned no error — the user would be shown no linked accounts")
	}
	if err := repo.Delete(ctx, "sa-1", "u-1"); err == nil {
		t.Error("Delete reported success — a link the user believes they unlinked would still resolve")
	}
	if err := repo.DeleteAllForUser(ctx, "u-1"); err == nil {
		t.Error("DeleteAllForUser reported success — erasure would leave the social links behind")
	}
}

// Password history is what stops a user cycling straight back to the password they were
// just told to change. If GetRecentByUser returned an empty slice on a database failure,
// the reuse check would find nothing to compare against and wave the old password through.
func TestPasswordHistoryRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewPasswordHistoryRepo(deadPool(t))
	ctx := context.Background()

	if err := repo.Create(ctx, &model.PasswordHistory{ID: "ph-1", UserID: "u-1", PasswordHash: "$argon2id$h"}); err == nil {
		t.Error("Create reported success against an unreachable database")
	}
	if _, err := repo.GetRecentByUser(ctx, "u-1", 5); err == nil {
		t.Error("GetRecentByUser returned no error — the reuse check would pass a password the user was just told to stop using")
	}
	if err := repo.DeleteAllForUser(ctx, "u-1"); err == nil {
		t.Error("DeleteAllForUser reported success — erasure would leave the old password hashes behind")
	}
}
