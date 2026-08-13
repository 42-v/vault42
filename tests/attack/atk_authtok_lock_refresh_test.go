package attack

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// atkAuthTokDeps bundles the repository mocks a constructed AuthService writes
// through, so a test can drive the exact user row and stored refresh token the
// service will observe. It exists because the service-package harness
// (newMockAuthService) is an internal test symbol this external attack package
// cannot import, so the wiring is reproduced here against the public
// service.NewAuthService constructor and the shared tests/mocks fakes.
type atkAuthTokDeps struct {
	users  *mocks.MockUserRepo
	tokens *mocks.MockRefreshTokenRepo
	cache  *mocks.MockCache
}

// atkAuthTokService builds an AuthService with mock repositories and the same
// TTLs the service-package harness uses. MaxSessionLifetime is deliberately left
// unset (zero) so enforceSessionLifetime short-circuits and does not stand in for
// the account-state gate the tests below are probing: the point is what Refresh
// and CompleteMFALogin check about the user, not the absolute session clock.
func atkAuthTokService(t *testing.T) (*service.AuthService, *atkAuthTokDeps) {
	t.Helper()
	d := &atkAuthTokDeps{
		users:  &mocks.MockUserRepo{},
		tokens: &mocks.MockRefreshTokenRepo{},
		cache:  &mocks.MockCache{},
	}
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := service.NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLog := audit.NewLogger(&mocks.MockAuditRepo{}, 0)

	svc := service.NewAuthService(
		d.users, d.tokens, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLog, service.NewHIBPClient(),
		d.cache, &mocks.MockEmailSender{}, "https://vault.test", "TestVault",
		"", 15, false, nil,
	)
	return svc, d
}

// TestAtk_AdminLockDoesNotStopRefresh proves that an administrative account lock
// (POST /admin/users/{id}/lock, which sets users.locked_until) does NOT terminate
// an already-issued refresh-token family. The attacker keeps rotating and keeps
// receiving fresh access tokens after the lock lands.
//
// WHY THIS IS A FINDING. docs/security.md AR-5 states, verbatim:
//
//	"Operators who need immediate revocation have a mechanism. Revoking the
//	 user's sessions (POST /admin/sessions/revoke-all, or locking the account)
//	 invalidates the refresh family and caps exposure at the remaining
//	 access-token TTL."
//
// internal/rbac/rbac.go reinforces this: UsersLock is "the intended first
// response to a suspected account takeover." An operator who follows that guidance
// believes the takeover is contained. It is not. AuthService.Login checks
// user.LockedUntil (auth.go ~539), but AuthService.Refresh never does: it re-reads
// the user and revokes the family only for nil / Deleted / Banned / Disabled
// (auth.go ~806-820). LockedUntil is not in that set, and LockUser
// (internal/adminapi/handler.go ~309) only writes the column; it revokes no
// tokens. So the lock stops new password logins and nothing else.
//
// Exposure is therefore not "the remaining access-token TTL" (5-15 min) but the
// whole absolute session lifetime, which defaults to 720h (30 days) and is off
// entirely when VAULT_MAX_SESSION_LIFETIME=0. The one AR-5 alternative,
// revoke-all, is a global nuke of every user's sessions (RefreshTokenRepo.RevokeAll
// runs an unfiltered UPDATE), not the surgical per-user tool the wording implies.
//
// This assertion encodes the SECURE behavior the register promises. It FAILS
// against the current code, and that failure is the proof: Refresh hands back a
// new pair for a locked account.
func TestAtk_AdminLockDoesNotStopRefresh(t *testing.T) {
	svc, d := atkAuthTokService(t)

	const userID = "victim-1"
	// The account was locked one minute ago for another 24h: exactly the state
	// LockUser leaves behind for a suspected takeover.
	lockedUntil := time.Now().Add(24 * time.Hour)

	// A live, unused, unexpired refresh token the attacker holds. FingerprintHash
	// is empty so the fingerprint gate is skipped (Refresh only compares when the
	// stored hash is non-empty), isolating the account-state question.
	stored := &model.RefreshToken{
		ID:        "rt-1",
		UserID:    userID,
		FamilyID:  "fam-1",
		TokenHash: vaultcrypto.SHA256Hex("attacker-held-refresh"),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	d.tokens.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
		return stored, nil
	}

	familyRevoked := false
	d.tokens.RevokeFamilyFn = func(_ context.Context, _ string) error {
		familyRevoked = true
		return nil
	}

	// The current, authoritative user row: locked by an admin, otherwise healthy.
	d.users.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, Roles: []string{"user"}, LockedUntil: &lockedUntil}, nil
	}

	res, err := svc.Refresh(context.Background(), "attacker-held-refresh", "9.9.9.9", "UA",
		vaultcrypto.FingerprintInput{})

	if err == nil {
		t.Fatalf("SECURITY: Refresh issued a new token pair for an admin-locked account "+
			"(access token len=%d); admin lock does not invalidate the refresh family, "+
			"contradicting docs/security.md AR-5", len(res.AccessToken))
	}
	if !familyRevoked {
		t.Errorf("SECURITY: the locked account's refresh family was not revoked on the " +
			"refresh attempt; the session survives the lock")
	}
}

// TestAtk_LockedAccountRefreshChainSurvives shows the consequence over time: the
// attacker does not merely get one more token, but an unbroken rotation chain. A
// second refresh with the token minted by the first still succeeds, so the lock
// buys the operator nothing at all.
//
// It encodes the same secure expectation (a locked account cannot refresh) and
// FAILS today for the same reason as the test above; it is kept separate because
// it demonstrates persistence rather than the single-shot bypass.
func TestAtk_LockedAccountRefreshChainSurvives(t *testing.T) {
	svc, d := atkAuthTokService(t)

	const userID = "victim-2"
	lockedUntil := time.Now().Add(72 * time.Hour)
	d.users.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, Roles: []string{"user"}, LockedUntil: &lockedUntil}, nil
	}

	// The store hands back a fresh live row for whatever hash is presented,
	// modeling a family that keeps rotating. MarkUsed defaults to true (unused).
	d.tokens.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
		return &model.RefreshToken{
			ID:        "rt-chain",
			UserID:    userID,
			FamilyID:  "fam-2",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, nil
	}

	first, err := svc.Refresh(context.Background(), "held-1", "9.9.9.9", "UA", vaultcrypto.FingerprintInput{})
	if err != nil {
		// Secure behavior reached the finish line: nothing to prove here.
		return
	}
	// Rotate again with the token the locked account just minted.
	if _, err := svc.Refresh(context.Background(), first.RefreshToken, "9.9.9.9", "UA", vaultcrypto.FingerprintInput{}); err == nil {
		t.Fatalf("SECURITY: a locked account rotated its refresh family twice in a row; " +
			"admin lock provides no containment of an active session")
	}
}
