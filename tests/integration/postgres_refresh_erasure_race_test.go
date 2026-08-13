package integration_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// Erasure is the one revocation that removes the rows instead of marking them,
// and the rotation guard is written against a mark. Create refuses to insert
// into a family that carries a revoked row; a family erasure has emptied carries
// nothing at all, so the guard passes over an empty set and the insert proceeds.
//
// The successor that lands is a fingerprint hash, a device reference and a
// user id belonging to an account that has just been erased, in a row nothing
// will ever collect: DeleteExpired only reaps rows that are used or revoked, and
// this one is neither. The erasure reported success and the cascade is
// permanently one row short of complete.

// eraseAccount runs the two steps of ErasureService.Erase that this table pair
// depends on, in the order the cascade runs them: the user row is tombstoned
// first (auth.erase_user_identity, migration 015), then every refresh-token row
// for that user is hard-deleted.
func eraseAccount(t *testing.T, pool *pgxpool.Pool, userID string) {
	t.Helper()
	db := &postgres.DB{Pool: pool}
	ctx := context.Background()

	if err := postgres.NewUserRepo(db).SoftDeleteScrub(ctx, userID, "deleted-"+userID+"@deleted.invalid"); err != nil {
		t.Fatalf("tombstone the user row: %v", err)
	}
	if err := postgres.NewRefreshTokenRepo(db).DeleteAllForUser(ctx, userID); err != nil {
		t.Fatalf("delete the user's refresh tokens: %v", err)
	}
}

// countTokenRows reports how many refresh-token rows a user still owns.
func countTokenRows(t *testing.T, pool *pgxpool.Pool, userID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM auth.refresh_tokens WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatalf("count refresh token rows: %v", err)
	}
	return n
}

// TestRotationCannotRefillAFamilyErasureEmptied is the invariant stated without
// the race: once the account is erased, no rotation may put a row back.
func TestRotationCannotRefillAFamilyErasureEmptied(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	f := newRaceFixture(t, pool, &hookedTokenRepo{})
	familyID := randomID()
	f.seedToken(t, familyID)

	eraseAccount(t, pool, f.userID)
	if n := countTokenRows(t, pool, f.userID); n != 0 {
		t.Fatalf("erasure left %d refresh-token row(s) behind before the rotation even ran", n)
	}

	successorID, _ := vaultcrypto.RandomUUID()
	successorRaw, _ := vaultcrypto.RandomHex(32)
	now := time.Now().UTC().Truncate(time.Microsecond)
	err := f.tokens.Create(ctx, &model.RefreshToken{
		ID: successorID, UserID: f.userID, TokenHash: vaultcrypto.SHA256Hex(successorRaw),
		FamilyID: familyID, DeviceID: randomID(), FingerprintHash: vaultcrypto.SHA256Hex("device-fingerprint"),
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	if err == nil {
		t.Error("a rotation inserted a refresh token for an erased account; the family guard only " +
			"looks for a revoked row, and erasure removes the rows rather than marking them, so " +
			"there was nothing left for it to see")
	}
	if n := countTokenRows(t, pool, f.userID); n != 0 {
		t.Errorf("%d refresh-token row(s) exist for an erased account; the row carries a fingerprint "+
			"hash, a device reference and the user id the erasure reported it had removed, and it is "+
			"neither used nor revoked, so DeleteExpired will never collect it", n)
	}
}

// TestRefreshRacingAnErasureLeavesNoRowBehind is the reachable path. The victim
// (or an attacker holding the account's refresh token) calls POST /auth/refresh
// while the erasure runs. Refresh reads the user row before the tombstone lands
// and inserts the successor after the cascade has deleted every row, so the
// window is the RSA signature and one round trip wide and can simply be spammed.
func TestRefreshRacingAnErasureLeavesNoRowBehind(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	var once sync.Once
	var f *raceFixture
	hooks := &hookedTokenRepo{
		// The whole erasure cascade lands between the account-state gate that
		// Refresh already applies and the insert that closes the rotation.
		beforeCreate: func(_ context.Context) {
			once.Do(func() { eraseAccount(t, pool, f.userID) })
		},
	}

	f = newRaceFixture(t, pool, hooks)
	familyID := randomID()
	stolen := f.seedToken(t, familyID)

	res, err := f.svc.Refresh(context.Background(), stolen, raceIP, raceUA, vaultcrypto.FingerprintInput{})
	if err == nil {
		t.Errorf("Refresh issued a rotated pair for an account erased mid-rotation (refresh token "+
			"returned: %v); the successor outlives the erasure and the client is handed a session "+
			"that Art. 17 says no longer exists", res.RefreshToken != "")
	}
	if n := countTokenRows(t, pool, f.userID); n != 0 {
		t.Errorf("%d refresh-token row(s) survived the erasure they raced; DeleteAllForUser takes the "+
			"table so the two statements cannot interleave, but the guard on the insert asks whether "+
			"the family carries a revoked row and an emptied family carries none", n)
	}
}
