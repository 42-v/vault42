package integration_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// Reuse detection revokes one family. Logout, device sign-out and the
// break-glass mass revoke are wider. All four answer the same question about
// which sessions must stop working right now, and all four are wrong in the same
// way if they are written as a single UPDATE.
//
// These tests drive the real repository against a real PostgreSQL and pin two
// properties that pull in opposite directions. A revocation has to see the
// successor of a rotation it overlapped, which needs a lock; and taking that
// lock must not deadlock against the family-scoped lock the rotation path
// already holds, which is why every locking statement in the file under test
// takes its rows in one order.

// newScopeToken builds the successor a rotation would issue into an existing
// family.
func newScopeToken(id, userID, familyID, raw string, now time.Time) *model.RefreshToken {
	return &model.RefreshToken{
		ID: id, UserID: userID, TokenHash: vaultcrypto.SHA256Hex(raw),
		FamilyID: familyID, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
}

// scopeSeed inserts one live token and returns its id. device may be empty.
func scopeSeed(t *testing.T, pool *pgxpool.Pool, userID, familyID, device, id string) string {
	t.Helper()
	if id == "" {
		id, _ = vaultcrypto.RandomUUID()
	}
	raw, _ := vaultcrypto.RandomHex(32)
	now := time.Now().UTC().Truncate(time.Microsecond)
	var dev *string
	if device != "" {
		dev = &device
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO auth.refresh_tokens (id, user_id, token_hash, family_id, device_id, expires_at, created_at, family_created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
		id, userID, vaultcrypto.SHA256Hex(raw), familyID, dev, now.Add(time.Hour), now); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	return id
}

// TestAScopedRevocationRevokesASuccessorInsertedWhileItWaited is the logout half
// of the reuse-detection race. A rotation holds the family's rows and has not
// yet inserted its successor; the revocation blocks on those rows, and the row
// the rotation adds while it waits is not in the snapshot a single statement
// took when it started. The caller is told every session is gone, the log says
// so, and one chain keeps rotating for the rest of the absolute session
// lifetime, which is the outcome "log out everywhere" exists to prevent.
func TestAScopedRevocationRevokesASuccessorInsertedWhileItWaited(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	f := newRaceFixture(t, pool, &hookedTokenRepo{})
	deviceID := randomID()

	cases := []struct {
		name   string
		device string
		// erased marks the paths that remove the row instead of revoking it.
		erased bool
		revoke func() error
	}{
		{
			name:   "logging out every session for a user",
			revoke: func() error { return f.tokens.RevokeAllForUser(ctx, f.userID) },
		},
		{
			name:   "signing out one device",
			device: deviceID,
			revoke: func() error { return f.tokens.RevokeByDeviceID(ctx, deviceID) },
		},
		{
			name:   "the break-glass system-wide revoke",
			revoke: func() error { return f.tokens.RevokeAll(ctx) },
		},
		{
			// Erasure is the same window with a worse remainder: the row that
			// survives carries a fingerprint hash and a device reference, and
			// the account it belongs to has been told they were deleted.
			name:   "erasing every token row for a user",
			erased: true,
			revoke: func() error { return f.tokens.DeleteAllForUser(ctx, f.userID) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			familyID := randomID()
			scopeSeed(t, pool, f.userID, familyID, tc.device, "")

			// A rotation in progress: it holds the family's rows and has not
			// yet inserted its successor.
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Rollback(ctx) // #nosec G104 -- committed below; this is the failure path
			if _, err := tx.Exec(ctx,
				`SELECT id FROM auth.refresh_tokens WHERE family_id = $1 FOR UPDATE`, familyID); err != nil {
				t.Fatalf("lock family in tx: %v", err)
			}

			done := make(chan error, 1)
			go func() { done <- tc.revoke() }()
			waitForBlockedBackends(t, pool, 1)

			successorID, _ := vaultcrypto.RandomUUID()
			successorRaw, _ := vaultcrypto.RandomHex(32)
			now := time.Now().UTC().Truncate(time.Microsecond)
			var dev *string
			if tc.device != "" {
				dev = &tc.device
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO auth.refresh_tokens (id, user_id, token_hash, family_id, device_id, expires_at, created_at, family_created_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
				successorID, f.userID, vaultcrypto.SHA256Hex(successorRaw), familyID, dev,
				now.Add(time.Hour), now); err != nil {
				t.Fatalf("insert successor in tx: %v", err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit rotation: %v", err)
			}

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("revoke: %v", err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("the revocation never returned after the rotation committed")
			}

			if tc.erased {
				var rows int
				if err := pool.QueryRow(ctx,
					`SELECT count(*) FROM auth.refresh_tokens WHERE id = $1`, successorID).Scan(&rows); err != nil {
					t.Fatalf("count successor rows: %v", err)
				}
				if rows != 0 {
					t.Error("erasure left the successor row behind: it waited for the rotation and then " +
						"deleted on a snapshot taken before the insert, so a fingerprint hash and a " +
						"device reference outlive the erasure that reported them gone")
				}
				return
			}

			var revoked bool
			if err := pool.QueryRow(ctx,
				`SELECT revoked FROM auth.refresh_tokens WHERE id = $1`, successorID).Scan(&revoked); err != nil {
				t.Fatalf("read successor: %v", err)
			}
			if !revoked {
				t.Error("the revocation left the successor alive: it waited for the rotation and then " +
					"updated on a snapshot taken before the insert, so the user was told every session " +
					"had ended while one token keeps rotating")
			}
		})
	}
}

// seedReversedPair inserts two rows of one family whose id order is the reverse
// of the order a plain scan returns them in, and returns them lowest id first.
// The two orders have to differ or the test proves nothing: with the ids and the
// physical layout agreeing, an unordered scan and an ordered one take the same
// locks in the same sequence by accident.
func seedReversedPair(t *testing.T, pool *pgxpool.Pool, userID, familyID string, reapable bool) (lowest, highest string) {
	t.Helper()
	a, _ := vaultcrypto.RandomUUID()
	b, _ := vaultcrypto.RandomUUID()
	if a < b {
		a, b = b, a
	}
	// a > b, and a is inserted first, so a plain scan reads a before b while an
	// ordered one reads b before a.
	scopeSeed(t, pool, userID, familyID, "", a)
	scopeSeed(t, pool, userID, familyID, "", b)
	if reapable {
		// What DeleteExpired collects: spent rows past their expiry.
		if _, err := pool.Exec(context.Background(), `
			UPDATE auth.refresh_tokens SET used = TRUE, expires_at = NOW() - INTERVAL '1 hour'
			WHERE id = ANY($1)`, []string{a, b}); err != nil {
			t.Fatalf("age the pair: %v", err)
		}
	}

	var first string
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM auth.refresh_tokens WHERE family_id = $1 LIMIT 1`, familyID).Scan(&first); err != nil {
		t.Fatalf("read scan order: %v", err)
	}
	if first != a {
		t.Fatalf("the plain scan returned %s first, want the higher id %s; the fixture no longer "+
			"produces two disagreeing orders and the deadlock it exists to catch cannot form", first, a)
	}
	return b, a
}

// TestAWideRevocationRacingTheRotationPathDoesNotDeadlock is the other half of
// the trade. A user-scoped lock takes rows the family-scoped lock also wants, so
// the two paths can hold what the other is waiting for. This drives the exact
// interleaving that closes the cycle: a third transaction holds the row the
// user-scoped path wants first, both paths queue behind it, and it lets go.
//
// The test passes because every locking statement in the repository takes rows
// in ascending id. Drop that ordering from either side and PostgreSQL kills one
// of them with 40P01 in the authentication path: a failed logout, or a failed
// refresh for a legitimate client.
func TestAWideRevocationRacingTheRotationPathDoesNotDeadlock(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	f := newRaceFixture(t, pool, &hookedTokenRepo{})

	cases := []struct {
		name string
		// reapable ages the pair into rows the expiry reaper collects.
		reapable bool
		// other is the second transaction: it takes the same rows from a
		// different direction while the user-scoped revocation is already
		// waiting.
		other func(familyID string) error
	}{
		{
			name:  "against the reuse-detection response",
			other: func(familyID string) error { return f.tokens.RevokeFamily(ctx, familyID) },
		},
		{
			name: "against a rotation issuing its successor",
			other: func(familyID string) error {
				id, _ := vaultcrypto.RandomUUID()
				raw, _ := vaultcrypto.RandomHex(32)
				now := time.Now().UTC().Truncate(time.Microsecond)
				return f.tokens.Create(ctx, newScopeToken(id, f.userID, familyID, raw, now))
			},
		},
		{
			// The reaper deletes rather than updates, so it locks without any
			// FOR UPDATE to read the order off. It is still a scan holding one
			// row while it waits for the next, which is all a cycle needs.
			name:     "against the expiry reaper",
			reapable: true,
			other:    func(string) error { _, err := f.tokens.DeleteExpired(ctx); return err },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			familyID := randomID()
			lowest, _ := seedReversedPair(t, pool, f.userID, familyID, tc.reapable)

			// The gate holds the row the user-scoped path locks first and the
			// family-scoped path would lock last, which is what lets both
			// queue up before either can finish.
			gate, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin gate: %v", err)
			}
			defer gate.Rollback(ctx) // #nosec G104 -- released below; this is the failure path
			if _, err := gate.Exec(ctx,
				`SELECT id FROM auth.refresh_tokens WHERE id = $1 FOR UPDATE`, lowest); err != nil {
				t.Fatalf("gate lock: %v", err)
			}

			var wg sync.WaitGroup
			var mu sync.Mutex
			outcomes := map[string]error{}
			record := func(who string, err error) {
				mu.Lock()
				outcomes[who] = err
				mu.Unlock()
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				record("the user-scoped revocation", f.tokens.RevokeAllForUser(ctx, f.userID))
			}()
			waitForBlockedBackends(t, pool, 1)

			wg.Add(1)
			go func() {
				defer wg.Done()
				record("the other writer", tc.other(familyID))
			}()
			waitForBlockedBackends(t, pool, 2)

			_ = gate.Rollback(ctx)
			wg.Wait()

			for who, err := range outcomes {
				switch {
				case err == nil:
				case strings.Contains(err.Error(), "40P01") || strings.Contains(err.Error(), "deadlock"):
					t.Errorf("%s was killed by the deadlock detector: %v; the two paths lock the same "+
						"rows in different orders, so logging out and detecting a replay can now take "+
						"each other down in the authentication path", who, err)
				case errors.Is(err, repository.ErrFamilyRevoked):
					// The revocation won the race and committed first, so the
					// rotation is correctly refused. That is the guard working.
				default:
					t.Errorf("%s failed: %v", who, err)
				}
			}
		})
	}
}
