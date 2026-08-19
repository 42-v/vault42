package integration_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
	"github.com/42-v/vault42/internal/service"
)

// Refresh-token reuse detection is the control that burns a stolen family the
// first time a token is presented twice. These tests drive the real
// AuthService.Refresh against a real PostgreSQL and pin the interleavings that
// let the winner of the race keep rotating while the audit log records
// replay_detected and the operator believes the family died.
//
// The repository methods are exercised through the service on purpose. The
// defect lives in the gap between GetByTokenHash, MarkUsed and Create, so a test
// that calls those methods in isolation cannot see it.

// raceRoleKey carries which of two concurrent Refresh calls a repository call
// belongs to. Both requests present the same stolen token, so nothing in the
// call itself can tell them apart.
type raceRoleKey struct{}

const (
	// roleWinner wins the MarkUsed CAS and goes on to rotate.
	roleWinner = "winner"
	// roleLoser loses it (or presents a used ancestor) and revokes the family.
	roleLoser = "loser"
)

func raceRole(ctx context.Context) string {
	role, _ := ctx.Value(raceRoleKey{}).(string)
	return role
}

func withRaceRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, raceRoleKey{}, role)
}

// gate is a one-shot barrier. Each side of the race opens the gates the other
// side waits on, which is what makes an interleaving that is otherwise a
// scheduling accident reproducible on every run.
type gate struct {
	ch   chan struct{}
	once sync.Once
}

func newGate() *gate { return &gate{ch: make(chan struct{})} }

func (g *gate) open() { g.once.Do(func() { close(g.ch) }) }

func (g *gate) await(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.ch:
	case <-time.After(30 * time.Second):
		// Reported rather than fatal: the waiting side runs in its own
		// goroutine, and letting it continue produces the real assertion
		// failure instead of a hang.
		t.Errorf("timed out waiting for %s; Refresh no longer makes the calls this test pins", what)
	}
}

// hookedTokenRepo wraps the production repository so a test can suspend a
// rotation at an exact point. Every method it does not override is inherited, so
// the service still talks to the real SQL, including the FamilyOrigin capability
// the absolute session lifetime asserts for.
type hookedTokenRepo struct {
	*postgres.RefreshTokenRepo

	afterGet          func(ctx context.Context)
	beforeMarkUsed    func(ctx context.Context)
	afterMarkUsed     func(ctx context.Context)
	afterRevokeFamily func(ctx context.Context)
	beforeCreate      func(ctx context.Context)
}

func fire(ctx context.Context, hook func(ctx context.Context)) {
	if hook != nil {
		hook(ctx)
	}
}

func (r *hookedTokenRepo) GetByTokenHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	tok, err := r.RefreshTokenRepo.GetByTokenHash(ctx, hash)
	fire(ctx, r.afterGet)
	return tok, err
}

func (r *hookedTokenRepo) MarkUsed(ctx context.Context, id string) (bool, error) {
	fire(ctx, r.beforeMarkUsed)
	ok, err := r.RefreshTokenRepo.MarkUsed(ctx, id)
	fire(ctx, r.afterMarkUsed)
	return ok, err
}

func (r *hookedTokenRepo) RevokeFamily(ctx context.Context, familyID string) error {
	err := r.RefreshTokenRepo.RevokeFamily(ctx, familyID)
	fire(ctx, r.afterRevokeFamily)
	return err
}

func (r *hookedTokenRepo) Create(ctx context.Context, token *model.RefreshToken) error {
	fire(ctx, r.beforeCreate)
	return r.RefreshTokenRepo.Create(ctx, token)
}

// raceFixture is one auth service wired to a real PostgreSQL, with the hooked
// repository in front of the real one.
type raceFixture struct {
	svc    *service.AuthService
	tokens *postgres.RefreshTokenRepo
	userID string
}

const (
	raceIP = "203.0.113.42"
	raceUA = "refresh-race-test-agent"
)

func newRaceFixture(t *testing.T, pool *pgxpool.Pool, hooks *hookedTokenRepo) *raceFixture {
	t.Helper()
	ctx := context.Background()

	db := &postgres.DB{Pool: pool}
	userRepo := postgres.NewUserRepo(db)
	tokenRepo := postgres.NewRefreshTokenRepo(db)
	hooks.RefreshTokenRepo = tokenRepo

	auditLog := audit.NewLogger(postgres.NewAuditRepo(db), 0)
	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := service.NewTokenService(key, kid, "vault-test", "vault-client",
		15*time.Minute, 7*24*time.Hour, 30*24*time.Hour)

	svc := service.NewAuthService(userRepo, hooks, nil, nil, tokenSvc, nil,
		auditLog, nil, mc, nil, "https://vault.test", "vault42", "", 15, false,
		[]byte("refresh-race-hmac-secret-32bytes"))

	user := makeUser("refresh-race-" + randomID() + "@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	return &raceFixture{svc: svc, tokens: tokenRepo, userID: user.ID}
}

// seedToken inserts one live refresh token and returns the opaque material a
// client would present. FingerprintHash is left empty so the fingerprint gate
// does not stand in for the rotation guard under test.
func (f *raceFixture) seedToken(t *testing.T, familyID string) string {
	t.Helper()
	raw, err := vaultcrypto.RandomHex(32)
	if err != nil {
		t.Fatalf("RandomHex: %v", err)
	}
	id, _ := vaultcrypto.RandomUUID()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := f.tokens.Create(context.Background(), &model.RefreshToken{
		ID: id, UserID: f.userID, TokenHash: vaultcrypto.SHA256Hex(raw),
		FamilyID: familyID, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	return raw
}

// assertFamilyIsBurned is the security property both race tests assert. Once a
// replay has been detected the family must have no usable row left: any survivor
// is a session that rotates for the rest of the absolute session lifetime while
// the audit log says the family was revoked.
func assertFamilyIsBurned(t *testing.T, pool *pgxpool.Pool, familyID string, winner *service.RefreshResult, svc *service.AuthService) {
	t.Helper()
	ctx := context.Background()

	var live int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM auth.refresh_tokens WHERE family_id = $1 AND revoked = FALSE`,
		familyID).Scan(&live); err != nil {
		t.Fatalf("count live rows: %v", err)
	}
	if live != 0 {
		t.Errorf("replay was detected and %d row(s) of family %s are still unrevoked; "+
			"the race winner keeps a rotating session while the operator reads replay_detected "+
			"in the audit log and believes the family died", live, familyID)
	}

	if winner == nil {
		return
	}
	if _, err := svc.Refresh(ctx, winner.RefreshToken, raceIP, raceUA, vaultcrypto.FingerprintInput{}); err == nil {
		t.Error("the successor issued during the detected replay rotated again; " +
			"reuse detection did not burn the stolen family, it only reported that it had")
	}
}

// assertReplayAudited checks the operator-visible half. Whatever happens to the
// race winner, the caller that lost must still be recorded as a replay.
func assertReplayAudited(t *testing.T, pool *pgxpool.Pool, familyID string) {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit.audit_log WHERE event_type = $1 AND metadata->>'family_id' = $2`,
		audit.TokenRevoke, familyID).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if n == 0 {
		t.Errorf("no %s audit entry for family %s; the replay was neither stopped nor reported",
			audit.TokenRevoke, familyID)
	}
}

// TestConcurrentRefreshOfOneTokenBurnsTheFamily pins the interleaving where two
// requests present the same unused token, the loser detects the replay, and the
// winner inserts its successor afterwards.
func TestConcurrentRefreshOfOneTokenBurnsTheFamily(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	winnerRead, loserRead := newGate(), newGate()
	winnerUsed, loserRevoked := newGate(), newGate()

	hooks := &hookedTokenRepo{
		// Both requests must read the row before either consumes it, which is
		// what makes them both pass the used and revoked checks.
		afterGet: func(ctx context.Context) {
			switch raceRole(ctx) {
			case roleWinner:
				winnerRead.open()
				loserRead.await(t, "the loser to read the same token")
			case roleLoser:
				loserRead.open()
				winnerRead.await(t, "the winner to read the same token")
			}
		},
		beforeMarkUsed: func(ctx context.Context) {
			if raceRole(ctx) == roleLoser {
				winnerUsed.await(t, "the winner to consume the token")
			}
		},
		afterMarkUsed: func(ctx context.Context) {
			if raceRole(ctx) == roleWinner {
				winnerUsed.open()
			}
		},
		afterRevokeFamily: func(ctx context.Context) {
			if raceRole(ctx) == roleLoser {
				loserRevoked.open()
			}
		},
		// The window: the loser's revocation only touches rows that exist, and
		// the winner's successor is not one of them yet.
		beforeCreate: func(ctx context.Context) {
			if raceRole(ctx) == roleWinner {
				loserRevoked.await(t, "the loser to revoke the family")
			}
		},
	}

	f := newRaceFixture(t, pool, hooks)
	familyID := randomID()
	stolen := f.seedToken(t, familyID)

	var (
		wg         sync.WaitGroup
		winnerRes  *service.RefreshResult
		winnerErr  error
		loserErr   error
		fpEmpty    = vaultcrypto.FingerprintInput{}
		background = context.Background()
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		winnerRes, winnerErr = f.svc.Refresh(withRaceRole(background, roleWinner), stolen, raceIP, raceUA, fpEmpty)
	}()
	go func() {
		defer wg.Done()
		_, loserErr = f.svc.Refresh(withRaceRole(background, roleLoser), stolen, raceIP, raceUA, fpEmpty)
	}()
	wg.Wait()

	if !errors.Is(loserErr, service.ErrReplayDetected) {
		t.Errorf("loser got %v, want ErrReplayDetected: the second use of one token is the replay "+
			"the whole rotation scheme exists to catch", loserErr)
	}
	t.Logf("winner outcome: res=%v err=%v", winnerRes != nil, winnerErr)

	assertReplayAudited(t, pool, familyID)
	assertFamilyIsBurned(t, pool, familyID, winnerRes, f.svc)
}

// TestReplayOfAUsedAncestorBurnsAConcurrentRotation pins the second window: a
// thief presents an already-used ancestor while the legitimate client is midway
// through its own rotation. The revocation lands between the victim's CAS and
// its insert, so the victim's successor is born outside the family the thief's
// replay just revoked.
func TestReplayOfAUsedAncestorBurnsAConcurrentRotation(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	victimUsed, thiefRevoked := newGate(), newGate()

	hooks := &hookedTokenRepo{
		beforeMarkUsed: func(ctx context.Context) {
			// The thief may only look once the victim is committed to rotating.
			if raceRole(ctx) == roleLoser {
				t.Error("the thief presented a used ancestor and should never reach MarkUsed")
			}
		},
		afterMarkUsed: func(ctx context.Context) {
			if raceRole(ctx) == roleWinner {
				victimUsed.open()
			}
		},
		afterGet: func(ctx context.Context) {
			if raceRole(ctx) == roleLoser {
				victimUsed.await(t, "the victim to consume its current token")
			}
		},
		afterRevokeFamily: func(ctx context.Context) {
			if raceRole(ctx) == roleLoser {
				thiefRevoked.open()
			}
		},
		beforeCreate: func(ctx context.Context) {
			if raceRole(ctx) == roleWinner {
				thiefRevoked.await(t, "the thief's replay to revoke the family")
			}
		},
	}

	f := newRaceFixture(t, pool, hooks)
	familyID := randomID()
	ancestor := f.seedToken(t, familyID)
	current := f.seedToken(t, familyID)

	// The ancestor is what a rotation leaves behind, and what a thief who copied
	// an earlier cookie still holds.
	stored, err := f.tokens.GetByTokenHash(context.Background(), vaultcrypto.SHA256Hex(ancestor))
	if err != nil || stored == nil {
		t.Fatalf("read seeded ancestor: %v", err)
	}
	if ok, err := f.tokens.MarkUsed(context.Background(), stored.ID); err != nil || !ok {
		t.Fatalf("mark ancestor used: ok=%v err=%v", ok, err)
	}

	var (
		wg         sync.WaitGroup
		victimRes  *service.RefreshResult
		victimErr  error
		thiefErr   error
		fpEmpty    = vaultcrypto.FingerprintInput{}
		background = context.Background()
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		victimRes, victimErr = f.svc.Refresh(withRaceRole(background, roleWinner), current, raceIP, raceUA, fpEmpty)
	}()
	go func() {
		defer wg.Done()
		_, thiefErr = f.svc.Refresh(withRaceRole(background, roleLoser), ancestor, raceIP, raceUA, fpEmpty)
	}()
	wg.Wait()

	if !errors.Is(thiefErr, service.ErrReplayDetected) {
		t.Errorf("thief got %v, want ErrReplayDetected", thiefErr)
	}
	t.Logf("victim outcome: res=%v err=%v", victimRes != nil, victimErr)

	assertReplayAudited(t, pool, familyID)
	assertFamilyIsBurned(t, pool, familyID, victimRes, f.svc)
}

// TestMarkUsedRefusesARevokedToken covers the first half of the window: a
// request that read the row before a revocation landed still consumes it.
// The compare-and-set is the moment a token is spent, so it has to carry the
// whole precondition, not just the half that was true when the row was read.
func TestMarkUsedRefusesARevokedToken(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	f := newRaceFixture(t, pool, &hookedTokenRepo{})
	familyID := randomID()
	raw := f.seedToken(t, familyID)

	stored, err := f.tokens.GetByTokenHash(ctx, vaultcrypto.SHA256Hex(raw))
	if err != nil || stored == nil {
		t.Fatalf("read seeded token: %v", err)
	}
	if err := f.tokens.RevokeFamily(ctx, familyID); err != nil {
		t.Fatalf("revoke family: %v", err)
	}

	ok, err := f.tokens.MarkUsed(ctx, stored.ID)
	if err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}
	if ok {
		t.Error("MarkUsed consumed a token whose family was already revoked; a request that " +
			"read the row a moment before the revocation goes on to rotate it, so the family " +
			"an operator just burned issues a fresh session anyway")
	}
}

// waitForBlockedBackends blocks until want backends are waiting on a lock
// against auth.refresh_tokens. Polling the server is what makes the overlap
// tests deterministic: a sleep would let the statement under test run to
// completion before the interleaving it is meant to prove ever forms.
func waitForBlockedBackends(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND query LIKE '%refresh_tokens%'`).Scan(&n); err != nil {
			t.Fatalf("poll pg_stat_activity: %v", err)
		}
		if n >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("fewer than %d backends ever blocked on auth.refresh_tokens; the statement under test "+
		"did not take the lock that serializes it against the other half of the race", want)
}

// TestRotationInsertRefusesAFamilyBeingRevoked proves the rotation side cannot
// read past a revocation that is in flight. Without this the two statements are
// mutually invisible: the revocation cannot see a successor it has not been told
// about, and the insert cannot see a revocation that has not committed, so both
// succeed and the family survives its own burning.
func TestRotationInsertRefusesAFamilyBeingRevoked(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	f := newRaceFixture(t, pool, &hookedTokenRepo{})
	familyID := randomID()
	f.seedToken(t, familyID)

	// A family revocation that has taken its row locks and not yet committed.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) // #nosec G104 -- committed below; this is the failure path
	if _, err := tx.Exec(ctx,
		`UPDATE auth.refresh_tokens SET revoked = TRUE WHERE family_id = $1`, familyID); err != nil {
		t.Fatalf("revoke in tx: %v", err)
	}

	successorID, _ := vaultcrypto.RandomUUID()
	successorRaw, _ := vaultcrypto.RandomHex(32)
	now := time.Now().UTC().Truncate(time.Microsecond)
	done := make(chan error, 1)
	go func() {
		done <- f.tokens.Create(ctx, &model.RefreshToken{
			ID: successorID, UserID: f.userID, TokenHash: vaultcrypto.SHA256Hex(successorRaw),
			FamilyID: familyID, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
	}()

	var createErr error
	returnedEarly := false
	select {
	case createErr = <-done:
		returnedEarly = true
	case <-time.After(time.Second):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit revocation: %v", err)
	}
	if !returnedEarly {
		select {
		case createErr = <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("the rotation insert never returned after the revocation committed")
		}
	}

	if returnedEarly {
		t.Error("the rotation insert completed while the family revocation was still uncommitted; " +
			"it read past the revocation, so the successor is born outside the family that was " +
			"just burned and the stolen session keeps rotating")
	}
	if createErr == nil {
		t.Error("the rotation inserted a successor into a revoked family; reuse detection " +
			"revokes the rows that exist, and this one did not exist yet")
	}

	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM auth.refresh_tokens WHERE id = $1`, successorID).Scan(&rows); err != nil {
		t.Fatalf("count successor rows: %v", err)
	}
	if rows != 0 {
		t.Errorf("the successor row exists (%d) after the family was revoked; a live row in a "+
			"burned family is exactly the session the operator believes they ended", rows)
	}
}

// TestFamilyRevocationSeesASuccessorInsertedWhileItWaited proves the other
// direction. A revocation that waits for a rotation in progress must revoke what
// that rotation inserted; a revocation running on a snapshot older than the
// insert reports success and leaves the successor alive.
func TestFamilyRevocationSeesASuccessorInsertedWhileItWaited(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	f := newRaceFixture(t, pool, &hookedTokenRepo{})
	familyID := randomID()
	f.seedToken(t, familyID)

	// A rotation in progress: it holds the family's rows and has not yet
	// inserted its successor.
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
	go func() { done <- f.tokens.RevokeFamily(ctx, familyID) }()
	waitForBlockedBackends(t, pool, 1)

	successorID, _ := vaultcrypto.RandomUUID()
	successorRaw, _ := vaultcrypto.RandomHex(32)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.refresh_tokens (id, user_id, token_hash, family_id, expires_at, created_at, family_created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6)`,
		successorID, f.userID, vaultcrypto.SHA256Hex(successorRaw), familyID,
		now.Add(time.Hour), now); err != nil {
		t.Fatalf("insert successor in tx: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit rotation: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RevokeFamily: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("RevokeFamily never returned after the rotation committed")
	}

	var revoked bool
	if err := pool.QueryRow(ctx,
		`SELECT revoked FROM auth.refresh_tokens WHERE id = $1`, successorID).Scan(&revoked); err != nil {
		t.Fatalf("read successor: %v", err)
	}
	if !revoked {
		t.Error("the family revocation left the successor alive: it waited for the rotation and " +
			"then updated on a snapshot taken before the insert, so the burned family still has " +
			"one usable token")
	}
}
