package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// RefreshTokenRepo implements repository.RefreshTokenRepository.
type RefreshTokenRepo struct {
	db *DB
}

// NewRefreshTokenRepo creates a new PostgreSQL-backed refresh token repository.
func NewRefreshTokenRepo(db *DB) *RefreshTokenRepo {
	return &RefreshTokenRepo{db: db}
}

// refreshFamilyLockClass namespaces this store's per-user advisory locks so they
// cannot collide with an advisory lock any other store takes. It is the first
// argument to the two-int pg_advisory_xact_lock; the second is hashtext(user_id).
const refreshFamilyLockClass int32 = 0x52544b46 // "RTKF"

// insertRefreshRowSQL inserts one refresh-token row and carries the family's
// birth date and both anti-race guards. It is shared verbatim by Create and
// CreateWithinCap so the two insert paths cannot drift: see Create for what each
// clause defends.
const insertRefreshRowSQL = `
	INSERT INTO auth.refresh_tokens (id, user_id, client_id, token_hash, family_id, device_id, fingerprint_hash, expires_at, created_at, family_created_at)
	SELECT $1::uuid, $2::uuid, $3::uuid, $4::varchar, $5::uuid, $6::uuid, $7::varchar, $8::timestamptz, $9::timestamptz,
	       COALESCE((SELECT MIN(family_created_at) FROM auth.refresh_tokens WHERE family_id = $5), $9)
	WHERE COALESCE((SELECT bool_or(family.revoked)
	                FROM (SELECT revoked FROM auth.refresh_tokens WHERE family_id = $5 ORDER BY id FOR UPDATE) AS family), FALSE) = FALSE
	  AND EXISTS (SELECT 1 FROM auth.users WHERE id = $2 AND deleted = FALSE)`

// countActiveFamiliesSQL counts a user's distinct active token families. It is
// shared by CountActiveFamilies and CreateWithinCap so the soft pre-check and
// the atomic cap enforce the same definition of "active".
const countActiveFamiliesSQL = `
	SELECT COUNT(DISTINCT family_id) FROM auth.refresh_tokens
	WHERE user_id = $1 AND revoked = FALSE AND used = FALSE AND expires_at > NOW()`

// refreshTokenInsertArgs binds insertRefreshRowSQL's placeholders from a token.
func refreshTokenInsertArgs(token *model.RefreshToken) []any {
	return []any{
		token.ID, token.UserID, nullStr(token.ClientID), token.TokenHash,
		token.FamilyID, nullStr(token.DeviceID), nullStr(token.FingerprintHash),
		token.ExpiresAt, token.CreatedAt,
	}
}

// Create inserts a new refresh token into the auth.refresh_tokens table.
//
// SECURITY INVARIANT (absolute session lifetime, migration 013): family_created_at
// is the family's birth date and a rotation must never be able to move it. The
// column is therefore not taken from the caller — it is read back from the family
// inside the same statement, and only a family with no rows yet (a genuine new
// session) falls back to this token's own created_at. A caller cannot extend a
// session by lying about it, because it never supplies the value.
//
// SECURITY INVARIANT (reuse detection): the insert is conditional on the family
// carrying no revoked row, and returns repository.ErrFamilyRevoked instead of
// inserting one when it does. Reuse detection revokes the rows a family has at
// that instant, so a rotation that inserts its successor a moment later produced
// a token no revocation ever touched: the caller who lost the race got
// replay_detected, the caller who won kept a rotating session for the rest of the
// absolute session lifetime, and the operator read the audit log and believed the
// family had died.
//
// The guard locks the family's rows instead of reading them, because a snapshot
// read cannot see a revocation that is still in flight. Locking makes the insert
// wait for that revocation and then read the value it committed. Together with
// the lock RevokeFamily takes, the two statements can no longer be invisible to
// each other in either direction. The aggregate sits outside the locked scan so
// that there is no filter on revoked for the planner to push down into it, which
// would turn the lock back into a snapshot read.
//
// The ORDER BY is the lock order described on lockThenWrite, and it is not
// cosmetic here: this scan takes a family's rows one at a time, so it can hold
// one and wait for another, which is exactly what a cycle needs.
//
// SECURITY INVARIANT (erasure completeness): the revoked-row guard above is
// written against a mark, and erasure is the one revocation that removes the
// rows instead of marking them. A family DeleteAllForUser has emptied carries no
// revoked row, so the guard passes over an empty set and the rotation that was
// in flight puts a row straight back. The table lock erasure takes does not stop
// it; it only orders the two, and the insert runs second. That row is a
// fingerprint hash, a device reference and a user id outliving the erasure that
// reported them gone, and it is neither used nor revoked, so DeleteExpired never
// collects it either. The cascade stays one row short for good (Art. 17).
//
// The insert therefore also asks whether the account still exists. The cascade
// tombstones the user row before it touches this table, so the check closes the
// whole window rather than the width of one statement: from the instant erasure
// commits the tombstone, no rotation can write here again. A ban, a lock or a
// disable is deliberately not part of this condition. Those leave the rows in
// place, so the family stays revocable and the next refresh terminates it, which
// is the one-access-token-TTL exposure docs/security.md already accepts.
//
// It is a plain read, and that is what keeps it out of the lock order this file
// otherwise lives by. A SELECT with no locking clause takes nothing above ACCESS
// SHARE and is never blocked by a row a writer holds, so it adds no edge any
// cycle could close.
func (r *RefreshTokenRepo) Create(ctx context.Context, token *model.RefreshToken) error {
	tag, err := r.db.Pool.Exec(ctx, insertRefreshRowSQL, refreshTokenInsertArgs(token)...)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrFamilyRevoked
	}
	return nil
}

// CreateWithinCap inserts the first token of a new family only while the user
// holds fewer than maxFamilies active families.
//
// SECURITY INVARIANT (concurrent-session cap, ASVS V2.3.4): the cap is a
// limited-quantity resource, and counting it and then inserting under it is one
// unit of work only because this transaction and this advisory lock make it one.
// Without the lock the count and the insert are two statements a racing login
// can interleave: each counts the same pre-insert total, each sees a free slot,
// and both insert, so a cap of N admits N+k for k simultaneous logins. The
// pg_advisory_xact_lock serializes every capped insert for one user, so the
// count each login reads already includes every login that committed before it.
//
// The lock is taken before the count for the same reason WithSubjectWriteLock
// takes it before its count: a lock acquired after the number it protects has
// been read is a lock around nothing. The count is a statement of its own after
// the lock so that, under READ COMMITTED, it takes a fresh snapshot that
// contains the rows a just-released peer committed; folding it into the insert's
// snapshot would reintroduce the race the lock closes.
//
// A maxFamilies of zero or less means no cap is configured, so the lock and the
// count are skipped and the insert runs exactly as Create.
func (r *RefreshTokenRepo) CreateWithinCap(ctx context.Context, token *model.RefreshToken, maxFamilies int) error {
	if maxFamilies <= 0 {
		return r.Create(ctx, token)
	}

	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin session cap tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // rollback after commit is a no-op

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`,
		refreshFamilyLockClass, token.UserID); err != nil {
		return fmt.Errorf("lock user sessions: %w", err)
	}

	var active int
	if err := tx.QueryRow(ctx, countActiveFamiliesSQL, token.UserID).Scan(&active); err != nil {
		return fmt.Errorf("count active families: %w", err)
	}
	if active >= maxFamilies {
		return repository.ErrSessionLimitReached
	}

	tag, err := tx.Exec(ctx, insertRefreshRowSQL, refreshTokenInsertArgs(token)...)
	if err != nil {
		return fmt.Errorf("insert refresh token within cap: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrFamilyRevoked
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit session cap tx: %w", err)
	}
	return nil
}

// FamilyOrigin returns the instant the given rotation family was created, which
// is what the absolute session lifetime is measured from.
//
// A family with no rows yields the zero time and no error: the family is gone, so
// there is no session to date. Callers enforcing the bound must treat a zero time
// as "age unknown" and fail closed — see AuthService.Refresh.
func (r *RefreshTokenRepo) FamilyOrigin(ctx context.Context, familyID string) (time.Time, error) {
	var origin *time.Time
	err := r.db.Pool.QueryRow(ctx, `
		SELECT MIN(family_created_at) FROM auth.refresh_tokens WHERE family_id = $1`, familyID).Scan(&origin)
	if err != nil {
		return time.Time{}, fmt.Errorf("family origin: %w", err)
	}
	if origin == nil {
		return time.Time{}, nil
	}
	return *origin, nil
}

// GetByTokenHash retrieves a refresh token by its SHA-256 hash. Returns nil, nil if not found.
func (r *RefreshTokenRepo) GetByTokenHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	var t model.RefreshToken
	var clientID, deviceID, fpHash *string
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, COALESCE(client_id::text, ''), token_hash, family_id,
		       COALESCE(device_id::text, ''), COALESCE(fingerprint_hash, ''),
		       expires_at, used, revoked, created_at
		FROM auth.refresh_tokens WHERE token_hash = $1`, hash).Scan(
		&t.ID, &t.UserID, &clientID, &t.TokenHash, &t.FamilyID,
		&deviceID, &fpHash, &t.ExpiresAt, &t.Used, &t.Revoked, &t.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	t.ClientID = deref(clientID)
	t.DeviceID = deref(deviceID)
	t.FingerprintHash = deref(fpHash)
	return &t, nil
}

// MarkUsed atomically marks a token as used. Returns true if the token was
// previously unused and not revoked.
//
// The revoked half of the precondition is not redundant with the caller's own
// check. This statement is the instant a token is spent, and the caller read the
// row earlier: a revocation landing in between left the caller holding a snapshot
// that says the family is live. Consuming the row on that stale read is how a
// token in a family an operator has just burned still gets spent.
func (r *RefreshTokenRepo) MarkUsed(ctx context.Context, id string) (bool, error) {
	tag, err := r.db.Pool.Exec(ctx,
		`UPDATE auth.refresh_tokens SET used = TRUE WHERE id = $1 AND used = FALSE AND revoked = FALSE`, id)
	if err != nil {
		return false, fmt.Errorf("mark token used: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RevokeByID marks a single refresh token as revoked.
func (r *RefreshTokenRepo) RevokeByID(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.refresh_tokens SET revoked = TRUE WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

// lockThenWrite runs one revocation or deletion as a lock and then a write, in a
// transaction of its own. scope names the rows for the operator reading the
// error; op is the verb that failed.
//
// Each statement arrives as its own string and its own arguments rather than
// bundled into a struct, because the injection control in tests/compliance
// follows a query back to a literal through parameters and package constants and
// no further. SQL reaching Exec from a struct field is a query it cannot vouch
// for. The two argument lists stay separate because the two statements are not
// always parameterized alike: a table lock names no rows and binds nothing.
//
// SECURITY INVARIANT (revocation completeness): a revocation must also end the
// session a rotation is in the middle of issuing. Written as a single statement
// it cannot, whatever it is scoped to. The statement takes its snapshot when it
// starts, then blocks on the rows the rotation holds, and the successor the
// rotation inserts while it waits was never in that snapshot: the write reports
// success having revoked every row but that one. The caller is told the sessions
// are over, and one chain keeps rotating for the rest of the absolute session
// lifetime. Locking in a statement of its own makes the rotation finish first,
// and the write that follows is a new statement whose snapshot contains the
// successor.
//
// LOCK ORDER: every statement in this file that can hold one row lock while
// waiting for another takes rows in ascending id, which is a total order over
// the table because id is the primary key. A cycle needs some transaction to
// hold a row above the one it waits for, so there is none to close: a
// transaction waiting for row r holds only rows below r, and whoever holds r is
// itself waiting for something above r. The orders genuinely disagree without
// this, because a family-scoped scan reads in physical order and a user-scoped
// scan sorted by id does not, and the two paths then take each other down with
// 40P01 in the authentication path. That is a failed logout, or a failed refresh
// for a legitimate client. The lock statement is where the order has to be
// stated: by the time the write below runs, this transaction already holds every
// row it will touch, so the order that statement scans in cannot matter.
//
// The order binds statements that never say FOR UPDATE too. A DELETE locks each
// row it removes as the scan reaches it, so an unordered mass delete is a
// hold-and-wait exactly like an unordered lock, and it deadlocks against these
// the moment their orders differ.
//
// Two callers take the table instead, and they need no row order because they
// never hold a row lock while waiting: a relation lock is acquired before any
// row lock, so they wait for every writer holding nothing, and once they have
// the table no other writer holds a row of it. See RevokeAll and
// DeleteAllForUser for why each one is on that side of the line.
func (r *RefreshTokenRepo) lockThenWrite(ctx context.Context, scope, op, lockSQL string, lockArgs []any, writeSQL string, writeArgs []any) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%s %s: %w", op, scope, err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	if _, err := tx.Exec(ctx, lockSQL, lockArgs...); err != nil {
		return fmt.Errorf("lock %s: %w", scope, err)
	}
	if _, err := tx.Exec(ctx, writeSQL, writeArgs...); err != nil {
		return fmt.Errorf("%s %s: %w", op, scope, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%s %s: %w", op, scope, err)
	}
	return nil
}

// RevokeByDeviceID revokes all active refresh tokens associated with a device.
//
// The lock scan has no index to use: device_id is not indexed, so both statements
// read the table. That is the price of the pre-lock here, and it is paid on a
// path a user reaches by signing a device out by hand.
func (r *RefreshTokenRepo) RevokeByDeviceID(ctx context.Context, deviceID string) error {
	return r.lockThenWrite(ctx, "device tokens", "revoke",
		`SELECT id FROM auth.refresh_tokens WHERE device_id = $1 ORDER BY id FOR UPDATE`, []any{deviceID},
		`UPDATE auth.refresh_tokens SET revoked = TRUE WHERE device_id = $1 AND revoked = FALSE`, []any{deviceID})
}

// RevokeFamily revokes all tokens in a rotation family to prevent replay attacks.
//
// This is the reuse-detection response: the family is known to be compromised, so
// every token descended from the stolen one has to stop working, including the
// successor of a rotation that is running right now. See lockThenWrite.
func (r *RefreshTokenRepo) RevokeFamily(ctx context.Context, familyID string) error {
	return r.lockThenWrite(ctx, "family", "revoke",
		`SELECT id FROM auth.refresh_tokens WHERE family_id = $1 ORDER BY id FOR UPDATE`, []any{familyID},
		`UPDATE auth.refresh_tokens SET revoked = TRUE WHERE family_id = $1`, []any{familyID})
}

// RevokeAllForUser revokes all active refresh tokens for a user (e.g., on
// password change, or when the user logs out of every session).
//
// The lock is scoped to the user and the rotation path's is scoped to one
// family, so the two overlap on the families of the user logging out. They take
// their rows in the same order, which is what keeps that overlap from becoming a
// deadlock; see lockThenWrite.
func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	return r.lockThenWrite(ctx, "all user tokens", "revoke",
		`SELECT id FROM auth.refresh_tokens WHERE user_id = $1 ORDER BY id FOR UPDATE`, []any{userID},
		`UPDATE auth.refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`, []any{userID})
}

// DeleteAllForUser hard-deletes every refresh token row for a user.
//
// Revoking is enough to end a session, but it leaves the row — and its
// fingerprint hash and device reference — behind. On erasure the account is
// gone, so there is no replay to detect and nothing to keep the rows for.
//
// It locks first for both reasons at once. A rotation that was already in flight
// when the account was tombstoned inserts its successor after a bare DELETE has
// taken its snapshot, and that row is a fingerprint hash and a device reference
// surviving the erasure that reported it had removed them. And the DELETE takes
// row locks of its own, so it has to agree with the order everything else in
// this file uses; see lockThenWrite.
//
// It takes the table rather than the rows because of who runs it. Admin-initiated
// erasure runs as vault_admin, which holds SELECT and DELETE on this table and
// deliberately not UPDATE — an admin may destroy a session but not rewrite one.
// PostgreSQL requires UPDATE for SELECT ... FOR UPDATE, so the row lock the
// scoped revocations use is not available to that role at all, while a table
// lock above ACCESS SHARE asks only for UPDATE, DELETE or TRUNCATE. Erasure is a
// deliberate, rare operation, so paying for it by stopping token writes for the
// length of one delete is the cheap side of that trade.
func (r *RefreshTokenRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	return r.lockThenWrite(ctx, "all user tokens", "delete",
		`LOCK TABLE auth.refresh_tokens IN EXCLUSIVE MODE`, nil,
		`DELETE FROM auth.refresh_tokens WHERE user_id = $1`, []any{userID})
}

// RevokeAll revokes all active refresh tokens system-wide (nuclear option).
//
// This one takes the table rather than the rows. The scope is every row there
// is, so locking them one by one would set a lock bit on the whole table before
// updating the whole table, and the operator reaching for this has already
// decided that no refresh should succeed until it is done. EXCLUSIVE is the mode
// that says exactly that: it stops every writer and every FOR UPDATE reader, and
// still lets a plain SELECT through.
//
// It cannot be half a deadlock either, which is why it does not need the row
// order the scoped revocations use. A relation lock is taken when a statement
// starts executing, before any row lock, so every rotation in flight already
// holds its weaker table lock and this waits for all of them holding nothing.
// Once it has the table no other writer can even begin, so the update below
// never waits for a row.
func (r *RefreshTokenRepo) RevokeAll(ctx context.Context) error {
	return r.lockThenWrite(ctx, "all tokens", "revoke",
		`LOCK TABLE auth.refresh_tokens IN EXCLUSIVE MODE`, nil,
		`UPDATE auth.refresh_tokens SET revoked = TRUE WHERE revoked = FALSE`, nil)
}

// CountActiveFamilies returns the number of distinct active (non-revoked, non-expired) token families for a user.
func (r *RefreshTokenRepo) CountActiveFamilies(ctx context.Context, userID string) (int, error) {
	var count int
	err := r.db.Pool.QueryRow(ctx, countActiveFamiliesSQL, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active families: %w", err)
	}
	return count, nil
}

// Batch bounds for DeleteExpired, the same shape the postgres cache reaper uses.
//
// The statement used to have no LIMIT, so on a table that had been allowed to
// grow — nothing on the server path ran it; the only caller was the CLI — one
// tick took a single transaction over every expired row, locking each one as
// the scan reached it and holding all of them until commit. Batching keeps each
// transaction short so a login rotating its own token waits milliseconds rather
// than the length of the sweep.
const (
	refreshReapBatch      = 2000
	refreshReapMaxBatches = 20
)

// DeleteExpired removes expired tokens that have been used or revoked. Returns the count of deleted rows.
//
// The reaper collects rows that are already spent, so it has no revocation to
// miss and needs no second statement. It does need the lock order: it deletes
// many rows, and a delete locks each one as the scan reaches it. Left to read
// the table in physical order it disagreed with every scoped revocation here,
// and a routine cleanup tick could take a user's logout down with 40P01.
//
// SKIP LOCKED lets two replicas sweep at once without either waiting on the
// other; a row another sweeper is already deleting does not need deleting
// twice.
func (r *RefreshTokenRepo) DeleteExpired(ctx context.Context) (int64, error) {
	var total int64
	for i := 0; i < refreshReapMaxBatches; i++ {
		tag, err := r.db.Pool.Exec(ctx, `
			DELETE FROM auth.refresh_tokens WHERE id IN (
				SELECT id FROM auth.refresh_tokens
				WHERE expires_at < NOW() AND (used = TRUE OR revoked = TRUE)
				ORDER BY id FOR UPDATE SKIP LOCKED
				LIMIT $1)`, refreshReapBatch)
		if err != nil {
			return total, fmt.Errorf("delete expired tokens: %w", err)
		}
		n := tag.RowsAffected()
		total += n
		if n < refreshReapBatch {
			break
		}
	}
	return total, nil
}

// DeleteExpiredUnused removes rows that expired without ever being used or
// revoked.
//
// DeleteExpired cannot collect these: its predicate is "used OR revoked", so a
// family whose owner simply stopped using it left rows behind forever. They are
// as dead as the spent ones — an expired token authenticates nothing — and on
// an instance with churn they are the majority.
func (r *RefreshTokenRepo) DeleteExpiredUnused(ctx context.Context) (int64, error) {
	var total int64
	for i := 0; i < refreshReapMaxBatches; i++ {
		tag, err := r.db.Pool.Exec(ctx, `
			DELETE FROM auth.refresh_tokens WHERE id IN (
				SELECT id FROM auth.refresh_tokens
				WHERE expires_at < NOW() AND used = FALSE AND revoked = FALSE
				ORDER BY id FOR UPDATE SKIP LOCKED
				LIMIT $1)`, refreshReapBatch)
		if err != nil {
			return total, fmt.Errorf("delete expired unused tokens: %w", err)
		}
		n := tag.RowsAffected()
		total += n
		if n < refreshReapBatch {
			break
		}
	}
	return total, nil
}
