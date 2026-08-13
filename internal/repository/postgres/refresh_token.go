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
func (r *RefreshTokenRepo) Create(ctx context.Context, token *model.RefreshToken) error {
	tag, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.refresh_tokens (id, user_id, client_id, token_hash, family_id, device_id, fingerprint_hash, expires_at, created_at, family_created_at)
		SELECT $1::uuid, $2::uuid, $3::uuid, $4::varchar, $5::uuid, $6::uuid, $7::varchar, $8::timestamptz, $9::timestamptz,
		       COALESCE((SELECT MIN(family_created_at) FROM auth.refresh_tokens WHERE family_id = $5), $9)
		WHERE COALESCE((SELECT bool_or(family.revoked)
		                FROM (SELECT revoked FROM auth.refresh_tokens WHERE family_id = $5 FOR UPDATE) AS family), FALSE) = FALSE`,
		token.ID, token.UserID, nullStr(token.ClientID), token.TokenHash,
		token.FamilyID, nullStr(token.DeviceID), nullStr(token.FingerprintHash),
		token.ExpiresAt, token.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrFamilyRevoked
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

// RevokeByDeviceID revokes all active refresh tokens associated with a device.
func (r *RefreshTokenRepo) RevokeByDeviceID(ctx context.Context, deviceID string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.refresh_tokens SET revoked = TRUE WHERE device_id = $1 AND revoked = FALSE`, deviceID)
	if err != nil {
		return fmt.Errorf("revoke device tokens: %w", err)
	}
	return nil
}

// RevokeFamily revokes all tokens in a rotation family to prevent replay attacks.
//
// SECURITY INVARIANT (reuse detection): the family's rows are locked in a
// statement of their own before the update, so that a rotation holding those rows
// finishes first and the update below runs on a snapshot that already contains
// the successor it inserted. A single UPDATE takes its snapshot when it starts,
// which is before it waits for those locks, so it would revoke every row of the
// family except the one the rotation it just waited for had added. That surviving
// row is the whole stolen session: the replaying caller is told replay_detected
// and the family keeps rotating.
func (r *RefreshTokenRepo) RevokeFamily(ctx context.Context, familyID string) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("revoke family: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	if _, err := tx.Exec(ctx, `SELECT id FROM auth.refresh_tokens WHERE family_id = $1 FOR UPDATE`, familyID); err != nil {
		return fmt.Errorf("lock family: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.refresh_tokens SET revoked = TRUE WHERE family_id = $1`, familyID); err != nil {
		return fmt.Errorf("revoke family: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("revoke family: %w", err)
	}
	return nil
}

// RevokeAllForUser revokes all active refresh tokens for a user (e.g., on password change).
func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`, userID)
	if err != nil {
		return fmt.Errorf("revoke all user tokens: %w", err)
	}
	return nil
}

// DeleteAllForUser hard-deletes every refresh token row for a user.
//
// Revoking is enough to end a session, but it leaves the row — and its
// fingerprint hash and device reference — behind. On erasure the account is
// gone, so there is no replay to detect and nothing to keep the rows for.
func (r *RefreshTokenRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.refresh_tokens WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("delete all user tokens: %w", err)
	}
	return nil
}

// RevokeAll revokes all active refresh tokens system-wide (nuclear option).
func (r *RefreshTokenRepo) RevokeAll(ctx context.Context) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.refresh_tokens SET revoked = TRUE WHERE revoked = FALSE`)
	if err != nil {
		return fmt.Errorf("revoke all tokens: %w", err)
	}
	return nil
}

// CountActiveFamilies returns the number of distinct active (non-revoked, non-expired) token families for a user.
func (r *RefreshTokenRepo) CountActiveFamilies(ctx context.Context, userID string) (int, error) {
	var count int
	err := r.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT family_id) FROM auth.refresh_tokens
		WHERE user_id = $1 AND revoked = FALSE AND used = FALSE AND expires_at > NOW()`, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active families: %w", err)
	}
	return count, nil
}

// DeleteExpired removes expired tokens that have been used or revoked. Returns the count of deleted rows.
func (r *RefreshTokenRepo) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.refresh_tokens WHERE expires_at < NOW() AND (used = TRUE OR revoked = TRUE)`)
	if err != nil {
		return 0, fmt.Errorf("delete expired tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}
