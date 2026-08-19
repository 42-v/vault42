package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
)

// AdminSessionRepo implements repository.AdminSessionRepository.
type AdminSessionRepo struct {
	db *DB
}

// NewAdminSessionRepo creates a new PostgreSQL-backed admin session repository.
func NewAdminSessionRepo(db *DB) *AdminSessionRepo {
	return &AdminSessionRepo{db: db}
}

// Create inserts a new admin session.
func (r *AdminSessionRepo) Create(ctx context.Context, session *model.AdminSession) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.admin_sessions (id, admin_id, token_hash, ip, user_agent, created_at, expires_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		session.ID, session.AdminID, session.TokenHash,
		session.IP, nullStr(session.UserAgent),
		session.CreatedAt, session.ExpiresAt, session.Revoked,
	)
	if err != nil {
		return fmt.Errorf("insert admin session: %w", err)
	}
	return nil
}

// GetByTokenHash retrieves a session by its SHA-256 token hash.
func (r *AdminSessionRepo) GetByTokenHash(ctx context.Context, hash string) (*model.AdminSession, error) {
	var s model.AdminSession
	var ua *string
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, admin_id, token_hash, ip, user_agent, created_at, expires_at, revoked
		FROM auth.admin_sessions WHERE token_hash = $1`, hash).Scan(
		&s.ID, &s.AdminID, &s.TokenHash, &s.IP, &ua,
		&s.CreatedAt, &s.ExpiresAt, &s.Revoked,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get admin session by hash: %w", err)
	}
	if ua != nil {
		s.UserAgent = *ua
	}
	return &s, nil
}

// ListByAdmin returns all active sessions for an admin user.
func (r *AdminSessionRepo) ListByAdmin(ctx context.Context, adminID string) ([]*model.AdminSession, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT id, admin_id, token_hash, ip, user_agent, created_at, expires_at, revoked
		FROM auth.admin_sessions
		WHERE admin_id = $1 AND revoked = FALSE AND expires_at > NOW()
		ORDER BY created_at DESC`, adminID)
	if err != nil {
		return nil, fmt.Errorf("list admin sessions: %w", err)
	}
	defer rows.Close()
	return r.scanSessions(rows)
}

// ListActive returns all active (non-revoked, non-expired) sessions.
func (r *AdminSessionRepo) ListActive(ctx context.Context) ([]*model.AdminSession, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT id, admin_id, token_hash, ip, user_agent, created_at, expires_at, revoked
		FROM auth.admin_sessions
		WHERE revoked = FALSE AND expires_at > NOW()
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list active admin sessions: %w", err)
	}
	defer rows.Close()
	return r.scanSessions(rows)
}

// Revoke marks a session as revoked.
func (r *AdminSessionRepo) Revoke(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE auth.admin_sessions SET revoked = TRUE WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("revoke admin session: %w", err)
	}
	return nil
}

// RevokeAllForAdmin revokes all sessions for an admin user.
func (r *AdminSessionRepo) RevokeAllForAdmin(ctx context.Context, adminID string) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE auth.admin_sessions SET revoked = TRUE WHERE admin_id = $1 AND revoked = FALSE`, adminID)
	if err != nil {
		return fmt.Errorf("revoke all admin sessions for admin: %w", err)
	}
	return nil
}

// RevokeAll revokes all active sessions.
func (r *AdminSessionRepo) RevokeAll(ctx context.Context) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE auth.admin_sessions SET revoked = TRUE WHERE revoked = FALSE`)
	if err != nil {
		return fmt.Errorf("revoke all admin sessions: %w", err)
	}
	return nil
}

// DeleteExpired removes expired sessions. Expiry is terminal: a row past
// expires_at is rejected by the admin middleware regardless of the revoked flag,
// so it is collected whether or not it was explicitly revoked. Gating the reap on
// revoked = TRUE left the common case (a session that simply timed out) in the
// table for good, retaining its token_hash, ip and user_agent with no purpose.
func (r *AdminSessionRepo) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := r.db.Pool.Exec(ctx,
		`DELETE FROM auth.admin_sessions WHERE expires_at < NOW()`)
	if err != nil {
		return 0, fmt.Errorf("delete expired admin sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *AdminSessionRepo) scanSessions(rows pgx.Rows) ([]*model.AdminSession, error) {
	var sessions []*model.AdminSession
	for rows.Next() {
		var s model.AdminSession
		var ua *string
		err := rows.Scan(
			&s.ID, &s.AdminID, &s.TokenHash, &s.IP, &ua,
			&s.CreatedAt, &s.ExpiresAt, &s.Revoked,
		)
		if err != nil {
			return nil, fmt.Errorf("scan admin session: %w", err)
		}
		if ua != nil {
			s.UserAgent = *ua
		}
		sessions = append(sessions, &s)
	}
	return sessions, rows.Err()
}
