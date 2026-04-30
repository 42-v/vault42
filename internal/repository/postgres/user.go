package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
)

// UserRepo implements repository.UserRepository.
type UserRepo struct {
	db *DB
}

// NewUserRepo creates a new PostgreSQL-backed user repository.
func NewUserRepo(db *DB) *UserRepo {
	return &UserRepo{db: db}
}

// Create inserts a new user into the auth.users table.
func (r *UserRepo) Create(ctx context.Context, user *model.User) error {
	roles := user.Roles
	if roles == nil {
		roles = []string{}
	}
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.users (id, email, email_verified, password_hash, display_name, avatar_url, locale, mfa_required, created_at, updated_at, roles)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		user.ID, user.Email, user.EmailVerified, nullStr(user.PasswordHash),
		nullStr(user.DisplayName), nullStr(user.AvatarURL), user.Locale,
		user.MFARequired, user.CreatedAt, user.UpdatedAt, roles,
	)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

// GetByID retrieves a user by primary key. Returns nil, nil if not found.
func (r *UserRepo) GetByID(ctx context.Context, id string) (*model.User, error) {
	return r.scanUser(r.db.Pool.QueryRow(ctx, `
		SELECT id, email, email_verified, COALESCE(password_hash, ''), display_name, avatar_url,
		       locale, mfa_required, locked_until, failed_login_count, created_at, updated_at, roles
		FROM auth.users WHERE id = $1`, id))
}

// GetByEmail retrieves a user by email address. Returns nil, nil if not found.
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	return r.scanUser(r.db.Pool.QueryRow(ctx, `
		SELECT id, email, email_verified, COALESCE(password_hash, ''), display_name, avatar_url,
		       locale, mfa_required, locked_until, failed_login_count, created_at, updated_at, roles
		FROM auth.users WHERE email = $1`, email))
}

// Update persists changes to a user's profile fields and sets updated_at to now.
func (r *UserRepo) Update(ctx context.Context, user *model.User) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE auth.users SET email=$2, display_name=$3, avatar_url=$4, locale=$5,
		       mfa_required=$6, updated_at=$7
		WHERE id = $1`,
		user.ID, user.Email, nullStr(user.DisplayName), nullStr(user.AvatarURL),
		user.Locale, user.MFARequired, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

// UpdatePassword replaces the user's password hash and updates the timestamp.
func (r *UserRepo) UpdatePassword(ctx context.Context, id, passwordHash string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.users SET password_hash=$2, updated_at=NOW() WHERE id=$1`, id, passwordHash)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return nil
}

// IncrementFailedLogin increments the failed login attempt counter by one.
func (r *UserRepo) IncrementFailedLogin(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.users SET failed_login_count = failed_login_count + 1 WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("increment failed login: %w", err)
	}
	return nil
}

// ResetFailedLogin resets the failed login counter to zero.
func (r *UserRepo) ResetFailedLogin(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.users SET failed_login_count = 0 WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("reset failed login: %w", err)
	}
	return nil
}

// LockUntil locks the user account until the specified time.
func (r *UserRepo) LockUntil(ctx context.Context, id string, until time.Time) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.users SET locked_until=$2 WHERE id=$1`, id, until)
	if err != nil {
		return fmt.Errorf("lock user: %w", err)
	}
	return nil
}

// Unlock clears the account lock and resets the failed login counter.
func (r *UserRepo) Unlock(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.users SET locked_until=NULL, failed_login_count=0 WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("unlock user: %w", err)
	}
	return nil
}

// VerifyEmail marks the user's email as verified.
func (r *UserRepo) VerifyEmail(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.users SET email_verified=TRUE, updated_at=NOW() WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("verify email: %w", err)
	}
	return nil
}

func (r *UserRepo) scanUser(row pgx.Row) (*model.User, error) {
	var u model.User
	var displayName, avatarURL *string
	err := row.Scan(
		&u.ID, &u.Email, &u.EmailVerified, &u.PasswordHash,
		&displayName, &avatarURL, &u.Locale, &u.MFARequired,
		&u.LockedUntil, &u.FailedLoginCount, &u.CreatedAt, &u.UpdatedAt,
		&u.Roles,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	if displayName != nil {
		u.DisplayName = *displayName
	}
	if avatarURL != nil {
		u.AvatarURL = *avatarURL
	}
	return &u, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
