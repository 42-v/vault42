package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
)

// AdminUserRepo implements repository.AdminUserRepository.
type AdminUserRepo struct {
	db *DB
}

// NewAdminUserRepo creates a new PostgreSQL-backed admin user repository.
func NewAdminUserRepo(db *DB) *AdminUserRepo {
	return &AdminUserRepo{db: db}
}

// Create inserts a new admin user.
func (r *AdminUserRepo) Create(ctx context.Context, user *model.AdminUser) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.admin_users (id, username, password_hash, role, totp_secret_enc, totp_verified,
		    failed_login_count, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		user.ID, user.Username, user.PasswordHash, user.Role,
		nullStr(user.TOTPSecretEnc), user.TOTPVerified,
		user.FailedLoginCount, user.CreatedAt, user.UpdatedAt,
		nullStr(user.CreatedBy),
	)
	if err != nil {
		return fmt.Errorf("insert admin user: %w", err)
	}
	return nil
}

// GetByID retrieves an admin user by ID with role populated from admin_roles.
func (r *AdminUserRepo) GetByID(ctx context.Context, id string) (*model.AdminUser, error) {
	return r.scanAdminUser(r.db.Pool.QueryRow(ctx, `
		SELECT u.id, u.username, u.password_hash, u.role,
		       COALESCE(u.totp_secret_enc, ''), u.totp_verified,
		       u.locked_until, u.failed_login_count, u.last_totp_counter,
		       u.last_login_at, u.created_at, u.updated_at, COALESCE(u.created_by::text, '')
		FROM auth.admin_users u
		JOIN auth.admin_roles r ON r.role = u.role
		WHERE u.id = $1`, id))
}

// GetByUsername retrieves an admin user by username.
func (r *AdminUserRepo) GetByUsername(ctx context.Context, username string) (*model.AdminUser, error) {
	return r.scanAdminUser(r.db.Pool.QueryRow(ctx, `
		SELECT u.id, u.username, u.password_hash, u.role,
		       COALESCE(u.totp_secret_enc, ''), u.totp_verified,
		       u.locked_until, u.failed_login_count, u.last_totp_counter,
		       u.last_login_at, u.created_at, u.updated_at, COALESCE(u.created_by::text, '')
		FROM auth.admin_users u
		JOIN auth.admin_roles r ON r.role = u.role
		WHERE u.username = $1`, username))
}

// List returns all admin users.
func (r *AdminUserRepo) List(ctx context.Context) ([]*model.AdminUser, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT u.id, u.username, u.password_hash, u.role,
		       COALESCE(u.totp_secret_enc, ''), u.totp_verified,
		       u.locked_until, u.failed_login_count, u.last_totp_counter,
		       u.last_login_at, u.created_at, u.updated_at, COALESCE(u.created_by::text, '')
		FROM auth.admin_users u
		JOIN auth.admin_roles r ON r.role = u.role
		ORDER BY r.rank DESC, u.username`)
	if err != nil {
		return nil, fmt.Errorf("list admin users: %w", err)
	}
	defer rows.Close()

	var users []*model.AdminUser
	for rows.Next() {
		u, err := r.scanAdminUserRow(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// Count returns the total number of admin users.
func (r *AdminUserRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.admin_users`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count admin users: %w", err)
	}
	return count, nil
}

// Update persists changes to an admin user's fields.
func (r *AdminUserRepo) Update(ctx context.Context, user *model.AdminUser) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE auth.admin_users
		SET username=$2, role=$3, totp_secret_enc=$4, totp_verified=$5, updated_at=$6
		WHERE id=$1`,
		user.ID, user.Username, user.Role,
		nullStr(user.TOTPSecretEnc), user.TOTPVerified, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("update admin user: %w", err)
	}
	return nil
}

// IncrementFailedLogin atomically increments the failed login counter and returns the new count.
func (r *AdminUserRepo) IncrementFailedLogin(ctx context.Context, id string) (int, error) {
	var newCount int
	err := r.db.Pool.QueryRow(ctx,
		`UPDATE auth.admin_users SET failed_login_count = failed_login_count + 1 WHERE id=$1 RETURNING failed_login_count`, id).Scan(&newCount)
	if err != nil {
		return 0, fmt.Errorf("increment admin failed login: %w", err)
	}
	return newCount, nil
}

// ResetFailedLogin resets the failed login counter to zero.
func (r *AdminUserRepo) ResetFailedLogin(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE auth.admin_users SET failed_login_count = 0 WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("reset admin failed login: %w", err)
	}
	return nil
}

// LockUntil locks the admin account until the specified time.
func (r *AdminUserRepo) LockUntil(ctx context.Context, id string, until time.Time) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE auth.admin_users SET locked_until=$2 WHERE id=$1`, id, until)
	if err != nil {
		return fmt.Errorf("lock admin user: %w", err)
	}
	return nil
}

// UpdateLastTOTPCounter records the accepted TOTP time-step for replay prevention.
func (r *AdminUserRepo) UpdateLastTOTPCounter(ctx context.Context, id string, counter int64) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE auth.admin_users SET last_totp_counter = $2 WHERE id = $1`, id, counter)
	if err != nil {
		return fmt.Errorf("update admin last totp counter: %w", err)
	}
	return nil
}

// UpdateLastLogin sets the last login timestamp.
func (r *AdminUserRepo) UpdateLastLogin(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE auth.admin_users SET last_login_at=NOW(), failed_login_count=0, locked_until=NULL WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("update admin last login: %w", err)
	}
	return nil
}

// Revoke deletes an admin user and their sessions (cascaded by FK).
func (r *AdminUserRepo) Revoke(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.admin_users WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("revoke admin user: %w", err)
	}
	return nil
}

func (r *AdminUserRepo) scanAdminUser(row pgx.Row) (*model.AdminUser, error) {
	var u model.AdminUser
	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role,
		&u.TOTPSecretEnc, &u.TOTPVerified,
		&u.LockedUntil, &u.FailedLoginCount, &u.LastTOTPCounter,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt, &u.CreatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan admin user: %w", err)
	}
	return &u, nil
}

func (r *AdminUserRepo) scanAdminUserRow(rows pgx.Rows) (*model.AdminUser, error) {
	var u model.AdminUser
	err := rows.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role,
		&u.TOTPSecretEnc, &u.TOTPVerified,
		&u.LockedUntil, &u.FailedLoginCount, &u.LastTOTPCounter,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt, &u.CreatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("scan admin user row: %w", err)
	}
	return &u, nil
}
