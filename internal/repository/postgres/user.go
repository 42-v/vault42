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

// CreateImported inserts an imported user with no password (import_pending=TRUE)
// and the source tag + legacy id. Email is pre-verified (the source verified it).
// Idempotent: ON CONFLICT (email) DO NOTHING.
func (r *UserRepo) CreateImported(ctx context.Context, user *model.User) error {
	roles := user.Roles
	if roles == nil {
		roles = []string{}
	}
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.users
			(id, email, email_verified, password_hash, display_name, avatar_url, locale,
			 mfa_required, created_at, updated_at, roles,
			 disabled, banned, ban_reason,
			 import_pending, imported_from, legacy_id, must_reset_password)
		VALUES ($1, $2, TRUE, NULL, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, TRUE, $13, $14, $15)
		ON CONFLICT (email) DO NOTHING`,
		user.ID, user.Email, nullStr(user.DisplayName), nullStr(user.AvatarURL), user.Locale,
		user.MFARequired, user.CreatedAt, user.UpdatedAt, roles,
		user.Disabled, user.Banned, nullStr(user.BanReason),
		nullStr(user.ImportedFrom), nullStr(user.LegacyID), user.MustResetPassword,
	)
	if err != nil {
		return fmt.Errorf("create imported user: %w", err)
	}
	return nil
}

// ClearImportPending marks an imported account as claimed (called after the user
// sets a password via the magic reset link).
func (r *UserRepo) ClearImportPending(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.users SET import_pending=FALSE, updated_at=NOW() WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("clear import_pending: %w", err)
	}
	return nil
}

// ClearMustResetPassword lifts a forced password reset (called once the user has
// set a new password through the reset link).
//
// It is the only direction vault_app may move the column: migration 039 grants
// the privilege for this statement and refuses the reverse from this role, so a
// forced reset can be completed by the web server and imposed only by the admin
// plane.
func (r *UserRepo) ClearMustResetPassword(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.users SET must_reset_password=FALSE, updated_at=NOW() WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("clear must_reset_password: %w", err)
	}
	return nil
}

// GetByID retrieves a user by primary key. Returns nil, nil if not found.
func (r *UserRepo) GetByID(ctx context.Context, id string) (*model.User, error) {
	return r.scanUser(r.db.Pool.QueryRow(ctx, `
		SELECT id, email, email_verified, COALESCE(password_hash, ''), display_name, avatar_url,
		       locale, mfa_required, locked_until, failed_login_count, created_at, updated_at, roles,
		       disabled, banned, COALESCE(ban_reason, ''), last_login_at, deleted, deleted_at,
		       import_pending, COALESCE(imported_from, ''), COALESCE(legacy_id::text, ''),
		       must_reset_password
		FROM auth.users WHERE id = $1`, id))
}

// GetByEmail retrieves a user by email address. Returns nil, nil if not found.
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	return r.scanUser(r.db.Pool.QueryRow(ctx, `
		SELECT id, email, email_verified, COALESCE(password_hash, ''), display_name, avatar_url,
		       locale, mfa_required, locked_until, failed_login_count, created_at, updated_at, roles,
		       disabled, banned, COALESCE(ban_reason, ''), last_login_at, deleted, deleted_at,
		       import_pending, COALESCE(imported_from, ''), COALESCE(legacy_id::text, ''),
		       must_reset_password
		FROM auth.users WHERE email = $1`, email))
}

// Update persists changes to a user's profile fields and sets updated_at to now.
//
// email is deliberately absent from the SET clause. It never carried a change:
// PUT /user/profile merges display_name, avatar_url and locale and writes back
// the address it just read. But PostgreSQL checks the column privilege on every
// target of an UPDATE whether or not the value differs, so naming it here forced
// a standing UPDATE(email) grant on vault_app, and with it the ability to point
// any account at any address. The address is immutable to this role by design;
// migration 015 is what makes the database agree.
func (r *UserRepo) Update(ctx context.Context, user *model.User) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE auth.users SET display_name=$2, avatar_url=$3, locale=$4,
		       mfa_required=$5, updated_at=$6
		WHERE id = $1`,
		user.ID, nullStr(user.DisplayName), nullStr(user.AvatarURL),
		user.Locale, user.MFARequired, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

// SoftDeleteScrub erases a user's PII in place: it overwrites the email with a
// tombstone, clears every other personal column on the row — display_name,
// avatar_url, password_hash, roles, ban_reason, last_login_at, imported_from,
// legacy_id — and marks the row deleted. The real email survives only in the
// encrypted account-recovery log. The row is kept (not removed) so foreign keys
// stay valid; the account-state gate rejects deleted=true users at login and
// refresh.
//
// The column list is migration 031's, not 015's. 015 scrubbed the six columns
// that were the whole of the personal data on auth.users when it was written;
// migrations 003, 004 and 006 had already added six more, and the password hash
// among them outlived every erasure until 031 widened the function.
//
// The write goes through auth.erase_user_identity() rather than an UPDATE of its
// own. Running it inline needed column-level UPDATE on email, display_name and
// avatar_url, and a column grant is standing: it also authorizes
// `UPDATE auth.users SET email=... WHERE id=<anyone>`, which is an account
// takeover because password reset follows the address. The function is SECURITY
// DEFINER, owned by the migration role, and writes nothing but a tombstone, so
// the roles keep erasure and lose arbitrary identity writes (migration 015).
// tombstoneEmail must be deleted-<id>@<domain>.invalid; the function refuses
// anything else.
func (r *UserRepo) SoftDeleteScrub(ctx context.Context, id, tombstoneEmail string) error {
	_, err := r.db.Pool.Exec(ctx, `SELECT auth.erase_user_identity($1, $2)`, id, tombstoneEmail)
	if err != nil {
		return fmt.Errorf("soft-delete scrub user: %w", err)
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

// SetLastLogin stamps the user's last successful login time to now.
func (r *UserRepo) SetLastLogin(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.users SET last_login_at=NOW() WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("set last login: %w", err)
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
		&u.Disabled, &u.Banned, &u.BanReason, &u.LastLoginAt, &u.Deleted, &u.DeletedAt,
		&u.ImportPending, &u.ImportedFrom, &u.LegacyID,
		&u.MustResetPassword,
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
