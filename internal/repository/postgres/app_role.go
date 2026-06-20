package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// AppRoleRepo implements repository.AppRoleRepository using PostgreSQL.
type AppRoleRepo struct {
	db *DB
}

// NewAppRoleRepo creates a new PostgreSQL-backed app-role repository.
func NewAppRoleRepo(db *DB) *AppRoleRepo {
	return &AppRoleRepo{db: db}
}

// List returns all catalog roles ordered by name.
func (r *AppRoleRepo) List(ctx context.Context) ([]*model.AppRole, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT name, namespace, description, reserved, created_at
		FROM auth.app_roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list app_roles: %w", err)
	}
	defer rows.Close()
	var out []*model.AppRole
	for rows.Next() {
		var a model.AppRole
		if err := rows.Scan(&a.Name, &a.Namespace, &a.Description, &a.Reserved, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan app_role: %w", err)
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// ListNames returns just the role names.
func (r *AppRoleRepo) ListNames(ctx context.Context) ([]string, error) {
	rows, err := r.db.Pool.Query(ctx, `SELECT name FROM auth.app_roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list app_role names: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("scan app_role name: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Get returns one role by name, or nil, nil if absent.
func (r *AppRoleRepo) Get(ctx context.Context, name string) (*model.AppRole, error) {
	var a model.AppRole
	err := r.db.Pool.QueryRow(ctx, `
		SELECT name, namespace, description, reserved, created_at
		FROM auth.app_roles WHERE name = $1`, name).
		Scan(&a.Name, &a.Namespace, &a.Description, &a.Reserved, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get app_role: %w", err)
	}
	return &a, nil
}

// Create inserts a new catalog role.
func (r *AppRoleRepo) Create(ctx context.Context, role *model.AppRole) error {
	ns := role.Namespace
	if ns == "" {
		ns = "app"
	}
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.app_roles (name, namespace, description, reserved)
		VALUES ($1, $2, $3, $4)`,
		role.Name, ns, role.Description, role.Reserved)
	if err != nil {
		return fmt.Errorf("create app_role: %w", err)
	}
	return nil
}

// Delete removes a non-reserved role. Reserved roles return ErrRoleReserved;
// a missing role is a no-op (idempotent).
func (r *AppRoleRepo) Delete(ctx context.Context, name string) error {
	existing, err := r.Get(ctx, name)
	if err != nil {
		return err
	}
	if existing == nil {
		return nil
	}
	if existing.Reserved {
		return repository.ErrRoleReserved
	}
	if _, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.app_roles WHERE name = $1 AND reserved = FALSE`, name); err != nil {
		return fmt.Errorf("delete app_role: %w", err)
	}
	return nil
}
