package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
)

// ClientRepo implements repository.ClientRepository using PostgreSQL.
type ClientRepo struct {
	db *DB
}

// NewClientRepo creates a new PostgreSQL-backed client repository.
func NewClientRepo(db *DB) *ClientRepo {
	return &ClientRepo{db: db}
}

// Create inserts a new service client into the auth.clients table.
func (r *ClientRepo) Create(ctx context.Context, client *model.Client) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.clients (id, name, secret_hash, role, scopes, redirect_uris, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		client.ID, client.Name, client.SecretHash, client.Role,
		client.Scopes, client.RedirectURIs, client.Active,
		client.CreatedAt, client.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	return nil
}

// GetByID retrieves a client by primary key. Returns nil, nil if not found.
func (r *ClientRepo) GetByID(ctx context.Context, id string) (*model.Client, error) {
	var c model.Client
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, name, secret_hash, role, scopes, redirect_uris, active, created_at, updated_at
		FROM auth.clients WHERE id = $1`, id).Scan(
		&c.ID, &c.Name, &c.SecretHash, &c.Role, &c.Scopes, &c.RedirectURIs,
		&c.Active, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}
	return &c, nil
}

// GetByName retrieves a client by its unique name. Returns nil, nil if not found.
func (r *ClientRepo) GetByName(ctx context.Context, name string) (*model.Client, error) {
	var c model.Client
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, name, secret_hash, role, scopes, redirect_uris, active, created_at, updated_at
		FROM auth.clients WHERE name = $1`, name).Scan(
		&c.ID, &c.Name, &c.SecretHash, &c.Role, &c.Scopes, &c.RedirectURIs,
		&c.Active, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get client by name: %w", err)
	}
	return &c, nil
}

// List returns all registered service clients, ordered by name.
func (r *ClientRepo) List(ctx context.Context) ([]*model.Client, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT id, name, secret_hash, role, scopes, redirect_uris, active, created_at, updated_at
		FROM auth.clients ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	defer rows.Close()

	var clients []*model.Client
	for rows.Next() {
		var c model.Client
		if err := rows.Scan(&c.ID, &c.Name, &c.SecretHash, &c.Role, &c.Scopes, &c.RedirectURIs,
			&c.Active, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan client: %w", err)
		}
		clients = append(clients, &c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan clients: %w", err)
	}
	return clients, nil
}

// Update persists changes to a client's fields and sets updated_at to now.
func (r *ClientRepo) Update(ctx context.Context, client *model.Client) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE auth.clients SET name=$2, secret_hash=$3, role=$4, scopes=$5, redirect_uris=$6, active=$7, updated_at=NOW()
		WHERE id = $1`,
		client.ID, client.Name, client.SecretHash, client.Role,
		client.Scopes, client.RedirectURIs, client.Active,
	)
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}
	return nil
}

// Deactivate marks a client as inactive, preventing further authentication.
func (r *ClientRepo) Deactivate(ctx context.Context, id string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.clients SET active = FALSE, updated_at = NOW() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deactivate client: %w", err)
	}
	return nil
}
