package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// WebAuthnRepo implements repository.WebAuthnRepository.
type WebAuthnRepo struct{ db *DB }

// NewWebAuthnRepo creates a new PostgreSQL-backed WebAuthn credential repository.
func NewWebAuthnRepo(db *DB) repository.WebAuthnRepository { return &WebAuthnRepo{db: db} }

// Create inserts a new WebAuthn credential into the auth.webauthn_credentials table.
func (r *WebAuthnRepo) Create(ctx context.Context, c *model.WebAuthnCredential) error {
	_, err := r.db.Pool.Exec(ctx,
		`INSERT INTO auth.webauthn_credentials (id, user_id, credential_id, public_key, sign_count, friendly_name, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		c.ID, c.UserID, c.CredentialID, c.PublicKey, c.SignCount, c.FriendlyName, c.CreatedAt)
	if err != nil {
		return fmt.Errorf("create webauthn credential: %w", err)
	}
	return nil
}

// GetByCredentialID retrieves a credential by its raw credential ID bytes.
func (r *WebAuthnRepo) GetByCredentialID(ctx context.Context, credID []byte) (*model.WebAuthnCredential, error) {
	row := r.db.Pool.QueryRow(ctx,
		`SELECT id, user_id, credential_id, public_key, sign_count, friendly_name, created_at
		 FROM auth.webauthn_credentials WHERE credential_id=$1`, credID)
	c := &model.WebAuthnCredential{}
	err := row.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.FriendlyName, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get webauthn credential: %w", err)
	}
	return c, nil
}

// ListByUser returns all WebAuthn credentials for a user, ordered by creation time.
func (r *WebAuthnRepo) ListByUser(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT id, user_id, credential_id, public_key, sign_count, friendly_name, created_at
		 FROM auth.webauthn_credentials WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("list webauthn credentials: %w", err)
	}
	defer rows.Close()
	var creds []*model.WebAuthnCredential
	for rows.Next() {
		c := &model.WebAuthnCredential{}
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.FriendlyName, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan webauthn credential: %w", err)
		}
		creds = append(creds, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan webauthn credentials: %w", err)
	}
	return creds, nil
}

// UpdateSignCount updates the signature counter for authenticator clone detection.
func (r *WebAuthnRepo) UpdateSignCount(ctx context.Context, id string, count int) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.webauthn_credentials SET sign_count=$1 WHERE id=$2`, count, id)
	if err != nil {
		return fmt.Errorf("update sign count: %w", err)
	}
	return nil
}

// Delete removes a single WebAuthn credential by ID with ownership verification.
func (r *WebAuthnRepo) Delete(ctx context.Context, id, userID string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.webauthn_credentials WHERE id=$1 AND user_id=$2`, id, userID)
	if err != nil {
		return fmt.Errorf("delete webauthn credential: %w", err)
	}
	return nil
}
