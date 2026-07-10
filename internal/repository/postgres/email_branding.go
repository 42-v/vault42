package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// EmailBrandingRepo implements repository.EmailBrandingRepository against
// auth.email_branding. The auth send path reads (vault_app holds SELECT); writes
// run as the admin gateway role, which owns the table.
type EmailBrandingRepo struct {
	db *DB
}

// NewEmailBrandingRepo creates a new PostgreSQL-backed email-branding repository.
func NewEmailBrandingRepo(db *DB) *EmailBrandingRepo {
	return &EmailBrandingRepo{db: db}
}

const emailBrandingCols = `app, app_name, logo_url, primary_color, from_name, from_address, created_at, updated_at, updated_by`

func scanEmailBranding(row pgx.Row) (*model.EmailBranding, error) {
	var b model.EmailBranding
	var appName, logoURL, primaryColor, fromName, fromAddress, updatedBy *string
	if err := row.Scan(&b.App, &appName, &logoURL, &primaryColor, &fromName, &fromAddress,
		&b.CreatedAt, &b.UpdatedAt, &updatedBy); err != nil {
		return nil, err
	}
	b.AppName = deref(appName)
	b.LogoURL = deref(logoURL)
	b.PrimaryColor = deref(primaryColor)
	b.FromName = deref(fromName)
	b.FromAddress = deref(fromAddress)
	b.UpdatedBy = deref(updatedBy)
	return &b, nil
}

// Get returns the branding for an app, or nil, nil if absent.
func (r *EmailBrandingRepo) Get(ctx context.Context, app string) (*model.EmailBranding, error) {
	b, err := scanEmailBranding(r.db.Pool.QueryRow(ctx,
		`SELECT `+emailBrandingCols+` FROM auth.email_branding WHERE app = $1`, app))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get email_branding: %w", err)
	}
	return b, nil
}

// List returns all per-app branding rows ordered by app.
func (r *EmailBrandingRepo) List(ctx context.Context) ([]*model.EmailBranding, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT `+emailBrandingCols+` FROM auth.email_branding ORDER BY app`)
	if err != nil {
		return nil, fmt.Errorf("list email_branding: %w", err)
	}
	defer rows.Close()
	var out []*model.EmailBranding
	for rows.Next() {
		b, err := scanEmailBranding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan email_branding: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// Upsert creates or replaces the branding for an app.
func (r *EmailBrandingRepo) Upsert(ctx context.Context, b *model.EmailBranding) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.email_branding
			(app, app_name, logo_url, primary_color, from_name, from_address, updated_at, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
		ON CONFLICT (app) DO UPDATE SET
			app_name      = EXCLUDED.app_name,
			logo_url      = EXCLUDED.logo_url,
			primary_color = EXCLUDED.primary_color,
			from_name     = EXCLUDED.from_name,
			from_address  = EXCLUDED.from_address,
			updated_at    = NOW(),
			updated_by    = EXCLUDED.updated_by`,
		b.App, nullStr(b.AppName), nullStr(b.LogoURL), nullStr(b.PrimaryColor),
		nullStr(b.FromName), nullStr(b.FromAddress), nullStr(b.UpdatedBy))
	if err != nil {
		return fmt.Errorf("upsert email_branding: %w", err)
	}
	return nil
}

// Delete removes the branding for an app (idempotent).
func (r *EmailBrandingRepo) Delete(ctx context.Context, app string) error {
	if _, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.email_branding WHERE app = $1`, app); err != nil {
		return fmt.Errorf("delete email_branding: %w", err)
	}
	return nil
}

var _ repository.EmailBrandingRepository = (*EmailBrandingRepo)(nil)
